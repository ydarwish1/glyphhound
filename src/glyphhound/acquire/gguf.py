"""Stage 1 (Acquirer) — extract the chat template from a GGUF file without weights.

A GGUF file begins with a metadata key-value block (the header), followed by the
tensor information and finally the tensor data — the multi-gigabyte weights. The
``tokenizer.chat_template`` we care about lives in that header. We read the file
*sequentially from offset 0* and stop the instant we have the template, so for a
remote file we issue HTTP range requests and only ever download the small prefix
that holds the metadata, never the weights (the project conventions).

Format reference: https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
"""

from __future__ import annotations

import os
import struct
import urllib.error
import urllib.request

from .models import (
    AcquireError,
    ChatTemplate,
    RangeUnsupportedError,
    RawTemplate,
    TemplateNotFoundError,
    decode_utf8_or_raise,
)

GGUF_MAGIC = b"GGUF"
CHAT_TEMPLATE_KEY = "tokenizer.chat_template"
_NAMED_PREFIX = "tokenizer.chat_template."  # multi-template models: ...chat_template.<name>

# GGUF metadata value types (gguf.md, "metadata value type" enum).
(_U8, _I8, _U16, _I16, _U32, _I32, _F32, _BOOL,
 _STRING, _ARRAY, _U64, _I64, _F64) = range(13)
_FIXED_WIDTH = {
    _U8: 1, _I8: 1, _BOOL: 1,
    _U16: 2, _I16: 2,
    _U32: 4, _I32: 4, _F32: 4,
    _U64: 8, _I64: 8, _F64: 8,
}

# Safety backstop: the metadata block of even a huge model is a few MB. If we have
# not found the template within this many bytes we refuse rather than read on into
# the weights. 64 MiB is comfortably larger than any real header and far smaller
# than any real weight file.
_MAX_METADATA_BYTES = 64 * 1024 * 1024
_CHUNK = 1024 * 1024  # 1 MiB HTTP range granularity
_TIMEOUT = 30
_USER_AGENT = "glyphhound/0.0 (+template-extraction; no-weights)"


def _read_capped(resp, limit: int) -> bytes:
    """Read at most ``limit`` bytes from a response.

    A server cannot be trusted to honor our Range request: a malicious 206 could
    stream the entire weights file. Capping the read at the number of bytes we
    asked for keeps the no-weights guarantee even against a hostile host (Rule 6).
    Handles partial reads (HTTP may return fewer bytes per ``read`` call).
    """
    buf = bytearray()
    while len(buf) < limit:
        chunk = resp.read(limit - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


class _ByteWindow:
    """Growable, read-from-zero view over a byte source, tracking bytes fetched.

    Subclasses fill ``self._buf`` (a bytearray) in ``_fill(upto)``.
    """

    total_size: int | None = None
    bytes_fetched: int = 0
    _buf: bytearray

    def _fill(self, upto: int) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def read(self, offset: int, length: int) -> bytes:
        end = offset + length
        if end > _MAX_METADATA_BYTES:
            raise AcquireError(
                f"metadata read at byte {end} exceeds the {_MAX_METADATA_BYTES}-byte safety cap; "
                "refusing to read further into the file (possible weights)"
            )
        self._fill(end)
        if end > len(self._buf):
            raise AcquireError("unexpected end of data while reading GGUF metadata")
        return bytes(self._buf[offset:end])


class _HttpRangeWindow(_ByteWindow):
    """Reads a remote GGUF prefix via HTTP range requests."""

    def __init__(self, url: str, chunk: int = _CHUNK):
        self.url = url
        self.chunk = chunk
        self._buf = bytearray()
        self.bytes_fetched = 0
        self.total_size = None
        self._fill(1)  # prime: discovers total_size from the first Content-Range

    def _range_get(self, start: int, length: int) -> bytes:
        end = start + length - 1
        headers = {"Range": f"bytes={start}-{end}", "User-Agent": _USER_AGENT}
        token = os.environ.get("HF_TOKEN")  # Phase 20: gated/private-repo access (sent only if set)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.url, headers=headers)
        try:
            resp = urllib.request.urlopen(req, timeout=_TIMEOUT)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AcquireError(
                    f"{self.url}: HTTP {exc.code} — gated or private repo; set HF_TOKEN to a "
                    "token with access"
                ) from exc
            raise AcquireError(f"{self.url}: HTTP {exc.code}") from exc
        with resp:
            if resp.status != 206:
                # HTTP 200 means the server ignored Range and is about to stream the
                # entire file. Refuse before reading the body so we never download the
                # weights (the project conventions).
                raise RangeUnsupportedError(
                    f"server returned HTTP {resp.status} (not 206 Partial Content) for a range "
                    f"request to {self.url}; refusing to download the full file"
                )
            if self.total_size is None:
                content_range = resp.headers.get("Content-Range", "")
                total = content_range.rsplit("/", 1)[-1] if "/" in content_range else ""
                if not total.isdigit():
                    raise AcquireError(
                        f"could not parse total size from Content-Range header: {content_range!r}"
                    )
                self.total_size = int(total)
            return _read_capped(resp, length)

    def _fill(self, upto: int) -> None:
        while len(self._buf) < upto:
            if self.total_size is not None and len(self._buf) >= self.total_size:
                break
            start = len(self._buf)
            length = self.chunk
            if self.total_size is not None:
                length = min(length, self.total_size - start)
            if length <= 0:
                break
            data = self._range_get(start, length)
            if not data:
                break
            self._buf += data
            self.bytes_fetched += len(data)


class _FileWindow(_ByteWindow):
    """Reads a local GGUF file prefix from disk."""

    def __init__(self, path: str):
        self.total_size = os.path.getsize(path)
        self._buf = bytearray()
        self.bytes_fetched = 0
        self._fh = open(path, "rb")

    def _fill(self, upto: int) -> None:
        target = min(upto, self.total_size)
        want = target - len(self._buf)
        if want <= 0:
            return
        self._fh.seek(len(self._buf))
        data = self._fh.read(want)
        self._buf += data
        self.bytes_fetched += len(data)

    def close(self) -> None:
        self._fh.close()


class _Cursor:
    """Sequential little-endian reader over a :class:`_ByteWindow`."""

    def __init__(self, window: _ByteWindow):
        self._w = window
        self.pos = 0

    def take(self, n: int) -> bytes:
        data = self._w.read(self.pos, n)
        self.pos += n
        return data

    def skip(self, n: int) -> None:
        # Advances past data we do not need. The next ``take`` pulls bytes at the new
        # position; for a contiguous window the skipped span is fetched as part of
        # reaching it, which still bounds total reads to the metadata prefix.
        self.pos += n

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def gguf_string(self) -> bytes:
        return self.take(self.u64())


def _consume_value(cur: _Cursor, vtype: int) -> None:
    """Advance the cursor past a metadata value we do not need to keep."""
    width = _FIXED_WIDTH.get(vtype)
    if width is not None:
        cur.skip(width)
        return
    if vtype == _STRING:
        cur.skip(cur.u64())
        return
    if vtype == _ARRAY:
        elem_type = cur.u32()
        count = cur.u64()
        elem_width = _FIXED_WIDTH.get(elem_type)
        if elem_width is not None:
            cur.skip(elem_width * count)
        elif elem_type == _STRING:
            for _ in range(count):
                cur.skip(cur.u64())
        elif elem_type == _ARRAY:
            for _ in range(count):
                _consume_value(cur, _ARRAY)
        else:
            raise AcquireError(f"unknown GGUF array element type {elem_type}")
        return
    raise AcquireError(f"unknown GGUF value type {vtype}")


def _extract_from_window(window: _ByteWindow, source_ref: str) -> RawTemplate:
    cur = _Cursor(window)
    if cur.take(4) != GGUF_MAGIC:
        raise AcquireError(f"{source_ref}: not a GGUF file (bad magic)")
    version = cur.u32()
    if version not in (2, 3):
        raise AcquireError(
            f"{source_ref}: unsupported GGUF version {version} (this reader supports 2 and 3)"
        )
    cur.u64()  # tensor_count — unused; we never read tensor info or data
    kv_count = cur.u64()

    default_text: str | None = None
    named: dict[str, str] = {}  # <name> -> template text
    # Scan the WHOLE metadata KV block (no early exit): a named template may appear
    # anywhere, including after the default, and a malicious named template must not
    # be skipped. This reads more of the header than the old early-break path, but
    # still only the metadata prefix (bounded by _MAX_METADATA_BYTES), never the
    # tensor data / weights (Rule 6) — the loop stops at the end of the KV block.
    for _ in range(kv_count):
        key = cur.gguf_string().decode("utf-8", "replace")
        vtype = cur.u32()
        if key == CHAT_TEMPLATE_KEY:
            if vtype != _STRING:
                raise AcquireError(f"{source_ref}: {key} is not a string (type {vtype})")
            default_text = decode_utf8_or_raise(cur.gguf_string(), source_ref, key)
            continue
        if key.startswith(_NAMED_PREFIX) and vtype == _STRING:
            name = key[len(_NAMED_PREFIX):]
            named[name] = decode_utf8_or_raise(cur.gguf_string(), source_ref, key)
            continue
        _consume_value(cur, vtype)

    templates: list[ChatTemplate] = []
    if default_text is not None:
        templates.append(ChatTemplate(None, default_text))
    for name in sorted(named):  # deterministic order for named variants
        templates.append(ChatTemplate(name, named[name]))
    if not templates:
        raise TemplateNotFoundError(
            f"{source_ref}: no '{CHAT_TEMPLATE_KEY}' found in GGUF metadata"
        )
    if window.total_size is None:
        raise AcquireError(f"{source_ref}: could not determine total file size")

    return RawTemplate(
        source_ref=source_ref,
        templates=tuple(templates),
        bytes_fetched=window.bytes_fetched,
        total_size=window.total_size,
    )


def read_gguf_template(ref: str, *, filename: str | None = None, revision: str = "main") -> RawTemplate:
    """Extract the chat template from a GGUF model, never reading the weights.

    ``ref`` may be:
      * a local path to a ``.gguf`` file,
      * a direct ``http(s)`` URL to a ``.gguf`` file, or
      * a Hugging Face repo id (e.g. ``"Qwen/Qwen2.5-0.5B-Instruct-GGUF"``), in
        which case ``filename`` is required and ``revision`` should be pinned to a
        commit SHA for determinism (the project conventions).
    """
    if ref.startswith(("http://", "https://")):
        return _extract_from_window(_HttpRangeWindow(ref), ref)

    if os.path.exists(ref):
        window = _FileWindow(ref)
        try:
            return _extract_from_window(window, ref)
        finally:
            window.close()

    if filename is None:
        raise AcquireError(
            f"{ref}: not a local file or URL; if this is a Hugging Face repo id, "
            "pass filename=... to locate the .gguf"
        )
    url = f"https://huggingface.co/{ref}/resolve/{revision}/{filename}"
    return _extract_from_window(_HttpRangeWindow(url), url)
