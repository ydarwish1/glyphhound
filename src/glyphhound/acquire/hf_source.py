"""Stage 1 (Acquirer) — read the CANONICAL chat template from a Hugging Face transformers
repo, without downloading weights.

The template the ``transformers`` library actually renders lives in the repo's metadata,
not in a GGUF quant — so to cover *every* transformers model (not just the GGUF re-uploads
the Phase-9 acquirer reads) we read it straight from the repo. Three sources, in order:

1. ``tokenizer_config.json`` -> the ``chat_template`` key. It is either a **string** (one
   default template) or a **list** of ``{"name": ..., "template": ...}`` dicts (a
   multi-template model — each is surfaced so a malicious named variant cannot hide).
2. ``chat_template.jinja`` — the standalone file newer repos ship instead.
3. The ``model.safetensors`` header's ``__metadata__.chat_template`` (read via a range
   request over the tiny JSON header — never the tensors).

Every read is a small metadata fetch capped at :data:`_HF_SOURCE_MAX_BYTES`; we never
request, and never stream, the multi-GB weights. Pin ``revision`` to a commit SHA for
determinism.
"""

from __future__ import annotations

import json
import os
import struct
import time
import urllib.error
import urllib.request

from .models import (
    AcquireError,
    ChatTemplate,
    RawTemplate,
    TemplateNotFoundError,
    WeightsLoadedError,
    decode_utf8_or_raise,
)

# A metadata file (tokenizer_config.json / chat_template.jinja / a safetensors header) is at
# most a few MB. Capping every read here means a misconfigured or hostile host can never
# stream the weights through this path; a real config never approaches this.
_HF_SOURCE_MAX_BYTES = 32 * 1024 * 1024
_TIMEOUT = 30
_USER_AGENT = "glyphhound/0.0 (+template-extraction; no-weights)"

# The transformers convention: in the list form of `chat_template`, the entry named
# "default" is the unnamed default template.
_DEFAULT_TEMPLATE_NAME = "default"

# --- HTTP auth + rate-limit backoff (Phase 17) ----------------------------------
# Anonymous by default; if HF_TOKEN is set we send it as a bearer token (higher rate limits
# and gated-repo access), per the owner's "env-if-set-else-anonymous" decision. Requests are
# retried on HTTP 429 (rate limit) and 503 (transient overload) with a FIXED exponential
# backoff (no random jitter) so a scan reproduces; a numeric Retry-After header is
# honored when present. This governs only WHETHER a metadata request is retried — never how
# much is read, so the no-weights guarantee is unchanged.
_MAX_RETRIES = 5
_BACKOFF_BASE = 1.0
_MAX_BACKOFF = 30.0
_RETRY_STATUSES = frozenset({429, 503})

# Indirection so the backoff path is unit-testable offline without real waiting / requests.
_sleep = time.sleep


def _auth_headers() -> dict:
    """An ``Authorization: Bearer`` header from ``HF_TOKEN`` if set, else ``{}`` (anonymous).

    Read at call time (not import time) so a token exported per-run/CI is picked up.
    """
    token = os.environ.get("HF_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _build_request(url: str, *, extra_headers: dict | None = None) -> urllib.request.Request:
    """A GET ``Request`` for ``url`` carrying the User-Agent + (if set) the HF auth header."""
    headers = {"User-Agent": _USER_AGENT, **_auth_headers()}
    if extra_headers:
        headers.update(extra_headers)
    return urllib.request.Request(url, headers=headers)


def _urlopen(req: urllib.request.Request):
    """Indirection over ``urllib.request.urlopen`` (timeout-bound) so the retry/backoff path
    is unit-testable offline."""
    return urllib.request.urlopen(req, timeout=_TIMEOUT)


def _retry_after_seconds(exc: urllib.error.HTTPError) -> float | None:
    """The numeric ``Retry-After`` (seconds) from a 429/503 response, or ``None``. The
    HTTP-date form is intentionally ignored in favor of the deterministic backoff schedule."""
    headers = getattr(exc, "headers", None)
    value = ((headers.get("Retry-After") if headers is not None else None) or "").strip()
    return float(value) if value.isdigit() else None


def _open_with_retry(req: urllib.request.Request):
    """Open ``req``, retrying on HTTP 429/503 with a deterministic exponential backoff.

    Honors a numeric ``Retry-After`` header; otherwise waits 1, 2, 4, 8, 16 s (each capped at
    :data:`_MAX_BACKOFF`). After :data:`_MAX_RETRIES` retries the final ``HTTPError``
    propagates, so the caller maps 404 -> None and any other code -> AcquireError. No
    randomness; this never changes how many bytes are read.
    """
    delay = _BACKOFF_BASE
    for attempt in range(_MAX_RETRIES + 1):
        try:
            return _urlopen(req)
        except urllib.error.HTTPError as exc:
            if exc.code in _RETRY_STATUSES and attempt < _MAX_RETRIES:
                _sleep(min(_retry_after_seconds(exc) or delay, _MAX_BACKOFF))
                delay = min(delay * 2, _MAX_BACKOFF)
                continue
            raise


def _gated_message(url: str, code: int) -> str:
    """A 401/403 on a HF resource almost always means the repo is gated or private (Phase 20).
    Point the user at HF_TOKEN rather than surfacing a bare HTTP code."""
    hint = ("set HF_TOKEN to a token with access" if "HF_TOKEN" not in os.environ
            else "the current HF_TOKEN lacks access to this repo")
    return f"{url}: HTTP {code} — gated or private repo; {hint}"


def _read_capped(resp, limit: int) -> bytes:
    """Read at most ``limit`` bytes from a response (a hostile host cannot make us read
    more than we asked for). Handles partial reads."""
    buf = bytearray()
    while len(buf) < limit:
        chunk = resp.read(limit - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _http_get(url: str, *, cap: int = _HF_SOURCE_MAX_BYTES) -> bytes | None:
    """GET ``url`` and return its body, or ``None`` if it is 404 (a missing optional file).

    The read is capped at ``cap`` bytes: if the host advertises or streams more we raise
    :class:`WeightsLoadedError` rather than download it, so this path can never pull weights.
    """
    req = _build_request(url)
    try:
        resp = _open_with_retry(req)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code in (401, 403):
            raise AcquireError(_gated_message(url, exc.code)) from exc
        raise AcquireError(f"{url}: HTTP {exc.code}") from exc
    with resp:
        length = resp.headers.get("Content-Length", "")
        if length.isdigit() and int(length) > cap:
            raise WeightsLoadedError(
                f"{url}: Content-Length {length} exceeds the {cap}-byte metadata cap; "
                "refusing to download (possible weights)"
            )
        data = _read_capped(resp, cap + 1)
    if len(data) > cap:
        raise WeightsLoadedError(
            f"{url}: response exceeds the {cap}-byte metadata cap; refusing to read further "
            "(possible weights)"
        )
    return data


def _http_range(url: str, start: int, length: int) -> bytes | None:
    """Range-GET ``length`` bytes of ``url`` from ``start``, or ``None`` if unavailable.

    Returns ``None`` on 404 or when the host will not honor the range (status != 206) —
    rather than read the body — so a fallback safetensors read can never stream the file.
    ``length`` is bounded by the caller and by :data:`_HF_SOURCE_MAX_BYTES`.
    """
    if length <= 0:
        return b""
    if length > _HF_SOURCE_MAX_BYTES:
        raise WeightsLoadedError(
            f"{url}: refusing a {length}-byte range read (> {_HF_SOURCE_MAX_BYTES}-byte cap)"
        )
    end = start + length - 1
    req = _build_request(url, extra_headers={"Range": f"bytes={start}-{end}"})
    try:
        resp = _open_with_retry(req)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code in (401, 403):
            raise AcquireError(_gated_message(url, exc.code)) from exc
        raise AcquireError(f"{url}: HTTP {exc.code}") from exc
    with resp:
        if resp.status != 206:
            return None  # host ignored Range; do not read the body (no weights)
        return _read_capped(resp, length)


def _templates_from_config(config: object) -> list[ChatTemplate]:
    """The chat templates declared in a parsed ``tokenizer_config.json`` (``[]`` if none).

    ``chat_template`` is a string (one default) or a list of ``{name, template}`` dicts; the
    entry named ``"default"`` (or unnamed) is the default (``ChatTemplate.name is None``).
    """
    if not isinstance(config, dict):
        return []
    chat_template = config.get("chat_template")
    if isinstance(chat_template, str):
        return [ChatTemplate(None, chat_template)]
    if isinstance(chat_template, list):
        default: list[ChatTemplate] = []
        named: list[ChatTemplate] = []
        for entry in chat_template:
            if not (isinstance(entry, dict) and isinstance(entry.get("template"), str)):
                continue
            name = entry.get("name")
            if name in (None, _DEFAULT_TEMPLATE_NAME):
                default.append(ChatTemplate(None, entry["template"]))
            else:
                named.append(ChatTemplate(str(name), entry["template"]))
        return default + sorted(named, key=lambda t: t.name or "")
    return []


def _safetensors_chat_template(base_url: str) -> tuple[str, int] | None:
    """``(template, bytes_read)`` from ``model.safetensors``' ``__metadata__.chat_template``,
    or ``None``. Reads only the 8-byte length prefix + the JSON header — never the tensors."""
    url = f"{base_url}/model.safetensors"
    head = _http_range(url, 0, 8)
    if head is None or len(head) < 8:
        return None
    header_len = struct.unpack("<Q", head)[0]
    if header_len <= 0 or header_len > _HF_SOURCE_MAX_BYTES:
        return None
    header_bytes = _http_range(url, 8, header_len)
    if header_bytes is None or len(header_bytes) < header_len:
        return None
    try:
        header = json.loads(header_bytes)
    except json.JSONDecodeError:
        return None
    metadata = header.get("__metadata__") if isinstance(header, dict) else None
    template = metadata.get("chat_template") if isinstance(metadata, dict) else None
    if isinstance(template, str):
        return template, 8 + len(header_bytes)
    return None


def _raw(repo: str, templates: list[ChatTemplate], bytes_fetched: int) -> RawTemplate:
    """Wrap extracted templates. ``total_size == bytes_fetched``: these are standalone
    metadata files, not the model weights, so the GGUF fraction invariant does not apply —
    the no-weights guarantee here is the absolute :data:`_HF_SOURCE_MAX_BYTES` cap on every
    read plus the fact that only metadata files are ever requested."""
    return RawTemplate(
        source_ref=repo,
        templates=tuple(templates),
        bytes_fetched=bytes_fetched,
        total_size=bytes_fetched,
    )


def smallest_gguf_filename(repo: str, *, revision: str = "main") -> str:
    """The smallest ``.gguf`` file in ``repo`` (for the CLI ``--file auto``), via the Hub tree
    API. A metadata-only listing (filenames + sizes), never the weights; the result is
    deterministic (smallest size, ties broken by path) and sends HF_TOKEN if set so it
    works on gated/private repos. Raises :class:`AcquireError` if the repo has no ``.gguf`` or
    the listing cannot be read.
    """
    url = f"https://huggingface.co/api/models/{repo}/tree/{revision}?recursive=true"
    data = _http_get(url)
    if data is None:
        raise AcquireError(f"{repo}: could not list repo files (404)")
    try:
        entries = json.loads(data)
    except json.JSONDecodeError as exc:
        raise AcquireError(f"{repo}: repo file listing is not valid JSON: {exc}") from exc
    candidates: list[tuple[int, str]] = []
    for entry in entries if isinstance(entries, list) else []:
        if not (isinstance(entry, dict) and entry.get("type") == "file"):
            continue
        path = entry.get("path")
        if not (isinstance(path, str) and path.lower().endswith(".gguf")):
            continue
        size = entry.get("size")
        if not isinstance(size, int):                       # LFS files carry it under "lfs"
            lfs = entry.get("lfs")
            size = lfs.get("size") if isinstance(lfs, dict) else None
        candidates.append((size if isinstance(size, int) else (1 << 62), path))
    if not candidates:
        raise AcquireError(
            f"{repo}: no .gguf file found — pass --file <name>.gguf, or omit --file to read "
            "the canonical tokenizer_config.json / chat_template.jinja template"
        )
    candidates.sort()  # (size, path): smallest size first, deterministic tie-break by path
    return candidates[0][1]


def read_hf_source_template(repo: str, *, revision: str = "main") -> RawTemplate:
    """Read the canonical chat template(s) from a Hugging Face repo, never reading weights.

    Tries ``tokenizer_config.json`` (string or multi-template list), then
    ``chat_template.jinja``, then the ``model.safetensors`` ``__metadata__``. Raises
    :class:`TemplateNotFoundError` if none carry a template. ``revision`` should be a pinned
    commit SHA for determinism.
    """
    base_url = f"https://huggingface.co/{repo}/resolve/{revision}"

    config_bytes = _http_get(f"{base_url}/tokenizer_config.json")
    if config_bytes is not None:
        try:
            config = json.loads(config_bytes)
        except json.JSONDecodeError as exc:
            raise AcquireError(f"{repo}: tokenizer_config.json is not valid JSON: {exc}") from exc
        templates = _templates_from_config(config)
        if templates:
            return _raw(repo, templates, len(config_bytes))

    jinja_bytes = _http_get(f"{base_url}/chat_template.jinja")
    if jinja_bytes is not None:
        text = decode_utf8_or_raise(jinja_bytes, repo, "chat_template.jinja")
        return _raw(repo, [ChatTemplate(None, text)], len(jinja_bytes))

    safetensors = _safetensors_chat_template(base_url)
    if safetensors is not None:
        text, bytes_read = safetensors
        return _raw(repo, [ChatTemplate(None, text)], bytes_read)

    raise TemplateNotFoundError(
        f"{repo}: no chat_template in tokenizer_config.json, chat_template.jinja, or "
        "the safetensors metadata"
    )
