"""Builders for deterministic, offline acquisition fixtures.

Nothing here touches the network or a real model. We synthesize a minimal GGUF
byte string and a synthetic Ollama model store so the acquirer can be verified
fully offline (the project conventions — determinism).
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import struct
import threading

# GGUF metadata value types (mirror of gguf.py — kept local so the test fixture
# is independent of the code under test).
_I32, _STRING, _ARRAY = 5, 8, 9


def _gguf_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack("<Q", len(raw)) + raw


def _kv_string(key: str, value: str) -> bytes:
    return _gguf_string(key) + struct.pack("<I", _STRING) + _gguf_string(value)


def _kv_i32_array(key: str, count: int) -> bytes:
    body = b"".join(struct.pack("<i", i % 1000) for i in range(count))
    return (
        _gguf_string(key)
        + struct.pack("<I", _ARRAY)
        + struct.pack("<I", _I32)
        + struct.pack("<Q", count)
        + body
    )


def _kv_string_array(key: str, items: list[str]) -> bytes:
    body = b"".join(_gguf_string(x) for x in items)
    return (
        _gguf_string(key)
        + struct.pack("<I", _ARRAY)
        + struct.pack("<I", _STRING)
        + struct.pack("<Q", len(items))
        + body
    )


def _kv_raw_string(key: str, raw_value: bytes) -> bytes:
    return _gguf_string(key) + struct.pack("<I", _STRING) + struct.pack("<Q", len(raw_value)) + raw_value


def _kv_nested_array(key: str) -> bytes:
    # An array whose elements are themselves int32 arrays (exercises nested skipping).
    inner = struct.pack("<I", _I32) + struct.pack("<Q", 2) + struct.pack("<i", 1) + struct.pack("<i", 2)
    return (
        _gguf_string(key)
        + struct.pack("<I", _ARRAY)
        + struct.pack("<I", _ARRAY)
        + struct.pack("<Q", 2)
        + inner + inner
    )


def build_gguf(chat_template: str = "", *, tokens: int = 64, scores: int = 256,
               include_template: bool = True, template_bytes: bytes | None = None,
               named_templates: dict | None = None, nested_array: bool = False) -> bytes:
    """A minimal valid GGUF v3 metadata block.

    Large-ish arrays are placed *before* the chat template so the parser must skip
    both a fixed-width array and a string array to reach it.

    * ``template_bytes`` injects a raw (possibly non-UTF-8) template value.
    * ``named_templates`` emits ``tokenizer.chat_template.<name>`` keys.
    * ``nested_array`` adds an array-of-arrays before the template.
    """
    kvs = [
        _kv_string("general.architecture", "llama"),
        _kv_string("general.name", "synthetic-fixture"),
        _kv_i32_array("synthetic.scores", scores),                      # fixed-width array -> skip
        _kv_string_array("tokenizer.ggml.tokens",
                         [f"tok{i}" for i in range(tokens)]),           # string array -> skip
    ]
    if nested_array:
        kvs.append(_kv_nested_array("synthetic.nested"))
    for name, value in (named_templates or {}).items():
        kvs.append(_kv_string(name, value))
    if template_bytes is not None:
        kvs.append(_kv_raw_string("tokenizer.chat_template", template_bytes))
    elif include_template:
        kvs.append(_kv_string("tokenizer.chat_template", chat_template))  # the target, last
    header = (
        b"GGUF"
        + struct.pack("<I", 3)            # version
        + struct.pack("<Q", 0)            # tensor_count
        + struct.pack("<Q", len(kvs))     # metadata_kv_count
    )
    return header + b"".join(kvs)


def write_ollama_model(
    models_dir: str,
    model: str,
    template: str,
    *,
    weights_size: int = 270_000_000,
    create_weights_blob: bool = False,
    corrupt_template_blob: bool = False,
    include_template_layer: bool = True,
    template_raw_bytes: bytes | None = None,
    digest_algo: str = "sha256",
    registry: str = "registry.ollama.ai",
    namespace: str = "library",
) -> dict:
    """Lay down a synthetic Ollama store: a manifest + the template blob.

    By default the *weights* blob file is NOT created — the reader must never need
    it. ``template_raw_bytes`` injects raw (possibly non-UTF-8) template content;
    ``digest_algo`` lets a test use a non-sha256 digest. Returns the manifest dict.
    """
    name, _, tag = model.partition(":")
    tag = tag or "latest"

    blobs_dir = os.path.join(models_dir, "blobs")
    os.makedirs(blobs_dir, exist_ok=True)

    intended = template_raw_bytes if template_raw_bytes is not None else template.encode("utf-8")
    if digest_algo == "sha256":
        template_digest = "sha256:" + hashlib.sha256(intended).hexdigest()
    else:
        template_digest = f"{digest_algo}:" + ("0" * 64)  # algorithm we expect to be rejected
    blob_on_disk = intended + (b"corrupt" if corrupt_template_blob else b"")
    with open(os.path.join(blobs_dir, template_digest.replace(":", "-", 1)), "wb") as fh:
        fh.write(blob_on_disk)

    # A weights digest that points at a file we intentionally do not create.
    weights_digest = "sha256:" + ("b" * 64)
    if create_weights_blob:
        with open(os.path.join(blobs_dir, weights_digest.replace(":", "-", 1)), "wb") as fh:
            fh.write(b"\x00" * 16)

    layers = [
        {"mediaType": "application/vnd.ollama.image.model",
         "digest": weights_digest, "size": weights_size},
    ]
    if include_template_layer:
        layers.append(
            {"mediaType": "application/vnd.ollama.image.template",
             "digest": template_digest, "size": len(intended)}
        )
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                   "digest": "sha256:" + ("c" * 64), "size": 561},
        "layers": layers,
    }

    manifest_dir = os.path.join(models_dir, "manifests", registry, namespace, name)
    os.makedirs(manifest_dir, exist_ok=True)
    with open(os.path.join(manifest_dir, tag), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    return manifest


class RangeServer:
    """A localhost HTTP server that serves a fixed byte payload.

    With ``honor_range=True`` it answers ``Range`` requests with ``206 Partial
    Content`` + ``Content-Range``; with ``honor_range=False`` it ignores Range and
    returns the full body with ``200`` (to exercise the acquirer's refusal path).
    """

    def __init__(self, payload: bytes, *, honor_range: bool = True, oversend: bool = False):
        self._payload = payload
        self._honor_range = honor_range
        self._oversend = oversend  # malicious server: send more than the requested range
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence test output
                pass

            def do_GET(self):
                data = outer._payload
                rng = self.headers.get("Range")
                if rng and outer._honor_range:
                    spec = rng.split("=", 1)[1]
                    start_s, _, end_s = spec.partition("-")
                    start = int(start_s)
                    end = int(end_s) if end_s else len(data) - 1
                    end = min(end, len(data) - 1)
                    # A hostile server can claim a small range but flood the whole file.
                    body = data[start:] if outer._oversend else data[start:end + 1]
                    self.send_response(206)
                    self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

        self._server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}/model.gguf"

    def __enter__(self) -> "RangeServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
