"""Stage 1 (Acquirer) — read a locally-pulled Ollama model's chat template, no weights.

Ollama stores each model as an OCI-style manifest plus content-addressed blobs:

    <models>/manifests/<registry>/<namespace>/<name>/<tag>   (tiny JSON)
    <models>/blobs/sha256-<hex>                               (one file per layer)

Each manifest ``layers`` entry carries a ``mediaType``; the chat template is the
layer typed ``application/vnd.ollama.image.template``. We read only that one small
blob (and verify its sha256), never the ``...image.model`` weights blob — we never
even open it.
"""

from __future__ import annotations

import hashlib
import json
import os

from .models import (
    AcquireError,
    ChatTemplate,
    RawTemplate,
    TemplateNotFoundError,
    decode_utf8_or_raise,
)

_TEMPLATE_MEDIA = "application/vnd.ollama.image.template"
_DEFAULT_REGISTRY = "registry.ollama.ai"
_DEFAULT_NAMESPACE = "library"


def default_models_dir() -> str:
    """The Ollama models directory: ``$OLLAMA_MODELS`` or ``~/.ollama/models``."""
    env = os.environ.get("OLLAMA_MODELS")
    if env:
        return env
    return os.path.join(os.path.expanduser("~"), ".ollama", "models")


def _blob_path(models_dir: str, digest: str) -> str:
    # registry digest "sha256:HEX" -> on-disk file "sha256-HEX"
    return os.path.join(models_dir, "blobs", digest.replace(":", "-", 1))


def read_ollama_template(
    model: str,
    *,
    models_dir: str | None = None,
    registry: str = _DEFAULT_REGISTRY,
) -> RawTemplate:
    """Extract the chat template for a locally-pulled Ollama model.

    ``model`` is ``name[:tag]`` (tag defaults to ``latest``); a ``namespace/name``
    form overrides the default ``library`` namespace.
    """
    models_dir = models_dir or default_models_dir()
    # Split the optional ":tag" — only a colon AFTER the last "/" is a tag separator,
    # so a ported registry like "host:5000/lib/name" is not mis-split.
    slash = model.rfind("/")
    colon = model.rfind(":")
    if colon > slash:
        ref, tag = model[:colon], model[colon + 1:]
    else:
        ref, tag = model, "latest"
    namespace = _DEFAULT_NAMESPACE
    name = ref
    if "/" in name:
        namespace, _, name = name.rpartition("/")

    manifest_path = os.path.join(models_dir, "manifests", registry, namespace, name, tag)
    if not os.path.isfile(manifest_path):
        raise AcquireError(f"ollama:{model}: manifest not found at {manifest_path}")
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)

    layers = manifest.get("layers", [])
    template_layer = next((l for l in layers if l.get("mediaType") == _TEMPLATE_MEDIA), None)
    if template_layer is None:
        raise TemplateNotFoundError(f"ollama:{model}: no template layer in manifest")

    # total_size = the whole model artifact (every layer we did NOT read), so the
    # bytes_fetched << total_size invariant stays meaningful regardless of which layer
    # is the weights blob. Malformed manifests surface as AcquireError, not KeyError.
    try:
        total_size = sum(int(layer["size"]) for layer in layers)
        digest = template_layer["digest"]
    except (KeyError, TypeError, ValueError) as exc:
        raise AcquireError(f"ollama:{model}: malformed manifest layer ({exc})") from exc

    blob_path = _blob_path(models_dir, digest)
    if not os.path.isfile(blob_path):
        raise AcquireError(f"ollama:{model}: template blob missing at {blob_path}")
    with open(blob_path, "rb") as fh:
        raw = fh.read()

    # Integrity: the template blob is tiny, so verify it matches its digest. We never
    # hash (or even open) the weights blob. An unknown digest algorithm is rejected,
    # not silently trusted.
    algo, _, expected = digest.partition(":")
    if algo != "sha256":
        raise AcquireError(f"ollama:{model}: unsupported template digest algorithm {algo!r}")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise AcquireError(
            f"ollama:{model}: template blob sha256 mismatch "
            f"(manifest {expected[:12]}..., file {actual[:12]}...)"
        )

    # Ollama stores exactly one template layer per model, so there is a single
    # (unnamed) template here.
    text = decode_utf8_or_raise(raw, f"ollama:{model}", "template blob")
    return RawTemplate(
        source_ref=f"ollama:{model}",
        templates=(ChatTemplate(None, text),),
        bytes_fetched=len(raw),
        total_size=total_size,
    )
