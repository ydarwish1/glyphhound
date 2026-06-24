"""Offline, deterministic tests for the Ollama acquirer (Phase 0b).

A synthetic Ollama store is built on disk; no Ollama install or pulled model is
needed. Real-model verification (once Ollama is installed) lives in
``scripts/verify_phase0.py``.
"""

from __future__ import annotations

import json
import os

import pytest

from glyphhound.acquire import (
    AcquireError,
    TemplateNotFoundError,
    read_ollama_template,
)
from synthetic import write_ollama_model

TEMPLATE = "{{ .System }}\n{{ .Prompt }} ☕"


def test_reads_template_without_touching_weights(tmp_path):
    models_dir = str(tmp_path)
    write_ollama_model(models_dir, "smol:test", TEMPLATE, weights_size=270_000_000)

    result = read_ollama_template("smol:test", models_dir=models_dir)

    assert result.template_string == TEMPLATE
    assert result.bytes_fetched == len(TEMPLATE.encode("utf-8"))
    # total_size sums all layers (weights + template); the template is a tiny fraction.
    assert result.total_size == 270_000_000 + len(TEMPLATE.encode("utf-8"))
    result.assert_no_weights_loaded()
    assert result.fraction_fetched < 0.001
    # Proof we never needed the weights: the weights blob file was never created.
    weights_blob = os.path.join(models_dir, "blobs", "sha256-" + "b" * 64)
    assert not os.path.exists(weights_blob)


def test_default_tag_is_latest(tmp_path):
    models_dir = str(tmp_path)
    write_ollama_model(models_dir, "smol", TEMPLATE)  # tag -> "latest"
    result = read_ollama_template("smol", models_dir=models_dir)
    assert result.template_string == TEMPLATE
    assert result.source_ref == "ollama:smol"


def test_digest_mismatch_raises(tmp_path):
    models_dir = str(tmp_path)
    write_ollama_model(models_dir, "smol:test", TEMPLATE, corrupt_template_blob=True)
    with pytest.raises(AcquireError, match="sha256 mismatch"):
        read_ollama_template("smol:test", models_dir=models_dir)


def test_missing_template_layer_raises(tmp_path):
    models_dir = str(tmp_path)
    write_ollama_model(models_dir, "smol:test", TEMPLATE, include_template_layer=False)
    with pytest.raises(TemplateNotFoundError):
        read_ollama_template("smol:test", models_dir=models_dir)


def test_missing_manifest_raises(tmp_path):
    with pytest.raises(AcquireError, match="manifest not found"):
        read_ollama_template("does-not-exist:test", models_dir=str(tmp_path))


def test_namespace_path_and_total_size_is_sum(tmp_path):
    models_dir = str(tmp_path)
    write_ollama_model(models_dir, "smol:test", TEMPLATE, weights_size=500, namespace="myorg")
    result = read_ollama_template("myorg/smol:test", models_dir=models_dir)
    assert result.template_string == TEMPLATE
    # total_size sums every layer: weights(500) + template blob length.
    assert result.total_size == 500 + len(TEMPLATE.encode("utf-8"))


def test_non_sha256_digest_rejected(tmp_path):
    models_dir = str(tmp_path)
    write_ollama_model(models_dir, "smol:test", TEMPLATE, digest_algo="sha512")
    with pytest.raises(AcquireError, match="digest algorithm"):
        read_ollama_template("smol:test", models_dir=models_dir)


def test_non_utf8_template_blob_raises(tmp_path):
    models_dir = str(tmp_path)
    write_ollama_model(models_dir, "smol:test", "", template_raw_bytes=b"\xff\xfe bad")
    with pytest.raises(AcquireError, match="not valid UTF-8"):
        read_ollama_template("smol:test", models_dir=models_dir)


def test_malformed_manifest_layer_raises(tmp_path):
    # A template layer missing its digest must surface as AcquireError, not KeyError.
    models_dir = str(tmp_path)
    write_ollama_model(models_dir, "smol:test", TEMPLATE)
    mpath = os.path.join(models_dir, "manifests", "registry.ollama.ai", "library", "smol", "test")
    with open(mpath, encoding="utf-8") as fh:
        manifest = json.load(fh)
    for layer in manifest["layers"]:
        layer.pop("digest", None)
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    with pytest.raises(AcquireError):
        read_ollama_template("smol:test", models_dir=models_dir)
