"""Offline tests for Phase 14 — scan the real source (HF tokenizer_config.json etc.).

No network: the HTTP fetchers are monkeypatched to serve synthetic metadata. Covers the
``chat_template`` string and multi-template list forms, the ``chat_template.jinja`` and
safetensors fallbacks, the no-template error, the no-weights cap, and the ``scan_source``
routing that lets ``scan owner/name`` work WITHOUT ``--file``. MARKER-only; the analyzer
parses + walks the template, never renders it.
"""

from __future__ import annotations

import json
import struct

import pytest

from glyphhound.acquire import (
    ChatTemplate,
    RawTemplate,
    TemplateNotFoundError,
    WeightsLoadedError,
    hf_source,
)
from glyphhound.acquire.hf_source import _templates_from_config, read_hf_source_template
from glyphhound.analyze import analyze_raw
from glyphhound.report import make_report
from glyphhound.scan import scan_source

# A public Jinja2 SSTI dunder chain -> reachable GH-S001 (MARKER only; never rendered).
MARKER = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
BENIGN = "{% for m in messages %}{{ m.role }}: {{ m.content }}{% endfor %}"


def _serve(monkeypatch, files: dict[str, bytes]) -> None:
    """Make ``_http_get`` return ``files[suffix]`` for a matching URL suffix, else 404; and
    ``_http_range`` return nothing (no safetensors) unless a test overrides it."""
    def fake_get(url, *, cap=hf_source._HF_SOURCE_MAX_BYTES):
        for suffix, body in files.items():
            if url.endswith(suffix):
                return body
        return None
    monkeypatch.setattr(hf_source, "_http_get", fake_get)
    monkeypatch.setattr(hf_source, "_http_range", lambda *a, **k: None)


# --- _templates_from_config (pure) ----------------------------------------------

def test_config_string_form():
    assert _templates_from_config({"chat_template": MARKER}) == [ChatTemplate(None, MARKER)]


def test_config_list_form_default_and_named():
    templates = _templates_from_config({"chat_template": [
        {"name": "default", "template": BENIGN},
        {"name": "tool_use", "template": MARKER},
    ]})
    assert ChatTemplate(None, BENIGN) in templates       # "default" -> the unnamed default
    assert ChatTemplate("tool_use", MARKER) in templates


def test_config_no_chat_template_or_not_a_dict():
    assert _templates_from_config({"model_max_length": 4096}) == []
    assert _templates_from_config("not a dict") == []
    assert _templates_from_config({"chat_template": [{"name": "x"}]}) == []  # no "template" key


# --- read_hf_source_template via the metadata sources ---------------------------

def test_reads_tokenizer_config_string_form(monkeypatch):
    _serve(monkeypatch, {"tokenizer_config.json": json.dumps({"chat_template": MARKER}).encode()})
    raw = read_hf_source_template("owner/name", revision="deadbeef")
    assert [t.text for t in raw.templates] == [MARKER]
    assert make_report(analyze_raw(raw)).exit_code == 1


def test_named_malicious_template_is_caught_and_tagged(monkeypatch):
    body = json.dumps({"chat_template": [
        {"name": "default", "template": BENIGN},
        {"name": "tool_use", "template": MARKER},
    ]}).encode()
    _serve(monkeypatch, {"tokenizer_config.json": body})
    findings = analyze_raw(read_hf_source_template("owner/name"))
    assert any(f.template_name == "tool_use" and f.reachable for f in findings)
    assert make_report(findings).exit_code == 1


def test_falls_back_to_chat_template_jinja(monkeypatch):
    # tokenizer_config.json exists but carries no chat_template -> use chat_template.jinja.
    _serve(monkeypatch, {
        "tokenizer_config.json": json.dumps({"model_max_length": 4096}).encode(),
        "chat_template.jinja": MARKER.encode(),
    })
    raw = read_hf_source_template("owner/name")
    assert [t.text for t in raw.templates] == [MARKER]


def test_falls_back_to_safetensors_metadata(monkeypatch):
    monkeypatch.setattr(hf_source, "_http_get", lambda url, **k: None)   # no json, no jinja
    header = json.dumps({"__metadata__": {"chat_template": MARKER}}).encode()
    blob = struct.pack("<Q", len(header)) + header

    def fake_range(url, start, length):
        return blob[start:start + length]
    monkeypatch.setattr(hf_source, "_http_range", fake_range)
    raw = read_hf_source_template("owner/name")
    assert [t.text for t in raw.templates] == [MARKER]


def test_no_template_anywhere_raises(monkeypatch):
    monkeypatch.setattr(hf_source, "_http_get", lambda url, **k: None)
    monkeypatch.setattr(hf_source, "_http_range", lambda *a, **k: None)
    with pytest.raises(TemplateNotFoundError):
        read_hf_source_template("owner/name")


def test_no_weights_bytes_are_tiny(monkeypatch):
    _serve(monkeypatch, {"tokenizer_config.json": json.dumps({"chat_template": BENIGN}).encode()})
    raw = read_hf_source_template("owner/name")
    assert raw.bytes_fetched < 1_000_000  # a metadata read, never the weights


def test_oversized_config_is_refused(monkeypatch):
    class _Resp:
        status = 200
        headers = {"Content-Length": str(hf_source._HF_SOURCE_MAX_BYTES + 1)}
        def read(self, n): return b"x" * n
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(hf_source.urllib.request, "urlopen", lambda *a, **k: _Resp())
    with pytest.raises(WeightsLoadedError):
        read_hf_source_template("owner/name")


# --- scan_source routing: `scan owner/name` works WITHOUT --file -----------------

def test_scan_source_hf_without_file_uses_canonical_source(monkeypatch):
    seen = {}

    def fake_hf(repo, *, revision="main"):
        seen["repo"], seen["revision"] = repo, revision
        return RawTemplate(repo, (ChatTemplate(None, MARKER),), 100, 100)
    monkeypatch.setattr("glyphhound.scan.read_hf_source_template", fake_hf)
    report = scan_source("owner/name", revision="abc123")  # no filename, auto-detect -> hf
    assert seen == {"repo": "owner/name", "revision": "abc123"}
    assert report.exit_code == 1


def test_scan_source_hf_with_file_still_uses_gguf(monkeypatch):
    seen = {}

    def fake_gguf(ref, *, filename=None, revision="main"):
        seen["filename"] = filename
        return RawTemplate(ref, (ChatTemplate(None, BENIGN),), 100, 100_000)
    monkeypatch.setattr("glyphhound.scan.read_gguf_template", fake_gguf)
    report = scan_source("owner/name", filename="model.gguf")
    assert seen["filename"] == "model.gguf"
    assert report.exit_code == 0
