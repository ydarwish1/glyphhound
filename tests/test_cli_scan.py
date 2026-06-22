"""Offline, deterministic tests for the end-to-end scan (Phase 9).

Phase 9 wires the Stage-1 acquirer into the scan path: ``scan_source`` resolves a model
reference (local file / ``.gguf`` URL / Hugging Face repo / Ollama name), extracts **every**
template (default + named) without loading weights, analyzes each, and tags findings by
template name. These tests drive each source type with the synthetic fixtures
(``build_gguf`` / ``RangeServer`` / ``write_ollama_model``) so the whole suite stays offline
and deterministic (the project conventions) — real-model / no-weights verification lives in
``scripts/verify_phase9.py``.

The headline (ARCHITECTURE.md §7 payoff): a sink hidden in a *named* template variant is
caught and tagged to that template, even when the default template is benign.
"""

from __future__ import annotations

import io
import json
import os

import pytest

from glyphhound.acquire import AcquireError, ChatTemplate, RawTemplate
from glyphhound.cli import main
from glyphhound.scan import ScanError, scan_source
from synthetic import RangeServer, build_gguf, write_ollama_model

ROOT = os.path.dirname(os.path.dirname(__file__))

# Reuse the committed MARKER fixture (the project conventions — marker only, never a real
# payload): a public SSTI gadget chain that the analyzer flags reachable.
MALICIOUS = open(
    os.path.join(ROOT, "fixtures", "malicious", "reachable_sink_marker.jinja"),
    encoding="utf-8",
).read()
BENIGN = "{% for m in messages %}{{ m.role }}: {{ m.content }}\n{% endfor %}"


# --------------------------------------------------------------------------- #
# scan_source — source resolution + multi-template scanning
# --------------------------------------------------------------------------- #
def test_local_gguf_named_template_is_caught_and_tagged(tmp_path):
    """The §7 payoff: a benign default but a malicious NAMED template → caught + tagged."""
    gguf = build_gguf(chat_template=BENIGN, named_templates={"tokenizer.chat_template.tool_use": MALICIOUS})
    path = tmp_path / "model.gguf"
    path.write_bytes(gguf)

    report = scan_source(str(path))

    assert report.exit_code != 0
    reachable = [f for f in report.findings if f.reachable]
    assert reachable, "the named-template sink should be reachable"
    # Every reachable finding is attributed to the named template, not the benign default.
    assert all(f.template_name == "tool_use" for f in reachable)


def test_local_gguf_benign_is_clean(tmp_path):
    gguf = build_gguf(chat_template=BENIGN)
    path = tmp_path / "model.gguf"
    path.write_bytes(gguf)

    report = scan_source(str(path))

    assert report.exit_code == 0
    assert report.summary.gating == 0


def test_gguf_url_over_http_range(tmp_path):
    payload = build_gguf(chat_template=BENIGN, named_templates={"tokenizer.chat_template.tool_use": MALICIOUS})
    payload += b"\x00" * 4096  # trailing "weights" we must not need
    with RangeServer(payload) as server:
        report = scan_source(server.url)  # auto -> gguf-url

    assert report.exit_code != 0
    assert any(f.template_name == "tool_use" for f in report.findings)


def test_ollama_malicious(tmp_path, monkeypatch):
    models_dir = tmp_path / "ollama"
    write_ollama_model(str(models_dir), "evilmodel", MALICIOUS)
    monkeypatch.setenv("OLLAMA_MODELS", str(models_dir))

    report = scan_source("evilmodel:latest")  # auto -> ollama

    assert report.exit_code != 0


def test_ollama_benign_default_tag(tmp_path, monkeypatch):
    models_dir = tmp_path / "ollama"
    write_ollama_model(str(models_dir), "goodmodel", BENIGN)
    monkeypatch.setenv("OLLAMA_MODELS", str(models_dir))

    report = scan_source("goodmodel")  # bare name -> ollama, tag defaults to latest

    assert report.exit_code == 0


def test_raw_template_file_autodetected(tmp_path):
    path = tmp_path / "tmpl.jinja"
    path.write_text(MALICIOUS, encoding="utf-8")  # not GGUF magic -> raw template

    assert scan_source(str(path)).exit_code != 0


def test_raw_benign_file(tmp_path):
    path = tmp_path / "tmpl.jinja"
    path.write_text(BENIGN, encoding="utf-8")

    assert scan_source(str(path)).exit_code == 0


# --------------------------------------------------------------------------- #
# --source override + error paths (all offline — no fetch reached)
# --------------------------------------------------------------------------- #
def test_source_override_forces_gguf_on_raw_file(tmp_path):
    """`--source gguf` on a raw text file is honored: it is read as GGUF -> bad magic.

    Auto-detect would have read this same file as a (benign) raw template, so the raised
    error proves the explicit override took precedence over the magic-byte sniff.
    """
    path = tmp_path / "tmpl.jinja"
    path.write_text(BENIGN, encoding="utf-8")
    with pytest.raises(AcquireError):
        scan_source(str(path), source="gguf")


def test_source_override_forces_file_on_gguf(tmp_path):
    """`--source file` on a real GGUF is honored: its bytes are read as text, not parsed."""
    gguf = build_gguf(chat_template=BENIGN)  # contains non-UTF-8 bytes (int arrays)
    path = tmp_path / "model.gguf"
    path.write_bytes(gguf)
    with pytest.raises(ScanError):
        scan_source(str(path), source="file")


def test_hf_without_file_uses_canonical_source_explicit(monkeypatch):
    # Phase 14: no --file -> read the repo's canonical template (tokenizer_config.json), not an error.
    seen = {}

    def fake_hf(repo, *, revision="main"):
        seen["repo"] = repo
        return RawTemplate(repo, (ChatTemplate(None, MALICIOUS),), 100, 100)
    monkeypatch.setattr("glyphhound.scan.read_hf_source_template", fake_hf)
    report = scan_source("owner/model", source="hf")  # no --file
    assert seen["repo"] == "owner/model"
    assert report.exit_code == 1


def test_hf_without_file_uses_canonical_source_auto(monkeypatch):
    # owner/name auto-detects as an HF repo; without --file it reads the canonical source.
    seen = {}

    def fake_hf(repo, *, revision="main"):
        seen["repo"] = repo
        return RawTemplate(repo, (ChatTemplate(None, BENIGN),), 100, 100)
    monkeypatch.setattr("glyphhound.scan.read_hf_source_template", fake_hf)
    report = scan_source("owner/model")  # auto -> hf -> canonical source (no --file)
    assert seen["repo"] == "owner/model"
    assert report.exit_code == 0


def test_ambiguous_ref_errors():
    with pytest.raises(ScanError):
        scan_source("a/b/c/d")  # 3 slashes, not a path -> matches no source pattern


def test_gguf_url_must_end_with_gguf():
    with pytest.raises(ScanError):
        scan_source("https://example.com/model.bin", source="gguf-url")


def test_auto_http_non_gguf_url_errors():
    with pytest.raises(ScanError):
        scan_source("https://example.com/model.bin")  # auto -> gguf-url -> not .gguf


# --------------------------------------------------------------------------- #
# CLI: main() exit codes + output
# --------------------------------------------------------------------------- #
def test_cli_local_gguf_named_template(tmp_path, capsys):
    gguf = build_gguf(chat_template=BENIGN, named_templates={"tokenizer.chat_template.tool_use": MALICIOUS})
    path = tmp_path / "model.gguf"
    path.write_bytes(gguf)

    rc = main(["scan", str(path), "--format", "json"])

    out = capsys.readouterr().out
    assert rc != 0
    doc = json.loads(out)
    assert any(f["template_name"] == "tool_use" for f in doc["findings"])


def test_cli_benign_exit_zero(tmp_path, capsys):
    gguf = build_gguf(chat_template=BENIGN)
    path = tmp_path / "model.gguf"
    path.write_bytes(gguf)

    assert main(["scan", str(path)]) == 0


def test_cli_gguf_url(capsys):
    payload = build_gguf(chat_template=BENIGN, named_templates={"tokenizer.chat_template.tool_use": MALICIOUS})
    with RangeServer(payload) as server:
        rc = main(["scan", server.url, "--format", "json"])

    out = capsys.readouterr().out
    assert rc != 0
    assert json.loads(out)["findings"]


def test_cli_ambiguous_ref_exits_2(capsys):
    rc = main(["scan", "a/b/c/d"])

    err = capsys.readouterr().err
    assert rc == 2
    assert "source" in err.lower()


def test_cli_hf_missing_file_exits_2(capsys):
    rc = main(["scan", "owner/model", "--source", "hf"])

    assert rc == 2
    assert capsys.readouterr().err  # a clean message, not a traceback


def test_cli_stdin_still_works(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(MALICIOUS))

    rc = main(["scan", "-", "--format", "json"])

    out = capsys.readouterr().out
    assert rc != 0
    assert json.loads(out)["findings"]


def test_cli_source_override(tmp_path, capsys):
    # A raw benign template forced to be read as GGUF -> clean error exit (2), not a crash.
    path = tmp_path / "tmpl.jinja"
    path.write_text(BENIGN, encoding="utf-8")

    rc = main(["scan", str(path), "--source", "gguf"])

    assert rc == 2
    assert capsys.readouterr().err
