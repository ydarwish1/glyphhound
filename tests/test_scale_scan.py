"""Offline tests for Phase 17 step 2 — the prevalence scale-scan core (scripts/scale_scan.py).

No network: the pure summary/obfuscation classification, the resume-skip helper, and the
per-repo loop (with ``read_hf_source_template`` monkeypatched) are exercised on synthetic
templates. Crucially, these assert the SAFETY contract: a summary record
NEVER contains the raw template text — only its sha256, finding counts, and the
flagged sink identifiers. MARKER-only; the analyzer parses + walks, never renders.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import scale_scan  # noqa: E402

from glyphhound.acquire import ChatTemplate, RawTemplate  # noqa: E402

# A plain Jinja2 SSTI dunder chain — gates on the raw walk too (NOT obfuscated).
MARKER = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
# The same capability hidden behind string concat — gates ONLY after de-obfuscation.
MARKER_OBF = "{{ ''['__cl' + 'ass__'] }}"
BENIGN = "{% for m in messages %}{{ m.role }}: {{ m.content }}{% endfor %}"


def test_summarize_benign_does_not_gate():
    rec = scale_scan.summarize_template(None, BENIGN)
    assert rec["gates_ci"] is False
    assert rec["obfuscated"] is False
    assert rec["n_findings"] == 0
    assert rec["n_reachable"] == 0


def test_summarize_plain_marker_gates_but_not_obfuscated():
    rec = scale_scan.summarize_template(None, MARKER)
    assert rec["gates_ci"] is True
    assert rec["obfuscated"] is False          # visible on the raw walk too
    assert rec["n_reachable"] >= 1
    assert "GH-S001" in rec["reachable_rule_ids"]


def test_summarize_obfuscated_marker_gates_and_is_flagged_obfuscated():
    rec = scale_scan.summarize_template(None, MARKER_OBF)
    assert rec["gates_ci"] is True
    assert rec["obfuscated"] is True           # gates only after de-obfuscation


def test_summary_record_never_contains_raw_template_text():
    # The whole point of "remove the malicious findings": no payload on disk. The record keeps
    # the template's SHA + the flagged sink IDENTIFIERS (evidence) — never the raw source text.
    for text in (MARKER, MARKER_OBF, BENIGN):
        rec = scale_scan.summarize_template("tool_use", text)
        assert text not in json.dumps(rec)              # the raw template is never embedded
        assert len(rec["template_sha256"]) == 64        # the SHA is what we keep instead
        int(rec["template_sha256"], 16)                 # ... and it is valid hex


def test_scan_repo_summarizes_every_template_no_raw_text(monkeypatch):
    raw = RawTemplate(
        source_ref="owner/name",
        templates=(ChatTemplate(None, BENIGN), ChatTemplate("tool_use", MARKER_OBF)),
        bytes_fetched=4321,
        total_size=4321,
    )
    monkeypatch.setattr(scale_scan, "read_hf_source_template", lambda repo, *, revision: raw)
    rec = scale_scan.scan_repo("owner/name", "deadbeef")
    assert rec["model"] == "owner/name" and rec["revision"] == "deadbeef"
    assert rec["n_templates"] == 2
    named = next(t for t in rec["templates"] if t["template_name"] == "tool_use")
    assert named["gates_ci"] is True and named["obfuscated"] is True
    assert MARKER_OBF not in json.dumps(rec)   # no raw payload anywhere in the model record


def test_scan_repo_records_unparseable_template_as_coverage_gap(monkeypatch):
    raw = RawTemplate(
        source_ref="owner/name",
        templates=(ChatTemplate(None, "{{ unclosed "),),   # malformed -> ParseError
        bytes_fetched=100,
        total_size=100,
    )
    monkeypatch.setattr(scale_scan, "read_hf_source_template", lambda repo, *, revision: raw)
    rec = scale_scan.scan_repo("owner/name", "rev")
    assert rec["templates"][0] == {"template_name": None, "parse_error": True}


def test_get_json_reads_through_the_metadata_cap(monkeypatch):
    """The Hub listing read must go through _read_capped at the metadata
    cap, never an uncapped json.load that a hostile host could flood."""
    class _Resp:
        headers = {"Link": ""}
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    seen = {}

    def fake_capped(resp, limit):
        seen["limit"] = limit
        return b'{"ok": true}'

    monkeypatch.setattr(scale_scan.hf_source, "_build_request", lambda url: url)
    monkeypatch.setattr(scale_scan.hf_source, "_open_with_retry", lambda req: _Resp())
    monkeypatch.setattr(scale_scan.hf_source, "_read_capped", fake_capped)

    assert scale_scan._get_json("https://huggingface.co/api/models/x") == {"ok": True}
    assert seen["limit"] == scale_scan.hf_source._HF_SOURCE_MAX_BYTES


def test_done_repos_reads_checkpoint(tmp_path):
    path = tmp_path / "results.jsonl"
    path.write_text(
        json.dumps({"model": "a/b", "templates": []}) + "\n"
        + json.dumps({"model": "c/d", "templates": []}) + "\n"
        + "\n",                                   # tolerate blank lines
        encoding="utf-8",
    )
    assert scale_scan.done_repos(str(path)) == {"a/b", "c/d"}
    assert scale_scan.done_repos(str(tmp_path / "missing.jsonl")) == set()
