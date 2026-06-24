"""Offline, deterministic tests for the Stage-5 reporter (Phase 5).

Fixture-driven: the malicious MARKER fixtures must produce a
report that gates CI (non-zero exit), and the real benign corpus must produce exit 0
(false positives measured on real templates). The reporter only *formats*
``Finding[]`` -- it never parses or renders a template, so nothing here can execute a
fixture. The few inputs analyzed here go through ``analyze_template`` (parse + walk the
AST only), exactly as the earlier phases do.

The four checks the reporter must satisfy are covered:
  (a) SARIF validates against the vendored official SARIF 2.1.0 schema + has results
      carrying ruleId / level / physicalLocation / message.
  (b) JSON round-trips (parse back to an equal Report) and carries the findings.
  (c) Human output renders and cites rule_id + source line + evidence (+ reachability).
  (d) Exit code is non-zero on a malicious fixture and zero on the benign corpus.
Plus determinism (same Finding[] -> identical bytes) and the exit-code policy.
"""

from __future__ import annotations

import json
import os

import pytest
from jsonschema import Draft7Validator

from glyphhound.analyze import analyze_template
from glyphhound.analyze.models import CRITICAL, HIGH, RULE_CATALOG, Finding
from glyphhound.report import (
    SARIF_SCHEMA_URI,
    SEVERITY_TO_SARIF_LEVEL,
    Report,
    make_report,
    render_human,
    render_json,
    render_sarif,
)
from glyphhound.scan import scan_template_string

ROOT = os.path.dirname(os.path.dirname(__file__))
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
SARIF_SCHEMA_PATH = os.path.join(ROOT, "schemas", "sarif-2.1.0.json")


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _corpus_files() -> list[str]:
    provenance = json.load(open(os.path.join(BENIGN_DIR, "PROVENANCE.json"), encoding="utf-8"))
    return [entry["file"] for entry in provenance]


def _malicious_findings(fname: str = "cve_2024_34359_marker.jinja") -> list[Finding]:
    return analyze_template(_read(os.path.join(MALICIOUS_DIR, fname)))


def _sarif_validator() -> Draft7Validator:
    schema = json.load(open(SARIF_SCHEMA_PATH, encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


# --- (a) SARIF validates against the official schema ----------------------------

@pytest.mark.parametrize("fname", [
    "cve_2024_34359_marker.jinja",
    "attr_filter_pivot_marker.jinja",
    "reachable_sink_marker.jinja",
    "deobfuscated_sink_marker.jinja",
])
def test_sarif_validates_against_official_schema(fname):
    report = make_report(_malicious_findings(fname))
    doc = json.loads(render_sarif(report))
    errors = sorted(_sarif_validator().iter_errors(doc), key=lambda e: list(e.path))
    assert errors == [], f"SARIF schema errors: {[(list(e.path), e.message) for e in errors]}"

    run = doc["runs"][0]
    results = run["results"]
    assert len(results) == len(report.findings) >= 1
    for res in results:
        assert res["ruleId"] in RULE_CATALOG
        assert res["level"] in {"error", "warning", "note", "none"}
        ploc = res["locations"][0]["physicalLocation"]
        assert ploc["artifactLocation"]["uri"]
        assert ploc["region"]["startLine"] >= 1
        assert res["message"]["text"]


def test_sarif_driver_rules_built_from_catalog():
    doc = json.loads(render_sarif(make_report(_malicious_findings())))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted(RULE_CATALOG)
    # ruleIndex on each result points at the matching driver rule.
    for res in doc["runs"][0]["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
    assert doc["$schema"] == SARIF_SCHEMA_URI
    assert doc["version"] == "2.1.0"


def test_sarif_level_mapping_critical_error_high_warning():
    assert SEVERITY_TO_SARIF_LEVEL[CRITICAL] == "error"
    assert SEVERITY_TO_SARIF_LEVEL[HIGH] == "warning"
    crit = Finding("GH-S001", CRITICAL, "dunder-attribute", None, 3, ".__class__",
                   "Getattr@line3", reachable=True)
    high = Finding("GH-S004", HIGH, "reflection-call", None, 4, "getattr",
                   "Name@line4", reachable=True)
    doc = json.loads(render_sarif(make_report([crit, high])))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["GH-S001"] == "error"
    assert levels["GH-S004"] == "warning"


# --- (b) JSON round-trips --------------------------------------------------------

def test_json_round_trips_to_equal_report():
    report = make_report(_malicious_findings())
    parsed = json.loads(render_json(report))
    assert parsed["exit_code"] == report.exit_code
    assert parsed["summary"]["total"] == len(report.findings)
    assert len(parsed["findings"]) == len(report.findings)
    rebuilt = Report.from_dict(parsed)
    assert rebuilt == report  # genuine round-trip: dict -> Report equals the original


def test_json_carries_expected_finding_fields():
    parsed = json.loads(render_json(make_report(_malicious_findings())))
    rule_ids = {f["rule_id"] for f in parsed["findings"]}
    assert {"GH-S001", "GH-S002"} <= rule_ids
    sample = parsed["findings"][0]
    for key in ("rule_id", "severity", "sink_kind", "template_name",
                "source_line", "evidence", "reachable", "confirmed"):
        assert key in sample
    # confirmed stays null (Phase 6 territory) -- the reporter must not invent it.
    assert all(f["confirmed"] is None for f in parsed["findings"])


# --- (c) Human output cites rule + line + evidence ------------------------------

def test_human_output_cites_rule_line_and_evidence():
    findings = _malicious_findings()
    text = render_human(make_report(findings))
    assert "GH-S001" in text
    assert "GH-S002" in text
    # the exact source line and evidence of a real finding appear verbatim
    f = findings[0]
    assert str(f.source_line) in text
    assert f.evidence in text
    assert "reachable" in text.lower()
    assert "exit" in text.lower()


def test_human_output_handles_no_findings():
    text = render_human(make_report([]))
    assert text.strip() != ""
    assert "0" in text  # reports zero findings without raising


# --- (d) exit codes: non-zero on malicious, zero on benign ----------------------

@pytest.mark.parametrize("fname", [
    "cve_2024_34359_marker.jinja",
    "attr_filter_pivot_marker.jinja",
    "reachable_sink_marker.jinja",
    "deobfuscated_sink_marker.jinja",
])
def test_exit_code_nonzero_on_malicious_fixture(fname):
    assert make_report(_malicious_findings(fname)).exit_code != 0
    assert scan_template_string(_read(os.path.join(MALICIOUS_DIR, fname))).exit_code != 0


def test_corpus_has_at_least_ten_templates():
    assert len(_corpus_files()) >= 10


@pytest.mark.parametrize("fname", _corpus_files())
def test_exit_code_zero_on_real_benign_template(fname):
    report = scan_template_string(_read(os.path.join(BENIGN_DIR, fname)))
    assert report.exit_code == 0, f"benign {fname} wrongly gated: {report.summary}"
    assert all(f.reachable is not True for f in report.findings)


# --- exit-code policy: reachable-only, configurable threshold -------------------

def test_presence_only_findings_do_not_gate():
    # A critical sink that is NOT reachable (e.g. a variable merely named `system`)
    # is reported but must not fail CI -- that is the whole point of reachability.
    presence = Finding("GH-S002", CRITICAL, "code-exec-name", None, 1, "system",
                       "Name@line1", reachable=False)
    assert make_report([presence]).exit_code == 0
    # reachable=None means "not analyzed" and likewise must not gate.
    unanalyzed = Finding("GH-S002", CRITICAL, "code-exec-name", None, 1, "system",
                         "Name@line1", reachable=None)
    assert make_report([unanalyzed]).exit_code == 0


def test_severity_threshold_is_configurable():
    reachable_high = Finding("GH-S004", HIGH, "reflection-call", None, 2, "getattr",
                             "Name@line2", reachable=True)
    assert make_report([reachable_high], severity_threshold=HIGH).exit_code == 1
    assert make_report([reachable_high], severity_threshold=CRITICAL).exit_code == 0
    reachable_crit = Finding("GH-S001", CRITICAL, "dunder-attribute", None, 2, ".__class__",
                             "Getattr@line2", reachable=True)
    assert make_report([reachable_crit], severity_threshold=CRITICAL).exit_code == 1


def test_summary_counts_match_findings():
    report = make_report(_malicious_findings())  # cve fixture: 5 critical, all reachable
    assert report.summary.total == 5
    assert report.summary.critical == 5
    assert report.summary.high == 0
    assert report.summary.reachable == 5
    assert report.summary.gating == 5
    assert report.summary.severity_threshold == HIGH


# --- determinism: same Finding[] -> identical bytes ---------------------

def test_reports_are_byte_identical_across_runs():
    f1 = analyze_template(_read(os.path.join(MALICIOUS_DIR, "cve_2024_34359_marker.jinja")))
    f2 = analyze_template(_read(os.path.join(MALICIOUS_DIR, "cve_2024_34359_marker.jinja")))
    for render in (render_human, render_json, render_sarif):
        assert render(make_report(f1)) == render(make_report(f2))


# --- safety boundary: the reporter formats Finding[] only -----------------------

def test_reporter_formats_findings_without_any_template_text():
    # Hand-built findings with NO template string in sight -- the reporter must produce
    # all three formats from Finding[] alone (it never renders/executes a template).
    findings = [
        Finding("GH-S001", CRITICAL, "dunder-attribute", "tool_use", 9, ".__globals__",
                "Getattr@line9", reachable=True),
        Finding("GH-S003", HIGH, "attr-filter", None, 2, "|attr(...)",
                "Filter@line2", reachable=False),
    ]
    report = make_report(findings)
    render_human(report)
    json.loads(render_json(report))
    doc = json.loads(render_sarif(report))
    assert Draft7Validator(json.load(open(SARIF_SCHEMA_PATH, encoding="utf-8"))).is_valid(doc)
    # the named template is attributed in the SARIF artifact location
    uris = {res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for res in doc["runs"][0]["results"]}
    assert "tokenizer.chat_template.tool_use" in uris
    assert "tokenizer.chat_template" in uris
