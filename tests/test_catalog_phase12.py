"""Offline tests for Phase 12 -- Catalog++ (CWE-mapped).

Fixture-driven: the new gadget / code-exec MARKER fixtures must flag
reachable, every catalog rule carries a CWE id surfaced in JSON + SARIF, and the real
benign corpus / fixtures stay clean (identifier-only matching, so a literal
"open" inside a benign tool-schema string is never flagged). The analyzer only parses +
walks the AST here; no template is rendered.
"""

from __future__ import annotations

import json
import os

import pytest
from jsonschema import Draft7Validator

from glyphhound.analyze import analyze_template
from glyphhound.analyze.models import (
    CODE_EXEC_NAMES,
    DANGEROUS_DUNDERS,
    RULE_CATALOG,
    cwe_for,
)
from glyphhound.report import Report, make_report, render_json, render_sarif

ROOT = os.path.dirname(os.path.dirname(__file__))
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
SARIF_SCHEMA_PATH = os.path.join(ROOT, "schemas", "sarif-2.1.0.json")

# The identifiers Phase 12 added to the catalog (must be exercised + must stay FP-clean).
NEW_DUNDERS = [
    "__getattribute__", "__call__", "__reduce__", "__reduce_ex__", "__getstate__",
    "__setstate__", "__code__", "__closure__", "__func__", "__self__",
    "__loader__", "__spec__", "__wrapped__",
]
NEW_NAMES = [
    "compile", "breakpoint", "open", "globals", "locals", "vars",
    "importlib", "builtins", "pty", "marshal", "pickle",
]
NEW_FIXTURES = [
    "reduce_dunder_marker.jinja", "func_internals_dunder_marker.jinja",
    "getattribute_call_dunder_marker.jinja", "import_machinery_dunder_marker.jinja",
    "namespace_builtins_marker.jinja", "dynamic_import_marker.jinja",
    "process_exec_marker.jinja",
]


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


# --- the new catalog members are present ---------------------------------------

def test_new_dunders_are_in_the_catalog():
    assert set(NEW_DUNDERS) <= DANGEROUS_DUNDERS


def test_new_names_are_in_the_catalog():
    assert set(NEW_NAMES) <= CODE_EXEC_NAMES


# --- each new dunder is a reachable GH-S001 (CWE-94) ----------------------------

@pytest.mark.parametrize("dunder", NEW_DUNDERS)
def test_new_dunder_flags_reachable_s001(dunder):
    # `base.__dunder__`: a dangerous-dunder access on a real base object is reachable.
    findings = analyze_template("{{ obj.%s }}" % dunder)
    reachable_s001 = [f for f in findings if f.rule_id == "GH-S001" and f.reachable]
    assert reachable_s001, \
        f"{dunder} should flag a reachable GH-S001; got {[(f.rule_id, f.reachable) for f in findings]}"
    assert all(cwe_for(f.rule_id) == "CWE-94" for f in reachable_s001)


# --- each new code-exec name is a reachable GH-S002 (CWE-94) when called --------

@pytest.mark.parametrize("name", NEW_NAMES)
def test_new_name_flags_reachable_s002_when_called(name):
    # Calling a bare code-exec name is reachable by Phase-3 taint.
    findings = analyze_template("{{ %s(payload) }}" % name)
    reachable_s002 = [f for f in findings if f.rule_id == "GH-S002" and f.reachable]
    assert reachable_s002, \
        f"{name}() should flag a reachable GH-S002; got {[(f.rule_id, f.reachable) for f in findings]}"
    assert all(cwe_for(f.rule_id) == "CWE-94" for f in reachable_s002)


# --- the family MARKER fixtures flag reachable + gate CI ------------------------

@pytest.mark.parametrize("fname", NEW_FIXTURES)
def test_family_fixture_flags_reachable_and_gates(fname):
    findings = analyze_template(_read(os.path.join(MALICIOUS_DIR, fname)))
    assert any(f.reachable for f in findings), f"{fname}: expected a reachable finding"
    assert make_report(findings).exit_code == 1, f"{fname}: should gate CI (exit 1)"


# --- CWE mapping is complete + correct -----------------------------------------

def test_every_rule_maps_to_a_known_cwe():
    for rid in RULE_CATALOG:
        assert cwe_for(rid) in {"CWE-94", "CWE-1336"}
    # the code-exec capability rules are code injection; the evasion pivots are SSTI.
    assert cwe_for("GH-S001") == "CWE-94"
    assert cwe_for("GH-S002") == "CWE-94"
    assert cwe_for("GH-S003") == "CWE-1336"
    assert cwe_for("GH-S004") == "CWE-1336"


# --- CWE surfaces in JSON (per finding) and the report still round-trips --------

def test_cwe_surfaces_in_json_and_round_trips():
    rep = make_report(analyze_template(_read(os.path.join(MALICIOUS_DIR, "reduce_dunder_marker.jinja"))))
    doc = json.loads(render_json(rep))
    assert doc["findings"], "expected findings"
    for fd in doc["findings"]:
        assert fd["cwe"] == cwe_for(fd["rule_id"])
    # cwe is derived, not a Finding field, so from_dict(to_dict(r)) still equals r.
    assert Report.from_dict(doc) == rep


# --- CWE surfaces in SARIF (rule + result) and it still validates ---------------

def test_cwe_surfaces_in_sarif_and_validates():
    rep = make_report(analyze_template(_read(os.path.join(MALICIOUS_DIR, "process_exec_marker.jinja"))))
    doc = json.loads(render_sarif(rep))
    schema = json.load(open(SARIF_SCHEMA_PATH, encoding="utf-8"))
    assert Draft7Validator(schema).is_valid(doc), "SARIF with CWE must still validate"
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        cwe = cwe_for(rule["id"])
        assert rule["properties"]["cwe"] == cwe
        number = cwe.split("-")[-1].zfill(3)
        assert f"external/cwe/cwe-{number}" in rule["properties"]["tags"]
    for res in doc["runs"][0]["results"]:
        assert res["properties"]["cwe"] == cwe_for(res["ruleId"])


# --- the new identifiers do NOT trip the real benign fixtures -------------------

@pytest.mark.parametrize("fname", _jinja_files(BENIGN_DIR))
def test_benign_fixtures_stay_clean_after_catalog_pp(fname):
    findings = analyze_template(_read(os.path.join(BENIGN_DIR, fname)))
    assert findings == [], \
        f"{fname} wrongly flagged after Catalog++: {[f.rule_id for f in findings]}"
