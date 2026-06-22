"""Offline tests for Phase 17 step 3 — the prevalence aggregator (scripts/prevalence_report.py).

Pure aggregation over synthetic scale-scan records; no network. Confirms the rate denominator
is parseable chat templates, that unparseable templates are counted as a coverage gap (not a
finding), and that obfuscated capable templates are a subset of capable ones.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import prevalence_report  # noqa: E402

_RECORDS = [
    {"model": "a/benign", "revision": "r1", "templates": [
        {"template_name": None, "template_sha256": "h1", "gates_ci": False,
         "obfuscated": False, "n_findings": 0, "n_reachable": 0, "reachable_rule_ids": []},
    ]},
    {"model": "b/plain", "revision": "r2", "templates": [
        {"template_name": None, "template_sha256": "h2", "gates_ci": True,
         "obfuscated": False, "n_findings": 5, "n_reachable": 2,
         "reachable_rule_ids": ["GH-S001"]},
    ]},
    {"model": "c/obf", "revision": "r3", "templates": [
        {"template_name": "tool_use", "template_sha256": "h3", "gates_ci": True,
         "obfuscated": True, "n_findings": 3, "n_reachable": 1,
         "reachable_rule_ids": ["GH-S001"]},
        {"template_name": "broken", "parse_error": True},
    ]},
]


def test_aggregate_counts():
    s = prevalence_report.aggregate(_RECORDS)
    assert s["models_recorded"] == 3
    assert s["templates_scanned"] == 4          # 3 parseable + 1 parse_error
    assert s["templates_parseable"] == 3
    assert s["templates_unparseable"] == 1
    assert s["distinct_templates"] == 3
    assert s["code_exec_capable_templates"] == 2
    assert s["obfuscated_capable_templates"] == 1     # subset of capable
    assert s["models_with_capable_template"] == 2
    assert s["gating_rate"] == round(2 / 3, 6)
    assert s["capable_by_reachable_rule"] == {"GH-S001": 2}


def test_aggregate_all_benign_is_zero_rate():
    s = prevalence_report.aggregate([_RECORDS[0]])
    assert s["code_exec_capable_templates"] == 0
    assert s["gating_rate"] == 0.0
    assert s["obfuscated_rate"] == 0.0


def test_csv_rows_flatten_lists_and_omit_raw_text(tmp_path):
    out = tmp_path / "prevalence.csv"
    n = prevalence_report.write_csv(_RECORDS, str(out))
    assert n == 4
    body = out.read_text(encoding="utf-8")
    assert "GH-S001" in body            # list fields flattened to space-joined strings
    assert body.startswith(",".join(prevalence_report.CSV_FIELDS))
