"""Phase 5 verification -- Stage-5 reporter (human / JSON / SARIF 2.1.0 + CI exit codes).

Offline and deterministic: it analyzes on-disk fixtures and the
vendored benign corpus, validates SARIF against the vendored official SARIF 2.1.0 schema
(no network), and never *renders* a template (it only parses + walks the AST, then formats
the resulting Finding[]) -- so reading the malicious fixtures cannot execute them.

Checks (human/JSON/SARIF 2.1.0 + CI exit
codes; SARIF validates against the official schema; exit != 0 on malicious, = 0 on benign):
  (a) SARIF for each malicious fixture VALIDATES against the official SARIF 2.1.0 schema and
      carries results with ruleId / level / physicalLocation / message.
  (b) JSON for a malicious fixture ROUND-TRIPS (parse back to an equal Report) and carries findings.
  (c) HUMAN output renders without error and cites rule_id + source line + evidence.
  (d) EXIT CODE is non-zero on each malicious fixture (in-process AND via the real CLI
      process) and zero on every benign corpus template (0/11).

Run:  .venv/Scripts/python.exe scripts/verify_phase5.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from jsonschema import Draft7Validator  # noqa: E402

from glyphhound.analyze import RULE_CATALOG, analyze_template  # noqa: E402
from glyphhound.report import (  # noqa: E402
    Report,
    make_report,
    render_human,
    render_json,
    render_sarif,
)

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
SCHEMA_PATH = os.path.join(ROOT, "schemas", "sarif-2.1.0.json")

# The fixture the round-trip / human checks read in detail.
PRIMARY = "cve_2024_34359_marker.jinja"


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


def _validator() -> Draft7Validator:
    schema = json.load(open(SCHEMA_PATH, encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def _report_for(fname: str) -> Report:
    return make_report(analyze_template(_read(os.path.join(MALICIOUS_DIR, fname))))


def verify_sarif_schema_valid() -> bool:
    print("=" * 78)
    print("Phase 5 (a) -- SARIF validates against the official SARIF 2.1.0 schema")
    print("=" * 78)
    validator = _validator()
    ok = True
    for fname in _jinja_files(MALICIOUS_DIR):
        doc = json.loads(render_sarif(_report_for(fname)))
        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
        results = doc["runs"][0]["results"]
        fields_ok = bool(results) and all(
            r["ruleId"] in RULE_CATALOG
            and r["level"] in {"error", "warning", "note", "none"}
            and r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            and r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
            and r["message"]["text"]
            for r in results
        )
        passed = not errors and fields_ok
        ok = ok and passed
        status = "OK" if passed else "FAIL"
        detail = "schema-valid" if not errors else f"{len(errors)} schema error(s)"
        print(f"[{status}]   {fname:34s} {len(results)} result(s), {detail}, "
              f"fields {'present' if fields_ok else 'MISSING'}")
        if errors:
            for e in errors[:3]:
                print(f"         - {list(e.path)}: {e.message}")
    print(f"[{'OK' if ok else 'FAIL'}] all malicious fixtures emit schema-valid SARIF with required fields.")
    return ok


def verify_json_round_trip() -> bool:
    print("\n" + "=" * 78)
    print("Phase 5 (b) -- JSON round-trips (parse back to an equal Report) + carries findings")
    print("=" * 78)
    report = _report_for(PRIMARY)
    text = render_json(report)
    parsed = json.loads(text)
    rebuilt = Report.from_dict(parsed)
    rule_ids = {f["rule_id"] for f in parsed["findings"]}
    round_trips = rebuilt == report
    has_findings = len(parsed["findings"]) == len(report.findings) >= 1
    expected_rules = {"GH-S001", "GH-S002"} <= rule_ids
    print(f"{PRIMARY}: {len(parsed['findings'])} finding(s) in JSON; rules {sorted(rule_ids)}")
    print(f"  round-trips to an equal Report: {round_trips}")
    print(f"  expected GH-S001+GH-S002 present: {expected_rules}; exit_code in JSON: {parsed['exit_code']}")
    ok = round_trips and has_findings and expected_rules
    print(f"[{'OK' if ok else 'FAIL'}] JSON is round-trippable and carries the expected findings.")
    return ok


def verify_human_output() -> bool:
    print("\n" + "=" * 78)
    print("Phase 5 (c) -- human output renders and cites rule_id + source line + evidence")
    print("=" * 78)
    findings = analyze_template(_read(os.path.join(MALICIOUS_DIR, PRIMARY)))
    text = render_human(make_report(findings))
    f = findings[0]
    cites_rule = "GH-S001" in text and "GH-S002" in text
    cites_line = str(f.source_line) in text
    cites_evidence = f.evidence in text
    cites_reach = "reachable" in text.lower()
    cites_exit = "exit" in text.lower()
    print(f"{PRIMARY}: human report is {len(text)} chars")
    print(f"  cites rule ids: {cites_rule}; source line {f.source_line}: {cites_line}; "
          f"evidence {f.evidence!r}: {cites_evidence}")
    print(f"  notes reachability: {cites_reach}; states exit code: {cites_exit}")
    ok = cites_rule and cites_line and cites_evidence and cites_reach and cites_exit
    print(f"[{'OK' if ok else 'FAIL'}] human output renders and cites rule + line + evidence.")
    return ok


def _cli_exit_code(path: str) -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "glyphhound", "scan", path, "--format", "json"],
        cwd=ROOT, capture_output=True,
    )
    return proc.returncode


def verify_exit_codes() -> bool:
    print("\n" + "=" * 78)
    print("Phase 5 (d) -- exit != 0 on malicious (in-process + real CLI), = 0 on benign")
    print("=" * 78)
    mal_ok = True
    for fname in _jinja_files(MALICIOUS_DIR):
        path = os.path.join(MALICIOUS_DIR, fname)
        in_proc = _report_for(fname).exit_code
        cli = _cli_exit_code(path)
        passed = in_proc != 0 and cli != 0
        mal_ok = mal_ok and passed
        print(f"[{'OK' if passed else 'FAIL'}]   {fname:34s} in-process exit={in_proc}, CLI exit={cli}")

    print("-" * 78)
    files = _jinja_files(BENIGN_DIR)
    flagged = 0
    for fname in files:
        path = os.path.join(BENIGN_DIR, fname)
        report = make_report(analyze_template(_read(path)))
        if report.exit_code != 0:
            flagged += 1
            print(f"[FAIL] {fname:46s} exit={report.exit_code} ({report.summary.gating} gating)")
        else:
            print(f"[OK]   {fname:46s} exit=0 ({report.summary.total} finding(s), 0 gating)")
    # Spot-check one benign template through the real CLI process too.
    benign_cli = _cli_exit_code(os.path.join(BENIGN_DIR, files[0])) if files else 1
    rate = flagged / len(files) if files else 1.0
    print(f"\nBenign false positives (gating): {flagged}/{len(files)} ({rate:.1%}); "
          f"real CLI exit on {files[0] if files else '-'}: {benign_cli}")
    benign_ok = flagged == 0 and len(files) >= 10 and benign_cli == 0
    ok = mal_ok and benign_ok
    print(f"[{'OK' if ok else 'FAIL'}] malicious gate CI; benign corpus is clean (0/{len(files)}).")
    return ok


def main() -> int:
    a_ok = verify_sarif_schema_valid()
    b_ok = verify_json_round_trip()
    c_ok = verify_human_output()
    d_ok = verify_exit_codes()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok and d_ok
    print(f"Phase 5: {'PASS' if ok else 'FAIL'} "
          f"(sarif {'ok' if a_ok else 'FAIL'}, "
          f"json {'ok' if b_ok else 'FAIL'}, "
          f"human {'ok' if c_ok else 'FAIL'}, "
          f"exit-codes {'ok' if d_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
