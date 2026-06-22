"""Phase 12 verification -- Catalog++ (CWE-mapped).

Offline and deterministic: it analyzes on-disk fixtures and the
vendored benign corpus -- no network, no weights, and it never *renders* a template
(only parses + walks the AST), so reading the malicious fixtures cannot execute them.

Checks:
  (a) Every Phase-12 family MARKER fixture flags a reachable finding and gates CI.
  (b) Catalog coverage: each newly added dunder is a reachable GH-S001, and each newly
      added code-exec name is a reachable GH-S002 when called.
  (c) CWE is surfaced: every rule maps to CWE-94/CWE-1336; JSON carries a per-finding cwe
      and still round-trips; SARIF carries cwe on each rule (+ a GitHub `tags` entry) and
      each result, and still validates against the vendored official SARIF 2.1.0 schema.
  (d) the expanded catalog keeps the real benign corpus at 0.00% (0/120) gating
      false positives (re-measured), and the 11 benign fixtures clean at presence level.

Run:  .venv/Scripts/python.exe scripts/verify_phase12.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from jsonschema import Draft7Validator  # noqa: E402

from glyphhound.analyze import analyze_template  # noqa: E402
from glyphhound.analyze.models import (  # noqa: E402
    CODE_EXEC_NAMES,
    DANGEROUS_DUNDERS,
    RULE_CATALOG,
    cwe_for,
)
from glyphhound.report import Report, make_report, render_json, render_sarif  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
CORPUS_DIR = os.path.join(ROOT, "corpus", "templates")
SARIF_SCHEMA_PATH = os.path.join(ROOT, "schemas", "sarif-2.1.0.json")

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


def verify_family_fixtures() -> bool:
    print("=" * 78)
    print("Phase 12 (a) -- each new family MARKER fixture flags reachable + gates CI")
    print("=" * 78)
    all_ok = True
    for fname in NEW_FIXTURES:
        findings = analyze_template(_read(os.path.join(MALICIOUS_DIR, fname)))
        reachable = [f for f in findings if f.reachable]
        report = make_report(findings)
        ok = bool(reachable) and report.exit_code == 1
        all_ok = all_ok and ok
        rules = ", ".join(sorted({f.rule_id for f in findings}))
        print(f"[{'OK' if ok else 'FAIL'}] {fname:42s} {len(findings)} finding(s), "
              f"{len(reachable)} reachable, exit {report.exit_code}  rules: {rules}")
    return all_ok


def verify_catalog_coverage() -> bool:
    print("\n" + "=" * 78)
    print("Phase 12 (b) -- each new dunder -> reachable GH-S001; each new name -> GH-S002")
    print("=" * 78)
    ok = True
    missing_dunders = [d for d in NEW_DUNDERS if d not in DANGEROUS_DUNDERS]
    missing_names = [n for n in NEW_NAMES if n not in CODE_EXEC_NAMES]
    if missing_dunders or missing_names:
        ok = False
        print(f"[FAIL] not in catalog -- dunders: {missing_dunders}  names: {missing_names}")
    for dunder in NEW_DUNDERS:
        findings = analyze_template("{{ obj.%s }}" % dunder)
        hit = any(f.rule_id == "GH-S001" and f.reachable for f in findings)
        ok = ok and hit
        if not hit:
            print(f"[FAIL] dunder {dunder} did not flag a reachable GH-S001")
    for name in NEW_NAMES:
        findings = analyze_template("{{ %s(payload) }}" % name)
        hit = any(f.rule_id == "GH-S002" and f.reachable for f in findings)
        ok = ok and hit
        if not hit:
            print(f"[FAIL] name {name}() did not flag a reachable GH-S002")
    print(f"[{'OK' if ok else 'FAIL'}] {len(NEW_DUNDERS)} new dunders flag reachable GH-S001; "
          f"{len(NEW_NAMES)} new names flag reachable GH-S002.")
    return ok


def verify_cwe_surfaced() -> bool:
    print("\n" + "=" * 78)
    print("Phase 12 (c) -- CWE id surfaced + correct in the catalog, JSON, and SARIF")
    print("=" * 78)
    ok = True
    for rid in sorted(RULE_CATALOG):
        cwe = cwe_for(rid)
        good = cwe in {"CWE-94", "CWE-1336"}
        ok = ok and good
        print(f"  {rid}: {cwe}  [{'OK' if good else 'FAIL'}]")

    # JSON: per-finding cwe + round-trip.
    rep = make_report(analyze_template(_read(os.path.join(MALICIOUS_DIR, "reduce_dunder_marker.jinja"))))
    doc = json.loads(render_json(rep))
    json_ok = bool(doc["findings"]) and all(fd["cwe"] == cwe_for(fd["rule_id"]) for fd in doc["findings"]) \
        and Report.from_dict(doc) == rep
    print(f"[{'OK' if json_ok else 'FAIL'}] JSON carries per-finding cwe and still round-trips to an equal Report.")

    # SARIF: rule.properties.cwe + tags, result.properties.cwe, schema-valid.
    rep2 = make_report(analyze_template(_read(os.path.join(MALICIOUS_DIR, "process_exec_marker.jinja"))))
    sdoc = json.loads(render_sarif(rep2))
    schema = json.load(open(SARIF_SCHEMA_PATH, encoding="utf-8"))
    valid = Draft7Validator(schema).is_valid(sdoc)
    rule_ok = True
    for rule in sdoc["runs"][0]["tool"]["driver"]["rules"]:
        cwe = cwe_for(rule["id"])
        tag = f"external/cwe/cwe-{cwe.split('-')[-1].zfill(3)}"
        rule_ok = rule_ok and rule["properties"]["cwe"] == cwe and tag in rule["properties"]["tags"]
    result_ok = all(res["properties"]["cwe"] == cwe_for(res["ruleId"]) for res in sdoc["runs"][0]["results"])
    sarif_ok = valid and rule_ok and result_ok
    print(f"[{'OK' if sarif_ok else 'FAIL'}] SARIF carries cwe on rules (+ GitHub tag) and results, "
          f"and validates against the vendored schema (valid={valid}).")
    return ok and json_ok and sarif_ok


def _gating_fp(directory: str) -> tuple[int, int, int]:
    files = _jinja_files(directory)
    gating = present = 0
    for fname in files:
        findings = analyze_template(_read(os.path.join(directory, fname)))
        if findings:
            present += 1
        if any(f.reachable for f in findings):
            gating += 1
    return len(files), present, gating


def verify_corpus_clean() -> bool:
    print("\n" + "=" * 78)
    print("Phase 12 (d) -- expanded catalog keeps the corpus + fixtures FP-clean")
    print("=" * 78)
    n_corpus, present_corpus, gating_corpus = _gating_fp(CORPUS_DIR)
    n_benign, present_benign, gating_benign = _gating_fp(BENIGN_DIR)
    rate = gating_corpus / n_corpus if n_corpus else 1.0
    print(f"corpus  : {n_corpus} templates -- presence {present_corpus}, gating {gating_corpus} "
          f"({rate:.2%} FP)")
    print(f"benign  : {n_benign} fixtures  -- presence {present_benign}, gating {gating_benign}")
    ok = (n_corpus >= 100 and gating_corpus == 0 and present_corpus == 0
          and n_benign >= 10 and gating_benign == 0 and present_benign == 0)
    print(f"[{'OK' if ok else 'FAIL'}] corpus FP 0.00% gating AND 0 presence (identifier-only "
          f"keeps literal sink words in benign strings clean).")
    return ok


def main() -> int:
    a_ok = verify_family_fixtures()
    b_ok = verify_catalog_coverage()
    c_ok = verify_cwe_surfaced()
    d_ok = verify_corpus_clean()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok and d_ok
    print(f"Phase 12: {'PASS' if ok else 'FAIL'} "
          f"(fixtures {'ok' if a_ok else 'FAIL'}, coverage {'ok' if b_ok else 'FAIL'}, "
          f"cwe {'ok' if c_ok else 'FAIL'}, corpus {'ok' if d_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
