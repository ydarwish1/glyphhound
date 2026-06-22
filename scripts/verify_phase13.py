"""Phase 13 verification -- constant-propagation.

Offline and deterministic (the project conventions): it analyzes on-disk fixtures and the
vendored benign corpus -- no network, no weights, and it never *renders* a template (only
parses, propagates, folds, and walks the AST), so reading the malicious fixtures cannot
execute them. Propagation is a static AST rewrite; no string is ever evaluated.

Checks (the design docs G8 / the project history Phase 13 tracker -- "substitute {% set %} constant-string
vars before the fold; `{% set c='__class__' %}{{ obj[c] }}` flags reachable; corpus FP
still 0/120; Phase-1 golden byte-identical"):
  (a) The Phase-13 MARKER fixture yields ZERO findings WITHOUT propagation (raw walker) and
      a reachable GH-S001 chain WITH the full pipeline -- and it gates CI.
  (b) The two exposed forms work: a single variable-held dunder subscript, and propagate-
      THEN-fold of a concatenation (`'__re' + 'duce__'` -> `'__reduce__'`).
  (c) Conservative scoping introduces NO false positive: a benign const, a re-binding, a
      loop variable, a runtime-valued set, and a bare load all stay clean.
  (d) Rule 9: the real benign corpus stays 0.00% (0/120, presence AND gating), benign
      fixtures 0/11 -- re-measured after the analyzer change.

Run:  .venv/Scripts/python.exe scripts/verify_phase13.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.analyze import analyze_ast, analyze_template  # noqa: E402
from glyphhound.parse import parse_template  # noqa: E402
from glyphhound.report import make_report  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
CORPUS_DIR = os.path.join(ROOT, "corpus", "templates")
FIXTURE = os.path.join(MALICIOUS_DIR, "const_propagation_marker.jinja")

# Benign / conservative-scoping probes that MUST stay clean (mirror the unit tests).
BENIGN_PROBES = [
    "{% set role = 'system' %}{{ messages|selectattr('role','eq',role)|list }}",
    "{% set k = 'content' %}{{ m[k] }}",
    "{% set y = '__class__' %}{% set y = user %}{{ obj[y] }}",
    "{% if t %}{% set z = '__class__' %}{% else %}{% set z = 'role' %}{% endif %}{{ obj[z] }}",
    "{% for x in items %}{{ obj[x] }}{% endfor %}",
    "{% set c = item.key %}{{ x[c] }}",
    "{% set role = 'system' %}{{ role }}",
]


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


def _reachable_rules(findings) -> list[str]:
    return sorted({f.rule_id for f in findings if f.reachable})


def verify_fixture() -> bool:
    print("=" * 78)
    print("Phase 13 (a) -- MARKER fixture: 0 findings WITHOUT propagation, reachable + gating WITH")
    print("=" * 78)
    src = _read(FIXTURE)
    raw = analyze_ast(parse_template(src))          # raw walker, no normalize/propagation
    full = analyze_template(src)                    # full pipeline, with propagation + fold
    report = make_report(full)
    reach = _reachable_rules(full)
    print(f"  without propagation: {len(raw)} finding(s)  (variable-held dunder -- a blind spot)")
    print(f"  with propagation:    {len(full)} finding(s), reachable rules: {reach}, exit {report.exit_code}")
    print(f"  reachable keys: {sorted({f.evidence for f in full if f.reachable})}")
    ok = (raw == []) and ("GH-S001" in reach) and report.exit_code == 1
    print(f"[{'OK' if ok else 'FAIL'}] propagation turns a 0-finding template into a reachable, gating GH-S001.")
    return ok


def verify_exposed_forms() -> bool:
    print("\n" + "=" * 78)
    print("Phase 13 (b) -- single variable-held dunder, and propagate-THEN-fold of a concat")
    print("=" * 78)
    single = analyze_template("{% set c = '__class__' %}{{ obj[c] }}")
    single_ok = any(f.reachable and f.rule_id == "GH-S001" for f in single)
    print(f"  {{% set c='__class__' %}}{{{{ obj[c] }}}} -> reachable GH-S001: {single_ok}")
    concat = analyze_template("{% set a = '__re' %}{% set b = 'duce__' %}{{ obj[a + b] }}")
    concat_ok = any(f.reachable and "__reduce__" in f.evidence for f in concat)
    print(f"  {{% set a='__re' %}}{{% set b='duce__' %}}{{{{ obj[a+b] }}}} -> reachable '__reduce__': {concat_ok}")
    ok = single_ok and concat_ok
    print(f"[{'OK' if ok else 'FAIL'}] both variable-held and propagate-then-fold forms are caught.")
    return ok


def verify_no_false_positives() -> bool:
    print("\n" + "=" * 78)
    print("Phase 13 (c) -- conservative scoping: benign / re-bound / loop / runtime stay CLEAN")
    print("=" * 78)
    ok = True
    for probe in BENIGN_PROBES:
        findings = analyze_template(probe)
        clean = not findings
        ok = ok and clean
        print(f"  [{'OK' if clean else 'FAIL'}] {probe[:60]:60s} -> "
              f"{'clean' if clean else sorted({f.rule_id for f in findings})}")
    print(f"[{'OK' if ok else 'FAIL'}] propagation introduces no false positive on the probes.")
    return ok


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
    print("Phase 13 (d) -- Rule 9: corpus + benign fixtures FP-clean after propagation")
    print("=" * 78)
    n_corpus, present_corpus, gating_corpus = _gating_fp(CORPUS_DIR)
    n_benign, present_benign, gating_benign = _gating_fp(BENIGN_DIR)
    rate = gating_corpus / n_corpus if n_corpus else 1.0
    print(f"corpus  : {n_corpus} templates -- presence {present_corpus}, gating {gating_corpus} ({rate:.2%} FP)")
    print(f"benign  : {n_benign} fixtures  -- presence {present_benign}, gating {gating_benign}")
    ok = (n_corpus >= 100 and gating_corpus == 0 and present_corpus == 0
          and n_benign >= 10 and gating_benign == 0 and present_benign == 0)
    print(f"[{'OK' if ok else 'FAIL'}] corpus FP 0.00% gating AND 0 presence after propagation (Rule 9).")
    return ok


def main() -> int:
    a_ok = verify_fixture()
    b_ok = verify_exposed_forms()
    c_ok = verify_no_false_positives()
    d_ok = verify_corpus_clean()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok and d_ok
    print(f"Phase 13: {'PASS' if ok else 'FAIL'} "
          f"(fixture {'ok' if a_ok else 'FAIL'}, forms {'ok' if b_ok else 'FAIL'}, "
          f"no-fp {'ok' if c_ok else 'FAIL'}, corpus {'ok' if d_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
