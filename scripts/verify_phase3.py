"""Phase 3 verification — taint / reachability.

Offline and deterministic (the project conventions): it analyzes on-disk fixtures and the
vendored benign corpus — no network, no weights, and it never *renders* a template
(only parses + walks the AST), so reading the malicious fixtures cannot execute them.

Checks (the design docs row 3 / the project history Phase 3 tracker — "flags a reachable-sink fixture;
does NOT flag a benign template that merely names a variable like `class`"):
  (a) The reachable-sink MARKER fixture is flagged with reachable=True (a dangerous
      chain that climbs a gadget base through dunders onto os.system).
  (b) The benign 'class'-named-variable negative has NO reachable findings.
  (c) The real benign corpus (>=10 templates) stays at 0 reachable findings (Rule 9).

Run:  .venv/Scripts/python.exe scripts/verify_phase3.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.analyze import analyze_template  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")

# The Phase-3 false-positive probe (Decision Log): a variable merely NAMED `class` is
# not a `__class__` access, so it builds toward nothing. Kept inline (mirrors the unit
# test) rather than as a benign corpus file, so the Rule-9 corpus stays the real set.
CLASS_NAMED_VARIABLE = "{% set class = 'x' %}{{ class }}"


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


def verify_reachable_fixture() -> bool:
    print("=" * 78)
    print("Phase 3 (a) — the reachable-sink MARKER fixture must be reachable=True")
    print("=" * 78)
    fname = "reachable_sink_marker.jinja"
    findings = analyze_template(_read(os.path.join(MALICIOUS_DIR, fname)))
    reachable = [f for f in findings if f.reachable]
    reachable_rules = sorted({f.rule_id for f in reachable})
    print(f"{fname}: {len(findings)} finding(s), {len(reachable)} reachable  "
          f"reachable rules: {reachable_rules}")
    # A reachable dunder pivot (GH-S001) AND the os.system code-exec name (GH-S002).
    ok = bool(reachable) and "GH-S001" in reachable_rules and "GH-S002" in reachable_rules
    print(f"[{'OK' if ok else 'FAIL'}] dangerous chain reaches a sink (GH-S001 + GH-S002).")
    return ok


def verify_class_named_variable() -> bool:
    print("\n" + "=" * 78)
    print("Phase 3 (b) — a variable merely named `class` must NOT be reachable")
    print("=" * 78)
    findings = analyze_template(CLASS_NAMED_VARIABLE)
    reachable = [f for f in findings if f.reachable]
    print(f"source: {CLASS_NAMED_VARIABLE!r}")
    print(f"  -> {len(findings)} finding(s), {len(reachable)} reachable")
    ok = not reachable
    print(f"[{'OK' if ok else 'FAIL'}] no reachable sink for a `class`-named variable.")
    return ok


def verify_benign_corpus_zero_reachable() -> bool:
    print("\n" + "=" * 78)
    print("Phase 3 (c) — real benign corpus must stay 0 reachable findings (Rule 9)")
    print("=" * 78)
    files = _jinja_files(BENIGN_DIR)
    flagged = 0
    for fname in files:
        findings = analyze_template(_read(os.path.join(BENIGN_DIR, fname)))
        reachable = [f for f in findings if f.reachable]
        if reachable:
            flagged += 1
            rules = ", ".join(sorted({f.rule_id for f in reachable}))
            print(f"[FAIL] {fname:46s} {len(reachable)} reachable: {rules}")
        else:
            print(f"[OK]   {fname:46s} 0 reachable")
    rate = flagged / len(files) if files else 1.0
    print(f"\nReachable false positives: {flagged}/{len(files)} benign templates ({rate:.1%}).")
    return flagged == 0 and len(files) >= 10


def main() -> int:
    a_ok = verify_reachable_fixture()
    b_ok = verify_class_named_variable()
    c_ok = verify_benign_corpus_zero_reachable()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok
    print(f"Phase 3: {'PASS' if ok else 'FAIL'} "
          f"(reachable-fixture {'ok' if a_ok else 'FAIL'}, "
          f"class-variable {'ok' if b_ok else 'FAIL'}, "
          f"benign-corpus {'ok' if c_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
