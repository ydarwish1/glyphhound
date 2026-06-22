"""Phase 4 verification -- de-obfuscation pre-pass.

Offline and deterministic: it analyzes on-disk fixtures and the
vendored benign corpus -- no network, no weights, and it never *renders* a template (only
parses, folds, and walks the AST), so reading the malicious fixtures cannot execute them.
Folding is a static AST rewrite; no string is ever evaluated.

Checks (fold string-concat + getattr before
analysis; catches getattr(x,'__cl'+'ass__') that Phase 2/3 missed):
  (a) The NEW obfuscated MARKER fixture (a pure string-concat chain) yields ZERO findings
      WITHOUT folding, and a reachable GH-S001 (+ GH-S002) WITH folding.
  (b) getattr(x,'__cl'+'ass__') is upgraded from a GH-S004 reflection call to a reachable
      GH-S001 dunder finding (the dangerous reflection is REPLACED by the resolved access).
  (c) A benign string-concat ('rol'+'e') does NOT flag, and the real benign corpus stays at
      0 reachable findings AFTER folding (re-measured post-fold).

Run:  .venv/Scripts/python.exe scripts/verify_phase4.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.analyze import analyze_ast, analyze_template  # noqa: E402
from glyphhound.parse import parse_template  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")

# A role string built by concatenation: folds to 'role', a benign identifier -> no finding.
BENIGN_CONCAT = "{% set r = 'rol' + 'e' %}{{ r }}"
# The obfuscated reflection line Phase 2/3 could only see as GH-S004.
OBFUSCATED_GETATTR = "{{ getattr(x, '__cl' + 'ass__') }}"


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


def _reachable_rules(findings) -> list[str]:
    return sorted({f.rule_id for f in findings if f.reachable})


def verify_concat_fixture() -> bool:
    print("=" * 78)
    print("Phase 4 (a) -- obfuscated MARKER fixture: 0 findings WITHOUT folding, reachable WITH")
    print("=" * 78)
    fname = "deobfuscated_sink_marker.jinja"
    src = _read(os.path.join(MALICIOUS_DIR, fname))
    raw = analyze_ast(parse_template(src))            # raw walker, no de-obfuscation
    folded = analyze_template(src)                    # full pipeline, with de-obfuscation
    reach = _reachable_rules(folded)
    print(f"{fname}")
    print(f"  without de-obfuscation: {len(raw)} finding(s)  (string-matcher / Phase 2-3 blind spot)")
    print(f"  with de-obfuscation:    {len(folded)} finding(s), reachable rules: {reach}")
    ok = (raw == []) and ("GH-S001" in reach) and ("GH-S002" in reach)
    print(f"[{'OK' if ok else 'FAIL'}] folding turns a 0-finding chain into a reachable GH-S001+GH-S002.")
    return ok


def verify_getattr_upgrade() -> bool:
    print("\n" + "=" * 78)
    print("Phase 4 (b) -- obfuscated getattr upgraded GH-S004 reflection -> GH-S001 dunder")
    print("=" * 78)
    before = analyze_ast(parse_template(OBFUSCATED_GETATTR))   # raw walker
    after = analyze_template(OBFUSCATED_GETATTR)               # with folding
    before_rules = sorted({f.rule_id for f in before})
    after_rules = sorted({f.rule_id for f in after})
    print(f"source: {OBFUSCATED_GETATTR!r}")
    print(f"  before folding: {before_rules}  (reflection only -- dunder hidden in the Add)")
    print(f"  after  folding: {after_rules}  reachable: {_reachable_rules(after)}")
    # The resolved access REPLACES the reflection finding: GH-S001 reachable, no GH-S004.
    ok = (any(f.rule_id == "GH-S001" and f.reachable for f in after)
          and all(f.rule_id != "GH-S004" for f in after))
    print(f"[{'OK' if ok else 'FAIL'}] GH-S001 reachable and the redundant GH-S004 is replaced.")
    return ok


def verify_benign_unaffected() -> bool:
    print("\n" + "=" * 78)
    print("Phase 4 (c) -- benign concat clean + real corpus 0 reachable AFTER folding")
    print("=" * 78)
    concat_findings = analyze_template(BENIGN_CONCAT)
    concat_ok = concat_findings == []
    print(f"benign concat {BENIGN_CONCAT!r} -> {len(concat_findings)} finding(s)  "
          f"[{'OK' if concat_ok else 'FAIL'}]")

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
            print(f"[OK]   {fname:46s} 0 reachable ({len(findings)} total)")
    rate = flagged / len(files) if files else 1.0
    print(f"\nReachable false positives after folding: {flagged}/{len(files)} ({rate:.1%}).")
    return concat_ok and flagged == 0 and len(files) >= 10


def main() -> int:
    a_ok = verify_concat_fixture()
    b_ok = verify_getattr_upgrade()
    c_ok = verify_benign_unaffected()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok
    print(f"Phase 4: {'PASS' if ok else 'FAIL'} "
          f"(concat-fixture {'ok' if a_ok else 'FAIL'}, "
          f"getattr-upgrade {'ok' if b_ok else 'FAIL'}, "
          f"benign {'ok' if c_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
