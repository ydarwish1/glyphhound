"""Phase 16 verification -- close the confirmed obfuscation bypasses.

Offline and deterministic: it analyzes on-disk fixtures and the vendored
benign corpus -- no network, no weights, and it never *renders* a template (only parses,
folds, and walks the AST), so reading the malicious fixtures cannot execute them. The fold is
a static AST rewrite over string literals; no string is ever evaluated.

Background: a live read-only CVE test (2026-06-22) confirmed GlyphHound gates every canonical
chain and every concat/format/slice/join/replace/{% set %}-const obfuscation, but TWO
evasions slipped past clean -- case-fold filters (``''['__CLASS__'|lower]``, the fold set
lacked the case/transform filters) and negative/reverse slices (``''['__ssalc__'[::-1]]``, a
``-1`` step is a ``Neg`` node, not a ``Const`` int). Phase 16 extends the constant-string fold
to a whitelist of pure string transforms and teaches the slice/index bound to unwrap a
``Neg(Const(int))`` -- so both fold to their constant value before the unchanged walk.

Checks (the bypass MARKER fixtures
(``''['__CLASS__'|lower]``, ``''['__ssalc__'[::-1]]``) now GATE; 120-corpus FP STILL 0/120):
  (a) The two Phase-16 MARKER fixtures yield ZERO findings WITHOUT the fold (raw walker) and a
      reachable GH-S001 + GH-S002 chain WITH the full pipeline -- and they gate CI.
  (b) The two reported minimal bypass forms now GATE, and the rest of the transform family
      (reverse-via-filter, swapcase, whitespace trim, chained transforms) folds the same way.
  (c) The permanent static ceiling is documented, not "fixed by rendering": a fully dynamic /
      runtime / loop-built name stays unflagged (the gated sandbox `--confirm` is the backstop).
  (d) the real benign corpus stays 0.00% (0/120, presence AND gating) and the 11
      benign fixtures clean, plus benign case-fold/reverse near-misses -- re-measured after the
      analyzer change. (The wider 241-template audit is verify_phase15's vendored result,
      re-measured 0/241 against this analyzer via `wider_fp_audit.py --rescan`.)

Run:  .venv/Scripts/python.exe scripts/verify_phase16.py
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
FIXTURES = ("casefold_filter_marker.jinja", "reverse_slice_marker.jinja")

# The two reported bypasses + the rest of the pure-transform family they generalize to.
BYPASS_FORMS = [
    "{{ ''['__CLASS__'|lower] }}",       # reported case-fold bypass
    "{{ ''['__ssalc__'[::-1]] }}",       # reported negative/reverse-slice bypass
    "{{ ''['__ssalc__'|reverse] }}",     # reverse via the filter
    "{{ ''['__CLASS__'|swapcase] }}",    # swapcase
    "{{ ''[' __class__ '|trim] }}",      # whitespace trim
    "{{ ''['__class__'|upper|lower] }}", # chained transforms fold bottom-up
]

# The PERMANENT static ceiling (never render to "resolve" these). DOCUMENTED, not
# fixed: the names are computed only at render, so static analysis cannot see them; the gated
# sandbox confirmer (`--confirm`) is the backstop.
DYNAMIC_LIMIT = [
    "{{ ''[messages[0].role] }}",
    "{% for ch in '__class__' %}{{ ''[ch] }}{% endfor %}",
]

# Benign case-fold / reverse near-misses that MUST stay clean.
BENIGN_PROBES = [
    "{{ 'Hello'|lower }}",
    "{{ message['role']|lower }}: {{ message['content'] }}",
    "{{ 'system'|upper }}",
    "{{ cfg['SYSTEM'|lower] }}",        # cfg['system'] on an untainted base (Phase 15)
    "{{ 'elor'[::-1] }}",
    "{{ name|trim }} {{ content|capitalize }}",
]


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


def _reachable_rules(findings) -> list[str]:
    return sorted({f.rule_id for f in findings if f.reachable})


def verify_fixtures() -> bool:
    print("=" * 78)
    print("Phase 16 (a) -- MARKER fixtures: 0 findings WITHOUT fold, reachable + gating WITH")
    print("=" * 78)
    ok = True
    for fname in FIXTURES:
        src = _read(os.path.join(MALICIOUS_DIR, fname))
        raw = analyze_ast(parse_template(src))      # raw walker, no fold
        full = analyze_template(src)                # full pipeline, with the Phase-16 fold
        report = make_report(full)
        reach = _reachable_rules(full)
        good = (raw == []) and ("GH-S001" in reach) and ("GH-S002" in reach) and report.exit_code == 1
        ok = ok and good
        print(f"  [{'OK' if good else 'FAIL'}] {fname:28s} raw={len(raw):>2}  "
              f"full={len(full):>2}  reachable={reach}  exit={report.exit_code}")
    print(f"[{'OK' if ok else 'FAIL'}] both bypass fixtures fold to a reachable, gating chain.")
    return ok


def verify_bypass_forms() -> bool:
    print("\n" + "=" * 78)
    print("Phase 16 (b) -- the reported bypasses + the transform family now GATE")
    print("=" * 78)
    ok = True
    for form in BYPASS_FORMS:
        findings = analyze_template(form)
        gates = make_report(findings).exit_code == 1
        good = gates and any(f.reachable and f.rule_id == "GH-S001" for f in findings)
        ok = ok and good
        print(f"  [{'OK' if good else 'FAIL'}] {form:42s} -> reachable GH-S001, gating={gates}")
    print(f"[{'OK' if ok else 'FAIL'}] every folded transform exposes a reachable dunder.")
    return ok


def verify_dynamic_limit() -> bool:
    print("\n" + "=" * 78)
    print("Phase 16 (c) -- fully dynamic / runtime names stay a DOCUMENTED limit (no render)")
    print("=" * 78)
    ok = True
    for form in DYNAMIC_LIMIT:
        reachable = any(f.reachable for f in analyze_template(form))
        good = not reachable  # the static ceiling -- the sandbox `--confirm` is the backstop
        ok = ok and good
        print(f"  [{'OK' if good else 'FAIL'}] {form[:54]:54s} -> reachable={reachable}")
    print(f"[{'OK' if ok else 'FAIL'}] dynamic names are not (and must not be) statically folded.")
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


def verify_no_false_positives() -> bool:
    print("\n" + "=" * 78)
    print("Phase 16 (d) -- corpus + benign fixtures + transform near-misses stay CLEAN")
    print("=" * 78)
    ok = True
    for probe in BENIGN_PROBES:
        findings = analyze_template(probe)
        clean = not findings
        ok = ok and clean
        print(f"  [{'OK' if clean else 'FAIL'}] {probe[:54]:54s} -> "
              f"{'clean' if clean else sorted({f.rule_id for f in findings})}")
    n_corpus, present_corpus, gating_corpus = _gating_fp(CORPUS_DIR)
    n_benign, present_benign, gating_benign = _gating_fp(BENIGN_DIR)
    rate = gating_corpus / n_corpus if n_corpus else 1.0
    print(f"corpus  : {n_corpus} templates -- presence {present_corpus}, gating {gating_corpus} ({rate:.2%} FP)")
    print(f"benign  : {n_benign} fixtures  -- presence {present_benign}, gating {gating_benign}")
    corpus_ok = (n_corpus >= 100 and gating_corpus == 0 and present_corpus == 0
                 and n_benign >= 10 and gating_benign == 0 and present_benign == 0)
    ok = ok and corpus_ok
    print(f"[{'OK' if ok else 'FAIL'}] corpus FP 0.00% gating AND 0 presence; near-misses clean.")
    return ok


def main() -> int:
    a_ok = verify_fixtures()
    b_ok = verify_bypass_forms()
    c_ok = verify_dynamic_limit()
    d_ok = verify_no_false_positives()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok and d_ok
    print(f"Phase 16: {'PASS' if ok else 'FAIL'} "
          f"(fixtures {'ok' if a_ok else 'FAIL'}, bypasses {'ok' if b_ok else 'FAIL'}, "
          f"dynamic-limit {'ok' if c_ok else 'FAIL'}, no-fp {'ok' if d_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
