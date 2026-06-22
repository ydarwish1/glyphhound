"""Phase 19 verification -- close the hidden string-building obfuscation bypasses.

Offline and deterministic (the project conventions): it analyzes on-disk fixtures and the vendored
benign corpus -- no network, no weights, and it never *renders* a template (only parses,
folds, and walks the AST), so reading the malicious fixtures cannot execute them. The fold is
a static AST rewrite over string literals; no string is ever evaluated.

Background: an adversarial bypass HUNT (2026-06-22) threw new obfuscation shapes at
analyze_template. Beyond the Phase-16 case-fold/reverse-slice folds, three *identifier-hiding*
builders slipped past clean -- and a string-matcher misses them too: string repetition
``'_' * 2`` (the ``Mul`` operator), printf via ``%`` and the ``|format`` filter, and the
``|string`` cast wrapped around a foldable expression to break the fold. Phase 19 extends the
one pure-constant-string evaluator to fold these, bounding ``Mul`` and printf widths against
``_MAX_FOLDED_LEN`` so a pathological repetition/width cannot allocate a giant transient.

Checks (the design docs row 19 / the project history Phase 19 tracker):
  (a) The three Phase-19 MARKER fixtures yield ZERO findings WITHOUT the fold (raw walker) and a
      reachable GH-S001 + GH-S002 chain WITH the full pipeline -- and they gate CI.
  (b) The reported minimal bypass forms (``*`` / ``%`` / ``|format`` / ``|string``) now GATE.
  (c) Documented gaps stay unflagged, NOT "fixed by rendering": (i) the permanent dynamic
      ceiling (runtime/loop-built names), and (ii) container indirection that leaves the
      identifier *literally visible* (``['__init__'][0]``, ``|first``, ``namespace(c=...).c``)
      -- a string-matcher already catches the visible literal, so it is out of the
      obfuscation-edge scope (recorded here as a known limitation, honest per Rule 3).
  (d) Rule 9: the real benign corpus stays 0.00% (0/120, presence AND gating) and the benign
      fixtures clean, plus Phase-19 near-misses (``'=' * 40`` separators, printf with
      variables, ``|string`` casts) -- re-measured after the analyzer change.

Run:  .venv/Scripts/python.exe scripts/verify_phase19.py
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
FIXTURES = ("mul_repeat_marker.jinja", "printf_marker.jinja", "string_cast_marker.jinja")

# The reported bypasses + the family they generalize to (all should GATE now).
BYPASS_FORMS = [
    "{{ cycler['_'*2 ~ 'init' ~ '_'*2] }}",          # string repetition (Mul), ~ join
    "{{ cycler['_'*2 + 'init' + '_'*2] }}",          # string repetition (Mul), + join
    "{{ cycler['%sinit%s' % ('__','__')] }}",        # printf via the % operator (tuple)
    "{{ cycler['__%s__' % 'init'] }}",               # printf via % (single arg)
    "{{ cycler['%sinit%s'|format('__','__')] }}",    # printf via the |format filter
    "{{ cycler|attr('%sinit%s'|format('__','__')) }}",  # |format inside |attr
    "{{ cycler[('__in'+'it__')|string] }}",          # |string cast around a folded concat
]

# Documented gaps that stay unflagged (Rule 4/6 -- never render to "resolve" them).
# (i) the PERMANENT dynamic ceiling (runtime/loop-built names; the gated --confirm sandbox is
#     the backstop).
# (ii) pure-const CONTAINER selection (list/tuple/dict index, |first, namespace.c) -- NOT yet
#     folded. Honest accounting (Rule 3): a BARE-literal container form (['__init__'][0]) leaves
#     the identifier visible to a string-matcher, but a SPLIT form (['__in'+'it__'][0]) still
#     hides it, so this is a genuine (if contrived) RESIDUAL BYPASS to fold in a later phase --
#     not a string-matcher-visible gap. Recorded here so it is tracked, not silently missed.
DOCUMENTED_GAPS = [
    "{{ ''[messages[0].role] }}",                        # dynamic name (permanent ceiling)
    "{% for ch in '__class__' %}{{ ''[ch] }}{% endfor %}",  # loop-built name (permanent ceiling)
    "{{ cycler[['__init__'][0]] }}",                     # container: list index (bare literal)
    "{{ cycler[('__init__',)[0]] }}",                    # container: tuple index (bare literal)
    "{{ cycler[{'k':'__init__'}['k']] }}",               # container: dict subscript (bare literal)
    "{{ cycler[['__init__']|first] }}",                  # container: |first (bare literal)
    "{{ cycler[['__in'+'it__'][0]] }}",                  # container + SPLIT -> hidden RESIDUAL bypass
    "{% set ns = namespace(c='__init__') %}{{ cycler[ns.c] }}",  # namespace attr
]

# Benign Phase-19 near-misses that MUST stay clean (Rule 9) -- common real-template uses of
# the newly-folded ops.
BENIGN_PROBES = [
    "{{ '=' * 40 }}",                       # separator line (folds to a long string, no sink)
    "{{ '-' * 3 }}{{ messages|length }}",
    "{{ '%s: %s' % (role, content) }}",     # printf with VARIABLES -> not folded
    "{{ 'Total: %d%%' % 100 }}",            # printf all-const -> 'Total: 100%' (not a sink)
    "{{ '%d'|format(count) }}",             # |format with a variable -> not folded
    "{{ name|string }} {{ content|string }}",
    "{{ messages|first }} {{ messages|last }}",
]


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


def _reachable_rules(findings) -> list[str]:
    return sorted({f.rule_id for f in findings if f.reachable})


def verify_fixtures() -> bool:
    print("=" * 78)
    print("Phase 19 (a) -- MARKER fixtures: 0 findings WITHOUT fold, reachable + gating WITH")
    print("=" * 78)
    ok = True
    for fname in FIXTURES:
        src = _read(os.path.join(MALICIOUS_DIR, fname))
        raw = analyze_ast(parse_template(src))      # raw walker, no fold
        full = analyze_template(src)                # full pipeline, with the Phase-19 fold
        report = make_report(full)
        reach = _reachable_rules(full)
        good = (raw == []) and ("GH-S001" in reach) and ("GH-S002" in reach) and report.exit_code == 1
        ok = ok and good
        print(f"  [{'OK' if good else 'FAIL'}] {fname:26s} raw={len(raw):>2}  "
              f"full={len(full):>2}  reachable={reach}  exit={report.exit_code}")
    print(f"[{'OK' if ok else 'FAIL'}] all three bypass fixtures fold to a reachable, gating chain.")
    return ok


def verify_bypass_forms() -> bool:
    print("\n" + "=" * 78)
    print("Phase 19 (b) -- the reported hidden bypasses now GATE")
    print("=" * 78)
    ok = True
    for form in BYPASS_FORMS:
        findings = analyze_template(form)
        gates = make_report(findings).exit_code == 1
        good = gates and any(f.reachable for f in findings)
        ok = ok and good
        print(f"  [{'OK' if good else 'FAIL'}] {form:50s} -> gating={gates}")
    print(f"[{'OK' if ok else 'FAIL'}] every folded string-builder exposes a reachable sink.")
    return ok


def verify_documented_gaps() -> bool:
    print("\n" + "=" * 78)
    print("Phase 19 (c) -- documented gaps stay unflagged (dynamic ceiling + literal-visible)")
    print("=" * 78)
    ok = True
    for form in DOCUMENTED_GAPS:
        reachable = any(f.reachable for f in analyze_template(form))
        good = not reachable
        ok = ok and good
        print(f"  [{'OK' if good else 'FAIL'}] {form[:58]:58s} -> reachable={reachable}")
    print(f"[{'OK' if ok else 'FAIL'}] dynamic + literal-visible forms are not statically folded "
          "(string-matchers catch the visible ones; documented, Rule 3).")
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
    print("Phase 19 (d) -- Rule 9: corpus + benign fixtures + Phase-19 near-misses stay CLEAN")
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
    print(f"[{'OK' if ok else 'FAIL'}] corpus FP 0.00% gating AND 0 presence; near-misses clean (Rule 9).")
    return ok


def main() -> int:
    a_ok = verify_fixtures()
    b_ok = verify_bypass_forms()
    c_ok = verify_documented_gaps()
    d_ok = verify_no_false_positives()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok and d_ok
    print(f"Phase 19: {'PASS' if ok else 'FAIL'} "
          f"(fixtures {'ok' if a_ok else 'FAIL'}, bypasses {'ok' if b_ok else 'FAIL'}, "
          f"documented-gaps {'ok' if c_ok else 'FAIL'}, no-fp {'ok' if d_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
