"""Phase 10 verification — obfuscation coverage++ (the measured headline).

Phase 10 widens the de-obfuscator from constant `+`/`~` concatenation to the other constant
string builders — `str.format()`, slice/index, the `|join` and `|replace` filters — and resolves
a dunder name that hides in a keyword argument (`getattr(obj, name=...)`, `|attr(name=...)`).

Checks (the project history Phase 10 tracker):
  (a) Each new family's MARKER fixture folds to a REACHABLE GH-S001 (+GH-S002) chain; the four
      const-builder fixtures yield ZERO findings WITHOUT folding (the string-matcher blind spot),
      and the kwarg fixture is UPGRADED from a GH-S004 reflection call to the precise GH-S001.
  (b) The same builders over BENIGN content do not flag, and the 120-template corpus
      false-positive rate is STILL 0.00% after the analyzer change (Rule 9, re-measured).
  (c) The head-to-head benchmark's GlyphHound-only edge has WIDENED (slice / |join / |replace
      are caught by GlyphHound and missed by ModelAudit), and two runs are byte-identical
      (Rule 7). Deferred if the isolated `.venv-modelaudit` env is absent (like verify_phase8).

Run:  .venv/Scripts/python.exe scripts/verify_phase10.py
Exit code is non-zero if any non-deferred check fails.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, HERE)  # import the benchmark harness

from glyphhound.analyze import analyze_ast, analyze_template  # noqa: E402
from glyphhound.parse import parse_template  # noqa: E402
from glyphhound.report import make_report  # noqa: E402

MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
CORPUS_DIR = os.path.join(ROOT, "corpus", "templates")

CONST_BUILDER_FIXTURES = [
    "format_builder_marker.jinja",
    "slice_builder_marker.jinja",
    "join_builder_marker.jinja",
    "replace_builder_marker.jinja",
]
KWARG_FIXTURE = "kwarg_call_marker.jinja"

# The same constant builders over benign content must NOT flag (Rule 9).
BENIGN_NEAR_MISSES = [
    "{{ 'r{}e'.format('ol') }}",
    "{{ 'hello world'[:5] }}",
    "{{ ['a', 'b']|join('-') }}",
    "{{ 'a_b'|replace('_', ' ') }}",
    "{{ '{}'.format(user_name) }}",
]


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _reachable_rules(findings) -> set[str]:
    return {f.rule_id for f in findings if f.reachable}


def verify_family_fixtures() -> bool:
    print("=" * 78)
    print("Phase 10 (a) — each new obfuscation family folds to a reachable sink")
    print("=" * 78)
    ok = True
    for fname in CONST_BUILDER_FIXTURES:
        src = _read(os.path.join(MALICIOUS_DIR, fname))
        raw = analyze_ast(parse_template(src))            # no de-obfuscation
        folded = analyze_template(src)                    # with de-obfuscation
        reach = _reachable_rules(folded)
        passed = (raw == []) and {"GH-S001", "GH-S002"} <= reach
        ok = ok and passed
        print(f"[{'OK' if passed else 'FAIL'}]   {fname:32s} raw={len(raw)} finding(s) -> "
              f"folded reachable {sorted(reach)}")

    # The kwarg fixture: a reflection call (GH-S004) upgraded to the precise dunder (GH-S001).
    src = _read(os.path.join(MALICIOUS_DIR, KWARG_FIXTURE))
    before = {f.rule_id for f in analyze_ast(parse_template(src))}
    after = analyze_template(src)
    kwarg_ok = ("GH-S004" in before
                and any(f.rule_id == "GH-S001" and f.reachable for f in after)
                and all(f.rule_id != "GH-S004" for f in after))
    ok = ok and kwarg_ok
    print(f"[{'OK' if kwarg_ok else 'FAIL'}]   {KWARG_FIXTURE:32s} raw rules {sorted(before)} -> "
          f"folded reachable {sorted(_reachable_rules(after))} (GH-S004 replaced)")
    print(f"[{'OK' if ok else 'FAIL'}] every new family is reachable; const-builders invisible without folding.")
    return ok


def verify_benign_and_corpus() -> bool:
    print("\n" + "=" * 78)
    print("Phase 10 (b) — benign builders clean + corpus FP still 0.00% (Rule 9, re-measured)")
    print("=" * 78)
    near_ok = True
    for src in BENIGN_NEAR_MISSES:
        findings = analyze_template(src)
        clean = findings == []
        near_ok = near_ok and clean
        print(f"[{'OK' if clean else 'FAIL'}]   benign builder {src!r} -> {len(findings)} finding(s)")

    files = sorted(f for f in os.listdir(CORPUS_DIR) if f.endswith(".jinja"))
    gating = 0
    for fname in files:
        report = make_report(analyze_template(_read(os.path.join(CORPUS_DIR, fname))))
        if report.exit_code != 0:
            gating += 1
            print(f"[FAIL] corpus FP: {fname} gates CI ({report.summary.gating} gating)")
    rate = gating / len(files) if files else 1.0
    corpus_ok = gating == 0 and len(files) >= 100
    print(f"\nCorpus gating false positives: {gating}/{len(files)} ({rate:.2%}) "
          f"[{'OK' if corpus_ok else 'FAIL'}]")
    ok = near_ok and corpus_ok
    print(f"[{'OK' if ok else 'FAIL'}] benign builders stay clean; corpus FP unchanged at 0.00%.")
    return ok


def verify_benchmark_edge_widened() -> bool:
    print("\n" + "=" * 78)
    print("Phase 10 (c) — head-to-head edge widened (slice/|join/|replace), two runs identical")
    print("=" * 78)
    import run_benchmark as bench
    exe = bench.find_modelaudit()
    if exe is None:
        print("[DEFERRED] ModelAudit not installed (.venv-modelaudit absent).")
        print("           The de-obfuscator widening is fully verified offline by (a)+(b);")
        print("           the head-to-head numbers reproduce once the incumbent env exists")
        print("           (see scripts/verify_phase8.py / benchmark/README.md).")
        return True

    manifest = bench.load_manifest()
    rows = bench.run_benchmark(exe, manifest)
    rows2 = bench.run_benchmark(exe, manifest)
    version = bench.modelaudit_version(exe)
    deterministic = (bench.format_table(rows, modelaudit_version_str=version)
                     == bench.format_table(rows2, modelaudit_version_str=version))

    by_file = {r["entry"]["file"]: r for r in rows}
    new_edges = ["21_slice_concat_gated.jinja", "22_join_split_gated.jinja",
                 "23_replace_placeholder_gated.jinja"]
    new_edge_ok = all(
        by_file[f]["glyphhound"]["caught"] and not by_file[f]["modelaudit"]["caught"]
        for f in new_edges if f in by_file
    )
    summary = bench.summarize(rows)
    total_edges = len(summary["ma_misses_gh_catches"])
    print(bench.format_summary(summary))
    print()
    print(f"[{'OK' if new_edge_ok else 'FAIL'}]   slice / |join / |replace: GlyphHound catches, ModelAudit misses")
    print(f"[{'OK' if total_edges >= 6 else 'FAIL'}]   GlyphHound-only obfuscation edges: {total_edges} (was 3 pre-Phase-10)")
    print(f"[{'OK' if deterministic else 'FAIL'}]   two benchmark runs produce a byte-identical table (Rule 7)")
    ok = new_edge_ok and total_edges >= 6 and deterministic
    print(f"[{'OK' if ok else 'FAIL'}] the measured ModelAudit lead widened, honestly and deterministically.")
    return ok


def main() -> int:
    a_ok = verify_family_fixtures()
    b_ok = verify_benign_and_corpus()
    c_ok = verify_benchmark_edge_widened()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok
    print(f"Phase 10: {'PASS' if ok else 'FAIL'} "
          f"(families {'ok' if a_ok else 'FAIL'}, "
          f"benign+corpus {'ok' if b_ok else 'FAIL'}, "
          f"benchmark {'ok' if c_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
