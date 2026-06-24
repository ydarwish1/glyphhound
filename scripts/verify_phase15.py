"""Phase 15 verification -- detection hardening (catalog audit + wider FP audit + benchmark).

Offline and deterministic: it analyzes on-disk fixtures, the vendored
benign corpus, the vendored wider-FP-audit result, and the benchmark payloads -- no network,
no weights, and it never *renders* a template (only parses + walks the AST). The network-only
audit BUILD step lives separately in ``scripts/wider_fp_audit.py`` (same build-vs-verify split
as ``build_fp_corpus.py`` / ``verify_phase7.py``).

Checks:
  (a) CATALOG DECISION: the candidate gadget dunders investigated this phase
      (__format__ / __getitem__ / __dir__) were NOT added -- they enable no reachable chain
      the existing 23-dunder catalog misses (their standalone form is not a real first-climb
      gadget), and every realistic exploit chain that uses them STILL gates via a cataloged
      dunder. Asserts: each candidate is absent from the catalog AND a realistic chain using
      it is still reachable AND its standalone form is not reachable (no coverage lost, no FP
      surface added).
  (b) WIDER FP AUDIT: the vendored ``study/wider_fp_audit.json`` audited a sample WIDER than
      the 120-corpus (distinct NEW templates not in the corpus) and measured 0 gating FP, with
      the Phase-12 common names (open/globals/locals/vars) never the cause of a gating FP.
  (c) the (unchanged) catalog keeps the real benign corpus at 0.00% (0/120) gating AND
      0 presence, and the 11 benign fixtures clean -- re-measured here.
  (d) BENCHMARK (GlyphHound side, offline): every malicious benchmark payload still gates and
      every benign control stays clean under the current analyzer (the full GH-vs-ModelAudit
      table + determinism is verify_phase8's job; it needs the separate .venv-modelaudit).

Run:  .venv/Scripts/python.exe scripts/verify_phase15.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.analyze import analyze_template  # noqa: E402
from glyphhound.analyze.models import DANGEROUS_DUNDERS  # noqa: E402
from glyphhound.parse import ParseError  # noqa: E402
from glyphhound.report import make_report  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
CORPUS_DIR = os.path.join(ROOT, "corpus", "templates")
AUDIT_PATH = os.path.join(ROOT, "study", "wider_fp_audit.json")
BENCH_DIR = os.path.join(ROOT, "benchmark", "payloads")
BENCH_MANIFEST = os.path.join(BENCH_DIR, "MANIFEST.json")

# Investigated this phase; NOT added (see check (a)). Each maps a
# realistic chain that USES the candidate (still caught via a cataloged dunder) to its
# standalone form (not a real first-climb gadget -> not reachable -> nothing to gain by adding).
CANDIDATE_DUNDERS = {
    "__getitem__": (
        "{{ cycler.__init__.__globals__.__getitem__('os').system('MARKER') }}",  # caught
        "{{ cycler.__getitem__('__globals__') }}",                               # not a gadget
    ),
    "__format__": (
        "{{ obj.__class__.__format__ }}",   # caught via __class__
        "{{ obj.__format__('') }}",         # returns a str; not exec
    ),
    "__dir__": (
        "{{ obj.__class__.__dir__() }}",    # caught via __class__
        "{{ obj.__dir__() }}",              # introspection; not exec
    ),
}

# The audited set must be genuinely WIDER than the 120-corpus: at least this many distinct
# templates the corpus never contained (combined, that more than doubles the evaluated benign
# set). The audit script targets 250.
WIDER_MIN = 120
AUDIT_NAMES = ("open", "globals", "locals", "vars")


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


def _reachable(tpl: str) -> bool:
    return any(f.reachable is True for f in analyze_template(tpl))


def verify_catalog_decision() -> bool:
    print("=" * 78)
    print("Phase 15 (a) -- candidate dunders investigated; NOT added (no reachable chain")
    print("              missed; standalone forms are not real first-climb gadgets)")
    print("=" * 78)
    ok = True
    for dunder, (realistic, standalone) in CANDIDATE_DUNDERS.items():
        absent = dunder not in DANGEROUS_DUNDERS
        caught = _reachable(realistic)            # real chain using it still gates
        standalone_inert = not _reachable(standalone)  # alone it adds nothing
        good = absent and caught and standalone_inert
        ok = ok and good
        print(f"[{'OK' if good else 'FAIL'}] {dunder:14s} absent={absent}  "
              f"realistic-chain-reachable={caught}  standalone-reachable={not standalone_inert}")
    print(f"[{'OK' if ok else 'FAIL'}] no detection lost by not cataloging the candidates; "
          f"no FP surface added.")
    return ok


def verify_wider_audit() -> bool:
    print("\n" + "=" * 78)
    print("Phase 15 (b) -- wider-corpus FP audit (vendored study/wider_fp_audit.json)")
    print("=" * 78)
    if not os.path.exists(AUDIT_PATH):
        print(f"[FAIL] no audit result at {AUDIT_PATH}. Build it first (needs network):")
        print("       .venv/Scripts/python.exe scripts/wider_fp_audit.py")
        return False
    with open(AUDIT_PATH, encoding="utf-8") as fh:
        audit = json.load(fh)
    s = audit["summary"]
    n = s["audited_distinct_new_templates"]
    gating = s["gating_false_positives"]
    excluded = s.get("excluded_in_corpus", 0)
    name_counts = s.get("audited_name_flagged_counts", {})
    # Recompute the gating count from the per-template records (don't trust the summary alone).
    recomputed_gating = sum(1 for r in audit["templates"] if r.get("gates_ci"))
    wider = n >= WIDER_MIN
    clean = gating == 0 and recomputed_gating == 0
    names_clean = all(name_counts.get(nm, 0) == 0
                      or all(not r.get("gates_ci") for r in audit["templates"]
                             if nm in r.get("catalog_identifiers_flagged", []))
                      for nm in AUDIT_NAMES)
    print(f"audited distinct NEW templates: {n}  (excluded {excluded} already-in-corpus; "
          f">= {WIDER_MIN} required: {wider})")
    print(f"presence templates: {s.get('presence_templates')}   "
          f"reachable: {s.get('reachable_templates')}")
    print(f"GATING false positives: {gating}  (recomputed {recomputed_gating})")
    print(f"audited-name flagged counts (open/globals/locals/vars): {name_counts}")
    if audit.get("gating_false_positives"):
        for r in audit["gating_false_positives"]:
            print(f"  [FP] {r['model']} [{r['template_name']}]: {r['rule_ids']} {r['evidence']}")
    ok = wider and clean and names_clean
    print(f"[{'OK' if ok else 'FAIL'}] wider sample ({n}) measured {gating}/{n} gating FP; "
          f"common names never gated.")
    return ok


def _gating_presence(directory: str) -> tuple[int, int, int]:
    files = _jinja_files(directory)
    gating = present = 0
    for fname in files:
        try:
            findings = analyze_template(_read(os.path.join(directory, fname)))
        except ParseError:
            return len(files), -1, -1
        if findings:
            present += 1
        if any(f.reachable for f in findings):
            gating += 1
    return len(files), present, gating


def verify_corpus_clean() -> bool:
    print("\n" + "=" * 78)
    print("Phase 15 (c) -- catalog keeps the 120-corpus + 11 fixtures FP-clean")
    print("=" * 78)
    n_corpus, present_corpus, gating_corpus = _gating_presence(CORPUS_DIR)
    n_benign, present_benign, gating_benign = _gating_presence(BENIGN_DIR)
    rate = gating_corpus / n_corpus if n_corpus else 1.0
    print(f"corpus  : {n_corpus} templates -- presence {present_corpus}, gating {gating_corpus} "
          f"({rate:.2%} FP)")
    print(f"benign  : {n_benign} fixtures  -- presence {present_benign}, gating {gating_benign}")
    ok = (n_corpus >= 100 and gating_corpus == 0 and present_corpus == 0
          and n_benign >= 10 and gating_benign == 0 and present_benign == 0)
    print(f"[{'OK' if ok else 'FAIL'}] corpus FP 0.00% gating AND 0 presence; fixtures clean.")
    return ok


def verify_benchmark_gh_side() -> bool:
    print("\n" + "=" * 78)
    print("Phase 15 (d) -- benchmark (GlyphHound side, offline): malicious gate, benign clean")
    print("=" * 78)
    manifest = json.load(open(BENCH_MANIFEST, encoding="utf-8"))
    ok = True
    mal = ben = 0
    for p in manifest["payloads"]:
        findings = analyze_template(_read(os.path.join(BENCH_DIR, p["file"])))
        gates = make_report(findings).exit_code != 0
        expected = bool(p["gh_expected"])
        good = gates == expected
        ok = ok and good
        if p["malicious"]:
            mal += 1
        else:
            ben += 1
        if not good:
            print(f"  [FAIL] {p['file']}: gates={gates}, expected={expected}")
    print(f"[{'OK' if ok else 'FAIL'}] {mal} malicious payloads gate, {ben} benign controls "
          f"clean under the current analyzer (full GH-vs-ModelAudit table: verify_phase8).")
    return ok


def main() -> int:
    a_ok = verify_catalog_decision()
    b_ok = verify_wider_audit()
    c_ok = verify_corpus_clean()
    d_ok = verify_benchmark_gh_side()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok and d_ok
    print(f"Phase 15: {'PASS' if ok else 'FAIL'} "
          f"(catalog-decision {'ok' if a_ok else 'FAIL'}, wider-audit {'ok' if b_ok else 'FAIL'}, "
          f"corpus {'ok' if c_ok else 'FAIL'}, benchmark {'ok' if d_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
