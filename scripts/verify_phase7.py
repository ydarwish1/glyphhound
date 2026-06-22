"""Phase 7 verification — benign corpus + measured false-positive rate.

OFFLINE and deterministic (the project conventions): it reads the VENDORED, SHA-pinned,
deduped corpus under ``corpus/`` and never touches the network or loads weights. It only
*parses* each template (via ``analyze_template`` — parse -> de-obfuscate -> walk), never
*renders* one, so reading the corpus cannot execute it. The network-only BUILD step lives
separately in ``scripts/build_fp_corpus.py``.

Checks (the design docs row 7 / the project history Phase 7 tracker — "FP rate computed and reported over
>=100 real templates"):
  (a) CORPUS: >=100 vendored templates, each matching its pinned ``template_sha256`` in
      PROVENANCE (bytes == the pin), all sha256 DISTINCT (deduped), no orphan files.
  (b) NO WEIGHTS (Rule 6): every PROVENANCE entry has ``bytes_fetched << total_size``
      (fraction_fetched < the no-weights threshold); prints min/mean/max fraction.
  (c) FP RATE: runs the real CI path ``make_report(analyze_template(text))`` over every
      template and reports the false-positive rate — a template is a false positive iff its
      report GATES CI (exit_code != 0, i.e. a finding with ``reachable is True`` at severity
      >= threshold). Also reports the presence-only count (any finding, reachable or not)
      and the reachable-template count for context. Prints the number either way (Rule 9);
      any FP is printed in full for honest investigation.

Acceptance bar (recorded in the project history Decision Log): >=100 templates, all no-weights, and a
gating FP rate at or below ACCEPTANCE_FP_RATE. The rate is the deliverable — it is the
MEASURED number on real templates, not a tuned one (Rule 9: do not silently tune the
analyzer to force 0%).

Run:  .venv/Scripts/python.exe scripts/verify_phase7.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.analyze import analyze_template  # noqa: E402
from glyphhound.parse import ParseError  # noqa: E402
from glyphhound.report import make_report  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
CORPUS_DIR = os.path.join(ROOT, "corpus")
TEMPLATES_DIR = os.path.join(CORPUS_DIR, "templates")
PROVENANCE_PATH = os.path.join(CORPUS_DIR, "PROVENANCE.json")

MIN_REQUIRED = 100          # PRD §9 row 7
NO_WEIGHTS_THRESHOLD = 0.10  # matches RawTemplate.assert_no_weights_loaded default (Rule 6)
ACCEPTANCE_FP_RATE = 0.0    # recorded bar: the MEASURED gating FP rate must be <= this


def _load_provenance() -> list[dict]:
    with open(PROVENANCE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def verify_corpus_integrity(prov: list[dict]) -> bool:
    print("=" * 78)
    print("Phase 7 (a) — corpus: >=100 vendored templates, pinned + deduped, no orphans")
    print("=" * 78)
    n = len(prov)
    sha_ok = 0
    digests: set[str] = set()
    integrity_fail = []
    for p in prov:
        path = os.path.join(TEMPLATES_DIR, p["file"])
        if not os.path.exists(path):
            integrity_fail.append(f"{p['file']}: MISSING on disk")
            continue
        digest = hashlib.sha256(_read(path).encode("utf-8")).hexdigest()
        if digest != p["template_sha256"]:
            integrity_fail.append(f"{p['file']}: sha256 mismatch (vendored bytes != pin)")
            continue
        sha_ok += 1
        digests.add(digest)
    # Orphan vendored files with no PROVENANCE entry?
    vendored = {f for f in os.listdir(TEMPLATES_DIR) if f.endswith(".jinja")} \
        if os.path.isdir(TEMPLATES_DIR) else set()
    listed = {p["file"] for p in prov}
    orphans = sorted(vendored - listed)

    distinct = len(digests)
    count_ok = n >= MIN_REQUIRED
    deduped = distinct == sha_ok == n  # every entry distinct AND all integrity-verified
    no_orphans = not orphans
    print(f"PROVENANCE entries:        {n}")
    print(f"vendored .jinja files:     {len(vendored)}")
    print(f"sha256 matches pin:        {sha_ok}/{n}")
    print(f"distinct templates:        {distinct}")
    print(f">= {MIN_REQUIRED} required:           {count_ok}")
    if integrity_fail:
        for line in integrity_fail[:10]:
            print(f"  [FAIL] {line}")
    if orphans:
        print(f"  [FAIL] {len(orphans)} orphan file(s) with no PROVENANCE entry: {orphans[:5]}")
    ok = count_ok and deduped and no_orphans and not integrity_fail
    print(f"[{'OK' if ok else 'FAIL'}] corpus is >=100, pinned (bytes==sha), deduped, no orphans.")
    return ok


def verify_no_weights(prov: list[dict]) -> bool:
    print("\n" + "=" * 78)
    print("Phase 7 (b) — no weights loaded: bytes_fetched << total_size for every model")
    print("=" * 78)
    fractions = []
    bad = []
    for p in prov:
        frac = p["bytes_fetched"] / p["total_size"] if p["total_size"] else 1.0
        fractions.append(frac)
        if not (p["bytes_fetched"] < p["total_size"] and frac < NO_WEIGHTS_THRESHOLD):
            bad.append((p["model"], frac))
    if fractions:
        lo, hi = min(fractions), max(fractions)
        mean = sum(fractions) / len(fractions)
        print(f"fraction_fetched over {len(fractions)} models: "
              f"min={lo:.4%}  mean={mean:.4%}  max={hi:.4%}  (threshold {NO_WEIGHTS_THRESHOLD:.0%})")
    for model, frac in bad[:10]:
        print(f"  [FAIL] {model}: fetched {frac:.2%} >= {NO_WEIGHTS_THRESHOLD:.0%}")
    ok = not bad and bool(fractions)
    print(f"[{'OK' if ok else 'FAIL'}] all {len(fractions)} models read only the header (Rule 6).")
    return ok


def verify_fp_rate(prov: list[dict]) -> bool:
    print("\n" + "=" * 78)
    print("Phase 7 (c) — measured false-positive rate over the real corpus (Rule 9)")
    print("=" * 78)
    n = len(prov)
    gating_fp = 0       # report gates CI (exit_code != 0) -> the false-positive definition
    reachable_tpls = 0  # >=1 reachable finding (== gating since all rules are severity>=high)
    presence_tpls = 0   # >=1 finding of ANY kind (reachable or not) — context for the filter
    parse_errors = 0
    fp_detail = []
    for p in sorted(prov, key=lambda d: d["model"]):
        path = os.path.join(TEMPLATES_DIR, p["file"])
        try:
            findings = analyze_template(_read(path))
        except ParseError as e:
            parse_errors += 1
            print(f"  [parse-error] {p['model']}: {type(e).__name__}: {e}")
            continue
        report = make_report(findings)
        if findings:
            presence_tpls += 1
        if any(f.reachable is True for f in findings):
            reachable_tpls += 1
        if report.exit_code != 0:
            gating_fp += 1
            fp_detail.append((p["model"], report.summary.gating,
                              [(f.rule_id, f.evidence, f.source_line) for f in findings
                               if f.reachable is True]))

    rate = gating_fp / n if n else 1.0
    print(f"templates analyzed:        {n}  (parse errors: {parse_errors})")
    print(f"presence-only (any finding): {presence_tpls}/{n}  "
          f"({presence_tpls / n:.1%}) — mention a catalog identifier somewhere")
    print(f"reachable findings:          {reachable_tpls}/{n}  ({reachable_tpls / n:.1%})")
    print(f"GATING false positives:      {gating_fp}/{n}")
    print(f"\n>>> MEASURED FALSE-POSITIVE RATE: {rate:.2%}  ({gating_fp}/{n}) <<<\n")
    for model, gating, reach in fp_detail:
        print(f"  [FP] {model}: {gating} gating finding(s): {reach}")
    ok = parse_errors == 0 and rate <= ACCEPTANCE_FP_RATE
    print(f"[{'OK' if ok else 'FAIL'}] FP rate {rate:.2%} <= acceptance bar "
          f"{ACCEPTANCE_FP_RATE:.2%}; {parse_errors} parse error(s).")
    return ok


def main() -> int:
    if not os.path.exists(PROVENANCE_PATH):
        print(f"[FAIL] no corpus at {PROVENANCE_PATH}. Build it first (needs network):")
        print("       .venv/Scripts/python.exe scripts/build_fp_corpus.py")
        return 1
    prov = _load_provenance()
    a_ok = verify_corpus_integrity(prov)
    b_ok = verify_no_weights(prov)
    c_ok = verify_fp_rate(prov)
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok
    print(f"Phase 7: {'PASS' if ok else 'FAIL'} "
          f"(corpus {'ok' if a_ok else 'FAIL'}, "
          f"no-weights {'ok' if b_ok else 'FAIL'}, "
          f"fp-rate {'ok' if c_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
