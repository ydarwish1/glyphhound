"""Phase 17 -- score GlyphHound over the public labeled yardstick (benchmark + corpus).

ModelAudit-free, offline, deterministic. Runs GlyphHound's real CI gate over:

* the **labeled MARKER payloads** in ``benchmark/payloads/`` (labels in ``MANIFEST.json``:
  ``malicious`` true/false) -- obfuscated CVE-2024-34359-class gadgets + benign controls; and
* the **labeled-benign corpus** in ``corpus/templates/`` (120 real HF templates, provenance in
  ``corpus/PROVENANCE.json``).

...and prints the catch rate (malicious flagged) + false-positive rate (benign flagged). Anyone
can run this to reproduce GlyphHound's numbers, or adapt the same loop to score *their own*
scanner against the dataset -- without installing the incumbent. Parse-only, never renders;
the payloads are harmless MARKER simulations.

    .venv/Scripts/python.exe scripts/score_yardstick.py   # exit 0 iff all malicious caught, 0 FP
"""

from __future__ import annotations

import glob
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.analyze import analyze_template  # noqa: E402
from glyphhound.report import make_report  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
PAYLOADS_DIR = os.path.join(ROOT, "benchmark", "payloads")
MANIFEST = os.path.join(PAYLOADS_DIR, "MANIFEST.json")
CORPUS_DIR = os.path.join(ROOT, "corpus", "templates")


def gates(text: str) -> bool:
    """GlyphHound's real CI verdict: does this template gate (>=1 reachable finding >= high)?"""
    return make_report(analyze_template(text)).exit_code != 0


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def score_payloads(manifest_path: str, payloads_dir: str) -> dict:
    """Score the labeled benchmark payloads. ``correct`` == flagged matches the ``malicious`` label."""
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    rows = []
    for p in manifest["payloads"]:
        with open(os.path.join(payloads_dir, p["file"]), encoding="utf-8") as fh:
            flagged = gates(fh.read())
        rows.append({"file": p["file"], "malicious": p["malicious"], "flagged": flagged,
                     "correct": flagged == p["malicious"]})
    malicious = [r for r in rows if r["malicious"]]
    benign = [r for r in rows if not r["malicious"]]
    return {
        "rows": rows,
        "malicious_total": len(malicious),
        "malicious_caught": sum(r["flagged"] for r in malicious),
        "benign_total": len(benign),
        "benign_false_positives": sum(r["flagged"] for r in benign),
    }


def score_corpus(corpus_dir: str) -> dict:
    """Score the labeled-benign corpus: every template should stay clean (no gate)."""
    files = sorted(glob.glob(os.path.join(corpus_dir, "*.jinja")))
    fp_files = [os.path.basename(f) for f in files if gates(_read(f))]
    return {"total": len(files), "false_positives": len(fp_files), "fp_files": fp_files}


def main() -> int:
    pay = score_payloads(MANIFEST, PAYLOADS_DIR)
    cor = score_corpus(CORPUS_DIR)
    benign_total = pay["benign_total"] + cor["total"]
    benign_fp = pay["benign_false_positives"] + cor["false_positives"]
    catch = pay["malicious_caught"] / pay["malicious_total"] if pay["malicious_total"] else 0.0

    print("=" * 70)
    print("GlyphHound yardstick scorecard (offline, ModelAudit-free, deterministic)")
    print("=" * 70)
    print(f"malicious payloads caught : {pay['malicious_caught']}/{pay['malicious_total']} "
          f"({catch:.0%})")
    print(f"benign controls + corpus  : {benign_total - benign_fp}/{benign_total} clean "
          f"({benign_fp} false positive{'s' if benign_fp != 1 else ''})")
    print(f"  - benchmark benign      : {pay['benign_total'] - pay['benign_false_positives']}"
          f"/{pay['benign_total']} clean")
    print(f"  - corpus benign         : {cor['total'] - cor['false_positives']}"
          f"/{cor['total']} clean")
    if cor["fp_files"]:
        print(f"  corpus FP files: {cor['fp_files']}")
    missed = [r["file"] for r in pay["rows"] if r["malicious"] and not r["flagged"]]
    if missed:
        print(f"  MISSED malicious: {missed}")
    ok = pay["malicious_caught"] == pay["malicious_total"] and benign_fp == 0
    print("=" * 70)
    print("RESULT:", "PASS -- all malicious caught, 0 false positives" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
