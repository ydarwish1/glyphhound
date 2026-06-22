"""Phase 17 -- aggregate the scale-scan JSONL into a prevalence CSV + summary JSON.

Reads the per-model checkpoint produced by ``scale_scan.py`` (summaries only -- no raw
template text) and emits two reproducible artifacts in ``study/``:

* ``prevalence.csv`` -- one row per scanned chat template (model, pinned SHA, name, sha256,
  gating/obfuscated flags, flagged sink identifiers + lines).
* ``prevalence_summary.json`` -- the aggregate counts behind the writeup's headline.

Pure aggregation over the recorded data -- no network, deterministic. Re-run any time after a
scan (or a ``scale_scan.py --rescan``) to regenerate the artifacts.

    .venv/Scripts/python.exe scripts/prevalence_report.py
"""

from __future__ import annotations

import csv
import json
import os
import sys

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
STUDY_DIR = os.path.join(ROOT, "study")
DEFAULT_IN = os.path.join(STUDY_DIR, "scale_scan_results.jsonl")
CSV_OUT = os.path.join(STUDY_DIR, "prevalence.csv")
SUMMARY_OUT = os.path.join(STUDY_DIR, "prevalence_summary.json")

CSV_FIELDS = [
    "model", "revision", "template_name", "template_sha256", "template_chars",
    "parse_error", "gates_ci", "obfuscated", "n_findings", "n_reachable",
    "rule_ids", "reachable_rule_ids", "evidence", "reachable_lines",
]


def load_jsonl(path: str) -> list[dict]:
    records: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _scanned_templates(records: list[dict]) -> list[dict]:
    """Every per-template summary across all models, tagged with its model + revision."""
    out: list[dict] = []
    for model in records:
        for t in model.get("templates", []):
            out.append({"model": model["model"], "revision": model["revision"], **t})
    return out


def aggregate(records: list[dict]) -> dict:
    """The prevalence counts. The rate's denominator is *parseable* chat templates -- a model
    with no chat template never enters ``records`` (it is skipped at scan time), and an
    unparseable template is a coverage gap counted separately, not a benign or a finding."""
    templates = _scanned_templates(records)
    parseable = [t for t in templates if not t.get("parse_error")]
    unparseable = [t for t in templates if t.get("parse_error")]
    gating = [t for t in parseable if t.get("gates_ci")]
    obfuscated = [t for t in gating if t.get("obfuscated")]
    distinct = {t["template_sha256"] for t in parseable}
    capable_models = {t["model"] for t in gating}
    by_rule: dict[str, int] = {}
    for t in gating:
        for rid in t.get("reachable_rule_ids", []):
            by_rule[rid] = by_rule.get(rid, 0) + 1
    n = len(parseable)
    return {
        "models_recorded": len(records),
        "templates_scanned": len(templates),
        "templates_parseable": n,
        "templates_unparseable": len(unparseable),
        "distinct_templates": len(distinct),
        "code_exec_capable_templates": len(gating),
        "obfuscated_capable_templates": len(obfuscated),
        "models_with_capable_template": len(capable_models),
        "gating_rate": round(len(gating) / n, 6) if n else 0.0,
        "obfuscated_rate": round(len(obfuscated) / n, 6) if n else 0.0,
        "capable_by_reachable_rule": dict(sorted(by_rule.items())),
        "method": "make_report(analyze_template(text)).exit_code != 0 == code-exec-capable "
                  "(the real CI gate); 'obfuscated' = gates only after de-obfuscation, not on "
                  "the raw walk. Parse-only, no weights; summaries only.",
    }


def write_csv(records: list[dict], path: str) -> int:
    rows = _scanned_templates(records)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for t in rows:
            row = dict(t)
            for key in ("rule_ids", "reachable_rule_ids", "evidence", "reachable_lines"):
                if isinstance(row.get(key), list):
                    row[key] = " ".join(str(x) for x in row[key])
            writer.writerow(row)
    return len(rows)


def main(argv: list[str] | None = None) -> int:
    in_path = (argv or [DEFAULT_IN])[0] if (argv) else DEFAULT_IN
    if not os.path.exists(in_path):
        print(f"[FAIL] no scan results at {in_path}; run scale_scan.py first.")
        return 1
    records = load_jsonl(in_path)
    n_rows = write_csv(records, CSV_OUT)
    summary = aggregate(records)
    with open(SUMMARY_OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    print(f"Wrote {CSV_OUT} ({n_rows} template rows)")
    print(f"Wrote {SUMMARY_OUT}")
    print("\n" + json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
