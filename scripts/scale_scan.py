"""Phase 17 -- resumable, rate-limit-aware prevalence scale-scan (parse-only, NO weights).

Measure how common code-exec-capable chat templates are in the wild: crawl the Hub's
most-downloaded text-generation models, read each one's CANONICAL chat template via the
Phase-14 source (``read_hf_source_template`` -- ``tokenizer_config.json`` /
``chat_template.jinja`` / safetensors ``__metadata__``, all small metadata files), and scan
it with the real CI path. Everything goes through the analyzer's *parse* path only -- a
template is never rendered (no ``--confirm``), and weights are never fetched.

SAFETY / privacy: we record **summaries only** -- the template's sha256, finding counts,
gating/obfuscation flags, the flagged sink identifiers and their lines. The raw template
TEXT is never written to disk, so a malicious payload never lands on the machine; a flagged
model can be re-fetched on demand by its pinned SHA for triage. Nothing here is published.

Resumable: results are appended one JSON object per model to a JSONL checkpoint; a re-run
skips models already recorded. Rate-limit-aware: every Hub request (the model listing and the
metadata fetches) goes through the Phase-17 backoff in :mod:`glyphhound.acquire.hf_source`
(HF_TOKEN auth if set, exponential retry on HTTP 429/503). Reproducible: each model is pinned
by commit SHA, so ``--rescan`` re-measures the exact recorded sample against the current
analyzer with no fresh crawl.

Run (needs network; metadata reads only, no weights):
    .venv/Scripts/python.exe scripts/scale_scan.py --limit 100
    .venv/Scripts/python.exe scripts/scale_scan.py --rescan      # re-measure recorded pins
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.acquire import hf_source, read_hf_source_template  # noqa: E402
from glyphhound.acquire.models import AcquireError  # noqa: E402
from glyphhound.analyze import analyze_ast, analyze_template  # noqa: E402
from glyphhound.parse import ParseError, parse_template  # noqa: E402
from glyphhound.report import make_report  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
STUDY_DIR = os.path.join(ROOT, "study")
DEFAULT_OUT = os.path.join(STUDY_DIR, "scale_scan_results.jsonl")

_API = "https://huggingface.co/api/models"
_POLITE = 0.12       # seconds between Hub requests (be a good citizen)
_MAX_PAGES = 60      # safety cap on API list pages (100 repos/page)


# --- Hub listing (rate-limit-aware via the Phase-17 hf_source backoff) -----------

def _get_json(url: str) -> object:
    # Cap the read at the metadata limit so even a hostile/compromised Hub response can never
    # stream an unbounded body (the same guard hf_source._http_get applies).
    with hf_source._open_with_retry(hf_source._build_request(url)) as resp:
        data = hf_source._read_capped(resp, hf_source._HF_SOURCE_MAX_BYTES)
    return json.loads(data)


def _get_json_and_next(url: str) -> tuple[object, str | None]:
    with hf_source._open_with_retry(hf_source._build_request(url)) as resp:
        link = resp.headers.get("Link", "")
        data = hf_source._read_capped(resp, hf_source._HF_SOURCE_MAX_BYTES)
    m = re.search(r'<([^>]+)>;\s*rel="next"', link)
    return json.loads(data), (m.group(1) if m else None)


def list_top_models(limit: int, *, max_pages: int = _MAX_PAGES) -> list[str]:
    """The ``limit`` most-downloaded text-generation repo ids, cursor-paginated.

    Most-downloaded shifts day to day, so the *crawl* is non-deterministic -- but each model is
    pinned by SHA when scanned and recorded, so the resulting study is reproducible.
    """
    url = (f"{_API}?pipeline_tag=text-generation&sort=downloads&direction=-1"
           f"&limit=100&full=false")
    ids: list[str] = []
    seen: set[str] = set()
    pages = 0
    while url and len(ids) < limit and pages < max_pages:
        data, url = _get_json_and_next(url)
        pages += 1
        for entry in data:
            rid = entry.get("id") or entry.get("modelId")
            if rid and rid not in seen:
                seen.add(rid)
                ids.append(rid)
        time.sleep(_POLITE)
    return ids[:limit]


def resolve_sha(repo: str) -> str:
    """Pin ``repo`` by its current commit SHA (determinism)."""
    return _get_json(f"{_API}/{repo}")["sha"]


# --- scanning (summaries only -- NO raw template text leaves memory) --------------

def summarize_template(name: str | None, text: str) -> dict:
    """A summary record for one chat template. NEVER includes the raw template text.

    ``obfuscated`` is True when the template gates only *after* de-obfuscation
    (``analyze_template``) and not on the raw walk (``analyze_ast(parse_template(...))``) --
    i.e. the code-exec capability was hidden behind concat/format/slice/case-fold/etc. and
    a string-matcher would miss it. That gates-only-after-folding gap is GlyphHound's edge.
    """
    folded = analyze_template(text)
    raw = analyze_ast(parse_template(text))
    gates = make_report(folded).exit_code != 0
    gates_raw = make_report(raw).exit_code != 0
    reachable = [f for f in folded if f.reachable is True]
    return {
        "template_name": name,
        "template_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "template_chars": len(text),
        "gates_ci": gates,
        "obfuscated": gates and not gates_raw,
        "n_findings": len(folded),
        "n_reachable": len(reachable),
        "rule_ids": sorted({f.rule_id for f in folded}),
        "reachable_rule_ids": sorted({f.rule_id for f in reachable}),
        "evidence": sorted({f.evidence for f in folded}),
        "reachable_lines": sorted({f.source_line for f in reachable if f.source_line >= 1}),
    }


def scan_repo(repo: str, revision: str) -> dict:
    """Read every canonical template in ``repo`` (pinned at ``revision``) and summarize each.

    A template that fails to parse is recorded as a coverage gap (``parse_error``), not a
    finding -- honest accounting, like the corpus build's parse-skips.
    """
    raw = read_hf_source_template(repo, revision=revision)
    templates: list[dict] = []
    for ct in raw.templates:
        try:
            templates.append(summarize_template(ct.name, ct.text))
        except ParseError:
            templates.append({"template_name": ct.name, "parse_error": True})
    return {
        "model": repo,
        "revision": revision,
        "bytes_fetched": raw.bytes_fetched,
        "n_templates": len(raw.templates),
        "templates": templates,
    }


# --- resume / orchestration ------------------------------------------------------

def done_repos(path: str) -> set[str]:
    """Repo ids already recorded in the JSONL checkpoint (so a re-run skips them)."""
    done: set[str] = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    done.add(json.loads(line)["model"])
                except (json.JSONDecodeError, KeyError):
                    continue
    return done


def _print_tally(records: list[dict]) -> None:
    scanned = [t for r in records for t in r["templates"] if "parse_error" not in t]
    gating = [t for t in scanned if t.get("gates_ci")]
    obf = [t for t in gating if t.get("obfuscated")]
    print("\n" + "=" * 78)
    print(f"models recorded: {len(records)}   templates scanned: {len(scanned)}")
    print(f"code-exec-capable (gating) templates: {len(gating)}   "
          f"of which obfuscated: {len(obf)}")
    print("=" * 78)


def run(limit: int, out_path: str, *, resume: bool = True) -> int:
    os.makedirs(STUDY_DIR, exist_ok=True)
    already = done_repos(out_path) if resume else set()
    print(f"[plan] scanning up to {limit} top text-generation models -> {out_path}")
    if already:
        print(f"[resume] {len(already)} models already recorded; skipping them")

    repos = list_top_models(limit)
    skips = {"no_template": 0, "http": 0, "other": 0, "resumed": 0}
    new_records: list[dict] = []

    mode = "a" if resume else "w"
    with open(out_path, mode, encoding="utf-8", newline="\n") as out:
        for i, repo in enumerate(repos, 1):
            if repo in already:
                skips["resumed"] += 1
                continue
            try:
                rec = scan_repo(repo, resolve_sha(repo))
            except urllib.error.HTTPError:
                skips["http"] += 1
                continue
            except AcquireError:           # incl. TemplateNotFoundError (no chat template)
                skips["no_template"] += 1
                continue
            except Exception as exc:        # noqa: BLE001 - one bad repo must not abort the scan
                skips["other"] += 1
                print(f"[skip-other] {repo}: {type(exc).__name__}: {exc}")
                continue
            finally:
                time.sleep(_POLITE)
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out.flush()
            new_records.append(rec)
            if i % 25 == 0:
                print(f"[progress] {i}/{len(repos)} examined, "
                      f"{len(new_records)} new models recorded, skips {skips}")

    print(f"\n[done] examined {len(repos)} repos; skips: {skips}")
    # Re-read the whole checkpoint so the tally reflects resumed runs too.
    all_records = _load_jsonl(out_path)
    _print_tally(all_records)
    return 0


# --- rescan: re-measure the recorded pins against the current analyzer ------------

def _load_jsonl(path: str) -> list[dict]:
    records: list[dict] = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


def rescan(out_path: str) -> int:
    """Re-fetch each recorded (model, revision) and re-summarize with the current analyzer.

    Deterministic given the pins; used to confirm the study reproduces after an
    analyzer change. A since-removed/gated repo is dropped from the sample.
    """
    if not os.path.exists(out_path):
        print(f"[FAIL] no prior scan at {out_path}; run a scan first.")
        return 1
    prev = _load_jsonl(out_path)
    rebuilt: list[dict] = []
    dropped = 0
    for old in prev:
        try:
            rebuilt.append(scan_repo(old["model"], old["revision"]))
        except Exception:  # noqa: BLE001 - a since-removed/gated pin drops from the sample
            dropped += 1
        time.sleep(_POLITE)
    with open(out_path, "w", encoding="utf-8", newline="\n") as out:
        for rec in rebuilt:
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"[rescan] re-measured {len(rebuilt)} models ({dropped} dropped as gone)")
    _print_tally(rebuilt)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GlyphHound prevalence scale-scan (no weights)")
    parser.add_argument("--limit", type=int, default=100,
                        help="number of top models to scan (default 100)")
    parser.add_argument("--out", default=DEFAULT_OUT, help="JSONL checkpoint path")
    parser.add_argument("--no-resume", action="store_true",
                        help="overwrite the checkpoint instead of resuming it")
    parser.add_argument("--rescan", action="store_true",
                        help="re-measure the recorded pins against the current analyzer")
    args = parser.parse_args(argv)
    if args.rescan:
        return rescan(args.out)
    return run(args.limit, args.out, resume=not args.no_resume)


if __name__ == "__main__":
    raise SystemExit(main())
