"""Phase 15 -- wider-corpus false-positive audit.

The Phase-7 corpus is 120 SHA-pinned GGUF templates with a MEASURED 0.00% gating FP.
Phase 12 then added the common names ``open``/``globals``/``locals``/``vars`` (and more) to
the catalog; they were re-measured 0/120 on that corpus, but we want them audited
on a *wider, independent* benign set before we lock the claim.

This script does exactly that, ONCE, over the network (range/metadata reads only, never
weights): it crawls the Hub's most-downloaded text-generation models and
reads each one's CANONICAL chat template via the Phase-14 source
(``read_hf_source_template`` -- ``tokenizer_config.json`` / ``chat_template.jinja`` /
safetensors ``__metadata__``, all small metadata files). It dedupes by template sha256 AND
excludes every template already in the pinned ``corpus/`` (so the audited set is genuinely
NEW, not a re-measurement of the 120), scans each with the real CI path
(``make_report(analyze_template(text))``), and writes the measured result to
``study/wider_fp_audit.json``.

``scripts/verify_phase15.py`` reads that vendored JSON OFFLINE and asserts the audited sample
is wider than the corpus and stayed 0 gating FP -- the same build (network, non-deterministic)
vs verify (offline, deterministic over the vendored result) split as
``build_fp_corpus.py`` / ``verify_phase7.py``.

Run once (needs network; metadata reads only, no weights):
    .venv/Scripts/python.exe scripts/wider_fp_audit.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.acquire import read_hf_source_template  # noqa: E402
from glyphhound.acquire.models import AcquireError  # noqa: E402
from glyphhound.analyze import analyze_template  # noqa: E402
from glyphhound.analyze.models import CODE_EXEC_NAMES, DANGEROUS_DUNDERS  # noqa: E402
from glyphhound.parse import ParseError  # noqa: E402
from glyphhound.report import make_report  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
STUDY_DIR = os.path.join(ROOT, "study")
OUT_PATH = os.path.join(STUDY_DIR, "wider_fp_audit.json")
CORPUS_PROVENANCE = os.path.join(ROOT, "corpus", "PROVENANCE.json")

_API = "https://huggingface.co/api/models"
_UA = "glyphhound/0.0 (+wider-fp-audit; no-weights)"

# The Phase-12 "common" names whose FP-safety on a wider set is the point of this audit.
_AUDIT_NAMES = ("open", "globals", "locals", "vars")

_TARGET_DISTINCT = 250      # collect this many NEW distinct templates (>= the >120 "wider" bar)
_MAX_CANDIDATES = 2000      # safety cap on repos examined
_MAX_PAGES = 30             # safety cap on API list pages (100 repos/page)
_POLITE = 0.12             # seconds between Hub requests (be a good citizen)


def _req(url: str, headers: dict | None = None) -> urllib.request.Request:
    h = {"User-Agent": _UA}
    if headers:
        h.update(headers)
    return urllib.request.Request(url, headers=h)


def _get_json(url: str, *, retries: int = 2) -> object:
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(_req(url), timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                time.sleep(2.0 * (attempt + 1))
                continue
            raise


def _get_json_and_next(url: str) -> tuple[object, str | None]:
    for attempt in range(3):
        try:
            with urllib.request.urlopen(_req(url), timeout=30) as resp:
                data = json.load(resp)
                link = resp.headers.get("Link", "")
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                time.sleep(2.0 * (attempt + 1))
                continue
            raise
    m = re.search(r'<([^>]+)>;\s*rel="next"', link)
    return data, (m.group(1) if m else None)


def _crawl_candidates() -> list[str]:
    """Most-downloaded text-generation repo ids, cursor-paginated. These are the ORIGINAL
    transformers repos (where the canonical template lives), a different population from the
    GGUF quant re-uploads the Phase-7 corpus was built from."""
    url = (f"{_API}?pipeline_tag=text-generation&sort=downloads&direction=-1"
           f"&limit=100&full=false")
    ids: list[str] = []
    seen: set[str] = set()
    pages = 0
    while url and len(ids) < _MAX_CANDIDATES and pages < _MAX_PAGES:
        try:
            data, url = _get_json_and_next(url)
        except Exception as e:  # noqa: BLE001 - stop on any list error, keep what we have
            print(f"[crawl-stop] page {pages}: {type(e).__name__}: {e}")
            break
        pages += 1
        for entry in data:
            rid = entry.get("id") or entry.get("modelId")
            if rid and rid not in seen:
                seen.add(rid)
                ids.append(rid)
        time.sleep(_POLITE)
    print(f"[crawl] {len(ids)} candidate text-generation repos over {pages} page(s)")
    return ids


def _resolve_sha(repo: str) -> str:
    """Pin the repo by its current commit SHA (for determinism)."""
    info = _get_json(f"{_API}/{repo}")
    return info["sha"]


def _identifier_hits(text: str) -> dict:
    """Which audited / catalog identifiers actually appear as IDENTIFIERS the analyzer
    inspects (via its findings), for honest per-name reporting. A finding is only produced
    when a catalog identifier sits in an inspected position; a literal sink word inside a
    benign string is a Const and yields no finding (the identifier-only FP discipline)."""
    findings = analyze_template(text)
    rule_ids = sorted({f.rule_id for f in findings})
    reachable = [f for f in findings if f.reachable is True]
    evidence = sorted({f.evidence for f in findings})
    names = sorted({e for e in evidence
                    if e in _AUDIT_NAMES or e in CODE_EXEC_NAMES or e in DANGEROUS_DUNDERS})
    return {
        "n_findings": len(findings),
        "n_reachable": len(reachable),
        "rule_ids": rule_ids,
        "evidence": evidence,
        "catalog_identifiers_flagged": names,
    }


def _load_corpus_shas() -> set[str]:
    if not os.path.exists(CORPUS_PROVENANCE):
        return set()
    with open(CORPUS_PROVENANCE, encoding="utf-8") as fh:
        return {p["template_sha256"] for p in json.load(fh)}


def main() -> int:
    os.makedirs(STUDY_DIR, exist_ok=True)
    corpus_shas = _load_corpus_shas()
    print(f"[plan] excluding {len(corpus_shas)} templates already in the pinned corpus; "
          f"target {_TARGET_DISTINCT} NEW distinct templates\n")

    candidates = _crawl_candidates()

    seen_sha: set[str] = set()
    records: list[dict] = []
    gating_fp: list[dict] = []
    skips = {"resolve": 0, "no_template": 0, "parse": 0, "dup": 0,
             "in_corpus": 0, "http": 0, "other": 0}
    examined = 0

    for repo in candidates:
        if len(records) >= _TARGET_DISTINCT:
            break
        examined += 1
        try:
            sha = _resolve_sha(repo)
            raw = read_hf_source_template(repo, revision=sha)
        except ParseError:
            skips["parse"] += 1
            continue
        except urllib.error.HTTPError:
            skips["http"] += 1
            continue
        except AcquireError:
            skips["no_template"] += 1
            continue
        except Exception:  # noqa: BLE001 - a flaky/changed repo shouldn't abort the audit
            skips["other"] += 1
            continue
        finally:
            time.sleep(_POLITE)

        # Scan EVERY template (default + named variants) -- a malicious named variant cannot hide.
        for ct in raw.templates:
            text = ct.text
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if digest in corpus_shas:
                skips["in_corpus"] += 1
                continue
            if digest in seen_sha:
                skips["dup"] += 1
                continue
            try:
                hits = _identifier_hits(text)
            except ParseError:
                skips["parse"] += 1
                continue
            seen_sha.add(digest)
            findings = analyze_template(text)
            report = make_report(findings)
            gates = report.exit_code != 0
            rec = {
                "model": repo,
                "revision": sha,
                "template_name": ct.name,
                "template_sha256": digest,
                "template_chars": len(text),
                "gates_ci": gates,
                **hits,
            }
            records.append(rec)
            if gates:
                gating_fp.append(rec)
            if len(records) >= _TARGET_DISTINCT:
                break

        if examined % 50 == 0:
            print(f"[progress] examined {examined} repos -> {len(records)} new distinct "
                  f"templates, {len(gating_fp)} gating")

    # Per-name presence over the audited set (how often each audited name was FLAGGED).
    name_flagged = {n: 0 for n in _AUDIT_NAMES}
    presence = sum(1 for r in records if r["n_findings"] > 0)
    reachable = sum(1 for r in records if r["n_reachable"] > 0)
    for r in records:
        for n in r["catalog_identifiers_flagged"]:
            if n in name_flagged:
                name_flagged[n] += 1

    n = len(records)
    rate = len(gating_fp) / n if n else 1.0
    summary = {
        "audited_distinct_new_templates": n,
        "examined_repos": examined,
        "excluded_in_corpus": skips["in_corpus"],
        "gating_false_positives": len(gating_fp),
        "gating_fp_rate": round(rate, 6),
        "presence_templates": presence,
        "reachable_templates": reachable,
        "audited_names": list(_AUDIT_NAMES),
        "audited_name_flagged_counts": name_flagged,
        "skips": skips,
        "source": "Phase-14 HF canonical source (tokenizer_config.json / chat_template.jinja "
                  "/ safetensors __metadata__); metadata reads only, no weights",
        "method": "make_report(analyze_template(text)).exit_code != 0 == gating FP (the real "
                  "CI gate); deduped by template sha256 and excluded from the pinned corpus",
    }

    records.sort(key=lambda r: (r["model"], r["template_name"] or ""))
    out = {"summary": summary, "gating_false_positives": gating_fp, "templates": records}
    with open(OUT_PATH, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print("\n" + "=" * 78)
    print(f"Examined {examined} repos; skips: {skips}")
    print(f"Audited {n} NEW distinct templates (not in the pinned corpus)")
    print(f"presence (any finding): {presence}/{n}   reachable: {reachable}/{n}")
    print(f">>> WIDER-SAMPLE GATING FALSE-POSITIVE RATE: {rate:.2%}  ({len(gating_fp)}/{n}) <<<")
    print(f"audited-name flagged counts: {name_flagged}")
    if gating_fp:
        print("\n[gating FP detail -- investigate before any 0-FP claim]:")
        for r in gating_fp:
            print(f"  {r['model']} [{r['template_name']}]: rules {r['rule_ids']} "
                  f"evidence {r['evidence']}")
    print(f"\nWrote {OUT_PATH}")
    print("=" * 78)
    # Non-zero only if we failed to gather a wider sample; the FP rate is the deliverable,
    # reported either way -- a gating hit is investigated, not silently failed here.
    return 0 if n >= 120 else 1


def _rescan_record(repo_cache: dict, model: str, revision: str, sha256: str) -> dict | None:
    """Re-fetch a repo (cached by (model, revision)) and re-scan the template whose text
    hashes to ``sha256`` with the CURRENT analyzer. ``None`` if the pinned template is gone."""
    key = (model, revision)
    if key not in repo_cache:
        try:
            repo_cache[key] = read_hf_source_template(model, revision=revision)
        except Exception:  # noqa: BLE001 - a since-removed/gated repo is dropped from the sample
            repo_cache[key] = None
    raw = repo_cache[key]
    if raw is None:
        return None
    ct = next((c for c in raw.templates
               if hashlib.sha256(c.text.encode("utf-8")).hexdigest() == sha256), None)
    if ct is None:
        return None
    findings = analyze_template(ct.text)
    return {
        "gates_ci": make_report(findings).exit_code != 0,
        **_identifier_hits(ct.text),
    }


def rescan() -> int:
    """Re-measure the EXISTING pinned audit sample against the current analyzer (no new crawl).

    Reads the per-template provenance from ``study/wider_fp_audit.json`` (model + pinned
    revision + template sha256), re-fetches each pinned template, re-scans it, and rewrites the
    JSON. Used after an analyzer change (e.g. the Phase-15 subscript-key FP narrowing) so the
    vendored result reflects the final analyzer on the same pinned sample -- deterministic given
    the pins, and far faster than a fresh crawl.
    """
    if not os.path.exists(OUT_PATH):
        print(f"[FAIL] no prior audit at {OUT_PATH}; run a full crawl first.")
        return 1
    with open(OUT_PATH, encoding="utf-8") as fh:
        prev = json.load(fh)
    repo_cache: dict = {}
    records: list[dict] = []
    dropped = 0
    for old in prev["templates"]:
        scanned = _rescan_record(repo_cache, old["model"], old["revision"],
                                 old["template_sha256"])
        if scanned is None:
            dropped += 1
            continue
        records.append({
            "model": old["model"], "revision": old["revision"],
            "template_name": old["template_name"], "template_sha256": old["template_sha256"],
            "template_chars": old["template_chars"], **scanned,
        })
        time.sleep(_POLITE)

    gating_fp = [r for r in records if r["gates_ci"]]
    name_flagged = {nm: 0 for nm in _AUDIT_NAMES}
    for r in records:
        for nm in r["catalog_identifiers_flagged"]:
            if nm in name_flagged:
                name_flagged[nm] += 1
    n = len(records)
    s = dict(prev["summary"])
    s.update({
        "audited_distinct_new_templates": n,
        "gating_false_positives": len(gating_fp),
        "gating_fp_rate": round(len(gating_fp) / n if n else 1.0, 6),
        "presence_templates": sum(1 for r in records if r["n_findings"] > 0),
        "reachable_templates": sum(1 for r in records if r["n_reachable"] > 0),
        "audited_name_flagged_counts": name_flagged,
        "rescanned": True,
        "rescan_dropped_since_audit": dropped,
    })
    records.sort(key=lambda r: (r["model"], r["template_name"] or ""))
    out = {"summary": s, "gating_false_positives": gating_fp, "templates": records}
    with open(OUT_PATH, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"Re-scanned {n} pinned templates ({dropped} dropped as gone); "
          f"gating FP now {len(gating_fp)}/{n} ({s['gating_fp_rate']:.2%}); "
          f"audited-name flagged: {name_flagged}")
    print(f"Wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    if "--rescan" in sys.argv:
        raise SystemExit(rescan())
    raise SystemExit(main())
