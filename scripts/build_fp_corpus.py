"""Build the Phase-7 benign FP corpus: >=100 DISTINCT real Hugging Face chat templates.

For each candidate GGUF model on the Hub, range-fetch *only* the metadata header to read
``tokenizer.chat_template`` (never the weights — the project conventions), pin the repo by its
current commit SHA, dedupe by template sha256, keep only templates the analyzer can parse,
and vendor the unique ones into ``corpus/templates/*.jinja`` with ``corpus/PROVENANCE.json``.

This is a SEPARATE, larger deliverable from the small Phase-1 ``fixtures/benign`` parse
corpus (Decision Log): ``fixtures/benign`` is the SHA-pinned Rule-9 set that the Phase 2-6
verifiers iterate; the >=100-template ``corpus/`` set is the credibility number for the
analyzer's false-positive rate (PRD §7.6/§8, Phase 7), measured OFFLINE by
``scripts/verify_phase7.py`` over these vendored, pinned, deduped files (Rule 7).

Run once (needs network; range-fetch only, no weights):
    .venv/Scripts/python.exe scripts/build_fp_corpus.py

Candidates are the Hub's most-downloaded GGUF models (cursor-paginated) plus a small diverse
seed. Most quant repos of one base model share a single template, so reaching >=100 DISTINCT
templates means crawling several hundred repos and deduping hard by sha256 (the docs warn
this is "more work than it looks").
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.acquire import read_gguf_template  # noqa: E402
from glyphhound.acquire.models import AcquireError, WeightsLoadedError  # noqa: E402
from glyphhound.analyze import analyze_template  # noqa: E402
from glyphhound.parse import ParseError  # noqa: E402

HERE = os.path.dirname(__file__)
CORPUS_DIR = os.path.normpath(os.path.join(HERE, "..", "corpus"))
TEMPLATES_DIR = os.path.join(CORPUS_DIR, "templates")
PROVENANCE_PATH = os.path.join(CORPUS_DIR, "PROVENANCE.json")

_API = "https://huggingface.co/api/models"
_UA = "glyphhound/0.0 (+fp-corpus-build; no-weights)"

_TARGET_UNIQUE = 120        # collect up to this many distinct templates (need >=100)
_MIN_REQUIRED = 100         # the Phase-7 bar (PRD §9 row 7)
_MAX_CANDIDATES = 2500      # safety cap on repos examined
_MAX_PAGES = 40             # safety cap on API pages crawled (100 repos/page)
_POLITE = 0.10              # seconds between Hub requests (be a good citizen)

# A small diverse seed (distinct families) crawled first, so the corpus is anchored by
# known-good templates even if the popularity crawl is thin on a given day. Weights are
# never read — only the metadata header — so large repos are fine.
SEED_REPOS = [
    "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
    "bartowski/Llama-3.2-1B-Instruct-GGUF",
    "bartowski/SmolLM2-360M-Instruct-GGUF",
    "unsloth/SmolLM2-135M-Instruct-GGUF",
    "bartowski/Phi-3.5-mini-instruct-GGUF",
    "bartowski/gemma-2-2b-it-GGUF",
    "bartowski/Mistral-7B-Instruct-v0.3-GGUF",
    "bartowski/TinyLlama-1.1B-Chat-v1.0-GGUF",
    "bartowski/stablelm-2-zephyr-1_6b-GGUF",
    "bartowski/Hermes-3-Llama-3.2-3B-GGUF",
    "microsoft/Phi-3-mini-4k-instruct-gguf",
]


def _get(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": _UA})


def _get_json(url: str, *, retries: int = 2) -> object:
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(_get(url), timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:  # rate-limited: back off + retry
                time.sleep(2.0 * (attempt + 1))
                continue
            raise


def _get_json_and_next(url: str) -> tuple[object, str | None]:
    """Fetch a Hub list page and return ``(json, next_page_url_or_None)`` using the
    cursor in the ``Link: rel="next"`` header."""
    for attempt in range(3):
        try:
            with urllib.request.urlopen(_get(url), timeout=30) as resp:
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
    """Most-downloaded GGUF repo ids, cursor-paginated (popular = realistic, PRD §7.6)."""
    url = f"{_API}?filter=gguf&sort=downloads&direction=-1&limit=100&full=false"
    ids: list[str] = []
    seen: set[str] = set()
    pages = 0
    while url and len(ids) < _MAX_CANDIDATES and pages < _MAX_PAGES:
        try:
            data, url = _get_json_and_next(url)
        except Exception as e:  # noqa: BLE001 - stop crawling on any list error, keep what we have
            print(f"[crawl-stop] page {pages}: {type(e).__name__}: {e}")
            break
        pages += 1
        for entry in data:
            rid = entry.get("id") or entry.get("modelId")
            if rid and rid not in seen:
                seen.add(rid)
                ids.append(rid)
        time.sleep(_POLITE)
    print(f"[crawl] {len(ids)} candidate GGUF repos over {pages} page(s)")
    return ids


def _resolve(repo: str) -> tuple[str, str]:
    """Return ``(commit_sha, gguf_filename)`` for a repo: pin the SHA, pick the smallest
    single-file ``.gguf`` (multi-part ``-NNNNN-of-`` shards are skipped)."""
    info = _get_json(f"{_API}/{repo}")
    sha = info["sha"]
    tree = _get_json(f"{_API}/{repo}/tree/{sha}?recursive=true")
    ggufs = [
        f for f in tree
        if f.get("type") == "file"
        and f["path"].lower().endswith(".gguf")
        and "-of-" not in f["path"]
    ]
    if not ggufs:
        raise RuntimeError("no single-file .gguf in repo")
    chosen = min(ggufs, key=lambda f: f.get("size", 1 << 62))
    return sha, chosen["path"]


def main() -> int:
    # Rebuild from scratch so stale templates never linger (reproducible vendored set).
    if os.path.isdir(TEMPLATES_DIR):
        shutil.rmtree(TEMPLATES_DIR)
    os.makedirs(TEMPLATES_DIR, exist_ok=True)

    candidates = list(dict.fromkeys(SEED_REPOS + _crawl_candidates()))
    print(f"[plan] {len(candidates)} unique candidate repos (seed + crawl); "
          f"target {_TARGET_UNIQUE} distinct templates\n")

    seen_sha: dict[str, str] = {}  # template sha256 -> repo (dedupe)
    provenance: list[dict] = []
    skips = {"resolve": 0, "no_template": 0, "weights": 0, "parse": 0, "dup": 0,
             "decode": 0, "http": 0, "other": 0}
    examined = 0

    for repo in candidates:
        if len(provenance) >= _TARGET_UNIQUE:
            break
        examined += 1
        try:
            sha, filename = _resolve(repo)
            r = read_gguf_template(repo, filename=filename, revision=sha)
            r.assert_no_weights_loaded()  # Rule 6: bytes_fetched << total_size
            text = r.template_string
            analyze_template(text)  # ensure it parses; keep the corpus analyzable
        except WeightsLoadedError:
            skips["weights"] += 1
            continue
        except ParseError as e:
            skips["parse"] += 1
            print(f"[parse-skip] {repo}: {type(e).__name__}: {e}")
            continue
        except urllib.error.HTTPError as e:
            skips["http"] += 1
            continue
        except AcquireError as e:
            # No chat template, decode failure, range unsupported, etc.
            skips["no_template" if "no '" in str(e) else "decode"] += 1
            continue
        except Exception as e:  # noqa: BLE001 - a flaky/changed repo shouldn't abort the build
            skips["resolve" if "gguf" in str(e).lower() else "other"] += 1
            continue

        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest in seen_sha:
            skips["dup"] += 1
            continue
        seen_sha[digest] = repo

        slug = repo.replace("/", "__")
        out = os.path.join(TEMPLATES_DIR, slug + ".jinja")
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        provenance.append({
            "model": repo,
            "revision": sha,
            "filename": filename,
            "file": slug + ".jinja",
            "template_sha256": digest,
            "template_chars": len(text),
            "bytes_fetched": r.bytes_fetched,
            "total_size": r.total_size,
            "fraction_fetched": round(r.fraction_fetched, 6),
        })
        print(f"[ok {len(provenance):3d}] {repo} @ {sha[:12]}  {len(text):5d} chars  "
              f"sha256={digest[:12]}  ({r.fraction_fetched:.3%} fetched)")

    provenance.sort(key=lambda p: p["model"])
    with open(PROVENANCE_PATH, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(provenance, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"\nExamined {examined} repos; skips: {skips}")
    print(f"Collected {len(provenance)} DISTINCT real templates -> {TEMPLATES_DIR}")
    ok = len(provenance) >= _MIN_REQUIRED
    if not ok:
        print(f"[WARN] only {len(provenance)} < {_MIN_REQUIRED} required; widen the crawl "
              f"(_MAX_PAGES / _TARGET_UNIQUE) or add seeds.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
