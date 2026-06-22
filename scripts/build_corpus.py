"""Build the benign real-template corpus for Phase 1 (parser) verification.

Extracts the chat template from a list of real Hugging Face GGUF models using the
Stage-1 acquirer (range-fetch only -- never the weights), pins each by the repo's
current commit SHA, dedupes by template sha256, and vendors the unique templates
into ``fixtures/benign/`` with a ``PROVENANCE.json`` manifest.

Run once (needs network) to (re)generate the corpus:
    .venv/Scripts/python.exe scripts/build_corpus.py

The vendored files are what the offline Phase-1 gate (tests + verify_phase1.py)
parses, so the gate stays deterministic and reproducible from a clean checkout
without re-hitting the network. These are benign, public templates -- safe
to commit.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.acquire import read_gguf_template  # noqa: E402

HERE = os.path.dirname(__file__)
BENIGN_DIR = os.path.normpath(os.path.join(HERE, "..", "fixtures", "benign"))
_API = "https://huggingface.co/api/models"
_UA = "glyphhound/0.0 (+corpus-build; no-weights)"
_TARGET_UNIQUE = 12  # collect at least this many distinct templates (check needs >=10)

# Diverse model families so we get distinct templates (Qwen / Llama-3.x / SmolLM2 /
# Phi / Gemma / Mistral / TinyLlama / StableLM-Zephyr / Hermes ...). Weights are never
# read -- only the metadata header -- so large repos are fine.
CANDIDATE_REPOS = [
    "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
    "bartowski/Llama-3.2-1B-Instruct-GGUF",
    "bartowski/SmolLM2-360M-Instruct-GGUF",
    "unsloth/SmolLM2-135M-Instruct-GGUF",
    "bartowski/Qwen2.5-1.5B-Instruct-GGUF",
    "bartowski/Phi-3.5-mini-instruct-GGUF",
    "bartowski/gemma-2-2b-it-GGUF",
    "bartowski/Mistral-7B-Instruct-v0.3-GGUF",
    "bartowski/TinyLlama-1.1B-Chat-v1.0-GGUF",
    "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
    "bartowski/stablelm-2-zephyr-1_6b-GGUF",
    "bartowski/Hermes-3-Llama-3.2-3B-GGUF",
    "microsoft/Phi-3-mini-4k-instruct-gguf",
    "bartowski/Qwen2.5-Coder-1.5B-Instruct-GGUF",
    "bartowski/Llama-3.2-3B-Instruct-GGUF",
    "bartowski/SmolLM2-1.7B-Instruct-GGUF",
]


def _get_json(url: str) -> object:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def _resolve(repo: str) -> tuple[str, str]:
    """Return (commit_sha, gguf_filename) for a repo: pin the SHA, pick the smallest
    single-file .gguf (multi-part ``-NNNNN-of-`` shards are skipped)."""
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
    os.makedirs(BENIGN_DIR, exist_ok=True)
    seen: dict[str, str] = {}  # template sha256 -> repo (dedupe)
    provenance: list[dict] = []

    for repo in CANDIDATE_REPOS:
        if len(provenance) >= _TARGET_UNIQUE:
            break
        try:
            sha, filename = _resolve(repo)
            r = read_gguf_template(repo, filename=filename, revision=sha)
            r.assert_no_weights_loaded()
        except Exception as e:  # noqa: BLE001 - skip a flaky/changed repo, keep going
            print(f"[skip] {repo}: {type(e).__name__}: {e}")
            continue

        digest = hashlib.sha256(r.template_string.encode("utf-8")).hexdigest()
        if digest in seen:
            print(f"[dup ] {repo}: same template as {seen[digest]} (sha256 {digest[:12]})")
            continue
        seen[digest] = repo

        slug = repo.replace("/", "__")
        out = os.path.join(BENIGN_DIR, slug + ".jinja")
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(r.template_string)
        provenance.append({
            "model": repo,
            "revision": sha,
            "filename": filename,
            "file": slug + ".jinja",
            "template_sha256": digest,
            "template_chars": len(r.template_string),
            "bytes_fetched": r.bytes_fetched,
            "total_size": r.total_size,
            "fraction_fetched": round(r.fraction_fetched, 6),
        })
        print(f"[ok  ] {repo} @ {sha[:12]}  {len(r.template_string)} chars  "
              f"sha256={digest[:12]}  ({r.fraction_fetched:.3%} fetched)")

    provenance.sort(key=lambda p: p["model"])
    with open(os.path.join(BENIGN_DIR, "PROVENANCE.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(provenance, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"\nCollected {len(provenance)} unique real templates -> {BENIGN_DIR}")
    return 0 if len(provenance) >= 10 else 1


if __name__ == "__main__":
    raise SystemExit(main())
