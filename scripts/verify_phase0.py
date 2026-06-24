"""Phase 0 verification -- extract chat templates from real models, no weights.

Phase 0a (GGUF): range-fetch the template from several real Hugging Face GGUFs,
pinned by commit SHA for determinism, and assert the no-weights
invariant bytes_fetched << total_size.

Phase 0b (Ollama): if an Ollama store with pulled models is present, extract their
templates too; otherwise report it as deferred (the offline synthetic test already
covers the reader).

Run:  .venv/Scripts/python.exe scripts/verify_phase0.py
Exit code is non-zero if any GGUF extraction fails its invariant.
"""

from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.acquire import (  # noqa: E402
    AcquireError,
    default_models_dir,
    read_gguf_template,
    read_ollama_template,
)

# (repo, filename, pinned commit SHA) -- three model families, diverse templates.
GGUF_MODELS = [
    ("Qwen/Qwen2.5-0.5B-Instruct-GGUF",
     "qwen2.5-0.5b-instruct-q4_k_m.gguf",
     "9217f5db79a29953eb74d5343926648285ec7e67"),
    ("bartowski/Llama-3.2-1B-Instruct-GGUF",
     "Llama-3.2-1B-Instruct-Q4_0.gguf",
     "067b946cf014b7c697f3654f621d577a3e3afd1c"),
    ("bartowski/SmolLM2-360M-Instruct-GGUF",
     "SmolLM2-360M-Instruct-Q4_0.gguf",
     "7be6f65f1db715fe5dc5a4634c0d459b4eed42ec"),
    ("unsloth/SmolLM2-135M-Instruct-GGUF",
     "SmolLM2-135M-Instruct-Q4_K_M.gguf",
     "9e6855bc4be717fca1ef21360a1db4b29d5c559a"),
]


def _human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


def verify_gguf() -> bool:
    print("=" * 78)
    print("Phase 0a -- GGUF template extraction (range-fetch, no weights)")
    print("=" * 78)
    all_ok = True
    for repo, filename, sha in GGUF_MODELS:
        try:
            r = read_gguf_template(repo, filename=filename, revision=sha)
            r.assert_no_weights_loaded()
            digest = hashlib.sha256(r.template_string.encode("utf-8")).hexdigest()
            preview = r.template_string[:90].replace("\n", "\\n")
            names = [t.name or "<default>" for t in r.templates]
            print(f"\n[OK] {repo}")
            print(f"     file     : {filename} @ {sha[:12]}")
            print(f"     fetched  : {_human(r.bytes_fetched)} of {_human(r.total_size)} "
                  f"= {r.fraction_fetched:.3%}")
            print(f"     templates: {len(r.templates)} ({', '.join(names)})")
            print(f"     default  : {len(r.template_string)} chars  sha256={digest[:16]}")
            print(f"     preview  : {preview}...")
        except (AcquireError, Exception) as e:  # noqa: BLE001 - report any failure
            all_ok = False
            print(f"\n[FAIL] {repo}: {type(e).__name__}: {e}")
    return all_ok


def verify_ollama() -> None:
    print("\n" + "=" * 78)
    print("Phase 0b -- Ollama template extraction (local blob, no weights)")
    print("=" * 78)
    models_dir = default_models_dir()
    manifests_root = os.path.join(models_dir, "manifests")
    if not os.path.isdir(manifests_root):
        print(f"\n[DEFERRED] No Ollama store at {models_dir}.")
        print("           Ollama not installed yet -- real-model check deferred.")
        print("           The offline synthetic-store test (tests/test_ollama_acquire.py)")
        print("           already verifies the reader against the documented format.")
        return

    found = False
    for root, _dirs, files in os.walk(manifests_root):
        for tag in files:
            manifest_path = os.path.join(root, tag)
            rel = os.path.relpath(manifest_path, manifests_root)
            parts = rel.replace("\\", "/").split("/")
            # <registry>/<namespace>/<name>/<tag>
            if len(parts) < 4:
                continue
            name, tagname = parts[-2], parts[-1]
            model = f"{name}:{tagname}"
            found = True
            try:
                r = read_ollama_template(model, models_dir=models_dir)
                r.assert_no_weights_loaded()
                digest = hashlib.sha256(r.template_string.encode("utf-8")).hexdigest()
                print(f"\n[OK] ollama:{model}")
                print(f"     fetched  : {_human(r.bytes_fetched)} of {_human(r.total_size)} "
                      f"= {r.fraction_fetched:.3%}")
                print(f"     templates: {len(r.templates)}")
                print(f"     template : {len(r.template_string)} chars  sha256={digest[:16]}")
            except Exception as e:  # noqa: BLE001
                print(f"\n[INFO] ollama:{model}: {type(e).__name__}: {e}")
    if not found:
        print("\n[DEFERRED] Ollama store exists but no models pulled yet.")


def main() -> int:
    gguf_ok = verify_gguf()
    verify_ollama()
    print("\n" + "=" * 78)
    print(f"Phase 0a GGUF: {'PASS' if gguf_ok else 'FAIL'}")
    print("=" * 78)
    return 0 if gguf_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
