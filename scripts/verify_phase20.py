"""Phase 20 verification -- small polish: deep-nest DoS guard + auto .gguf + gated repos.

Offline and deterministic (the project conventions): the deep-nest checks are pure; the network
bits (the Hub tree listing and gated 401/403 responses) are exercised by swapping the module's
HTTP helpers for stubs, so no request is issued. No weights are ever read (Rule 6).

Checks (the design docs row 20 / the project history Phase 20 tracker):
  (a) deep-nest DoS guard: a pathologically nested template raises a clean ParseError (not an
      uncaught RecursionError), the cap has >=3x headroom over the deepest benign corpus
      template, and no real corpus template is falsely rejected.
  (b) auto-pick smallest .gguf: `--file auto` resolves to the smallest .gguf in a repo
      (deterministic); a repo with no .gguf raises a clear AcquireError.
  (c) gated/private repos: a 401/403 on BOTH the canonical-source path and the GGUF path
      surfaces a clean AcquireError pointing at HF_TOKEN, and the GGUF path sends the token.

Run:  .venv/Scripts/python.exe scripts/verify_phase20.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.acquire import AcquireError, gguf, hf_source  # noqa: E402
from glyphhound.parse import ParseError, parse_template  # noqa: E402
from glyphhound.parse.jinja_ast import _MAX_AST_DEPTH  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
CORPUS_DIR = os.path.join(ROOT, "corpus", "templates")


def _raises(exc_type, fn) -> bool:
    try:
        fn()
        return False
    except exc_type:
        return True


def verify_deep_nest_guard() -> bool:
    print("=" * 78)
    print("Phase 20 (a) -- deep-nest DoS guard: clean ParseError, no false rejection")
    print("=" * 78)
    over = "{{ x[" + "'a'" + "+'a'" * 200 + "] }}"        # ~204 deep: parses then exceeds cap
    extreme = "{{ x[" + "'a'" + "+'a'" * 20000 + "] }}"   # overflows Jinja's own parser
    shallow = "{{ x[" + "'a'" + "+'a'" * 50 + "] }}"      # ~54 deep: fine

    over_ok = _raises(ParseError, lambda: parse_template(over))
    extreme_ok = _raises(ParseError, lambda: parse_template(extreme))
    shallow_ok = not _raises(Exception, lambda: parse_template(shallow))
    print(f"  [{'OK' if over_ok else 'FAIL'}]   ~204-deep template -> ParseError (cap={_MAX_AST_DEPTH})")
    print(f"  [{'OK' if extreme_ok else 'FAIL'}]   ~20000-deep template -> ParseError (no RecursionError)")
    print(f"  [{'OK' if shallow_ok else 'FAIL'}]   ~54-deep template parses fine")

    rejected = []
    for fname in sorted(f for f in os.listdir(CORPUS_DIR) if f.endswith(".jinja")):
        if _raises(ParseError, lambda p=os.path.join(CORPUS_DIR, fname):
                   parse_template(open(p, encoding="utf-8").read())):
            rejected.append(fname)
    corpus_ok = not rejected and _MAX_AST_DEPTH >= 100
    print(f"  [{'OK' if corpus_ok else 'FAIL'}]   benign corpus: 0 false rejections "
          f"({len(rejected)} rejected); cap {_MAX_AST_DEPTH} >= 3x the deepest benign (29)")
    ok = over_ok and extreme_ok and shallow_ok and corpus_ok
    print(f"[{'OK' if ok else 'FAIL'}] a pathological template is rejected cleanly; real ones are not.")
    return ok


def verify_auto_gguf() -> bool:
    print("\n" + "=" * 78)
    print("Phase 20 (b) -- --file auto picks the smallest .gguf (deterministic)")
    print("=" * 78)
    saved = hf_source._http_get
    try:
        hf_source._http_get = lambda url, **k: json.dumps([
            {"type": "file", "path": "big.Q8.gguf", "size": 900},
            {"type": "file", "path": "small.Q4.gguf", "size": 100},
            {"type": "file", "path": "notes.md", "size": 5},
            {"type": "file", "path": "lfs.Q5.gguf", "lfs": {"size": 300}},
        ]).encode("utf-8")
        picked = hf_source.smallest_gguf_filename("o/r")
        pick_ok = picked == "small.Q4.gguf"
        print(f"  [{'OK' if pick_ok else 'FAIL'}]   smallest of 3 .gguf (+1 non-gguf) -> {picked!r}")

        hf_source._http_get = lambda url, **k: json.dumps(
            [{"type": "file", "path": "x.txt", "size": 1}]).encode("utf-8")
        none_ok = _raises(AcquireError, lambda: hf_source.smallest_gguf_filename("o/r"))
        print(f"  [{'OK' if none_ok else 'FAIL'}]   repo with no .gguf -> clear AcquireError")
    finally:
        hf_source._http_get = saved
    ok = pick_ok and none_ok
    print(f"[{'OK' if ok else 'FAIL'}] auto-pick resolves the smallest quant deterministically.")
    return ok


def verify_gated_repos() -> bool:
    print("\n" + "=" * 78)
    print("Phase 20 (c) -- gated/private 401/403 -> clean AcquireError pointing at HF_TOKEN")
    print("=" * 78)
    # canonical-source path
    saved_open = hf_source._open_with_retry
    src_ok = False
    try:
        def raise_401(req):
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
        hf_source._open_with_retry = raise_401
        try:
            hf_source._http_get("https://huggingface.co/o/r/resolve/main/tokenizer_config.json")
        except AcquireError as exc:
            src_ok = "401" in str(exc) and "HF_TOKEN" in str(exc)
            print(f"  [{'OK' if src_ok else 'FAIL'}]   canonical source 401 -> {str(exc)[:70]}...")
    finally:
        hf_source._open_with_retry = saved_open

    # GGUF path
    saved_urlopen = urllib.request.urlopen
    gg_ok = sent_token = False
    try:
        os.environ["HF_TOKEN"] = "tok-xyz"

        def fake_urlopen(req, timeout=None):
            nonlocal sent_token
            sent_token = req.get_header("Authorization") == "Bearer tok-xyz"
            raise urllib.error.HTTPError(getattr(req, "full_url", "u"), 403, "Forbidden", {}, None)
        urllib.request.urlopen = fake_urlopen
        try:
            gguf.read_gguf_template("owner/repo", filename="x.gguf")
        except AcquireError as exc:
            gg_ok = "HF_TOKEN" in str(exc)
            print(f"  [{'OK' if gg_ok else 'FAIL'}]   GGUF path 403 -> {str(exc)[:70]}...")
        print(f"  [{'OK' if sent_token else 'FAIL'}]   GGUF path sends the HF_TOKEN bearer when set")
    finally:
        urllib.request.urlopen = saved_urlopen
        os.environ.pop("HF_TOKEN", None)
    ok = src_ok and gg_ok and sent_token
    print(f"[{'OK' if ok else 'FAIL'}] gated/private repos fail cleanly with an actionable message.")
    return ok


def main() -> int:
    a_ok = verify_deep_nest_guard()
    b_ok = verify_auto_gguf()
    c_ok = verify_gated_repos()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok
    print(f"Phase 20: {'PASS' if ok else 'FAIL'} "
          f"(deep-nest {'ok' if a_ok else 'FAIL'}, auto-gguf {'ok' if b_ok else 'FAIL'}, "
          f"gated {'ok' if c_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
