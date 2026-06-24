"""Phase 20 -- small polish: deep-nest DoS guard, auto-pick smallest .gguf, gated/private repos.

All offline (the network bits are monkeypatched):
  * the parser rejects a pathologically deep template with a clean ParseError instead of an
    uncaught RecursionError, and never rejects a real (shallow) template;
  * ``--file auto`` resolves to the smallest .gguf in a repo (deterministic);
  * a gated/private repo (HTTP 401/403) surfaces a clean AcquireError that points at HF_TOKEN,
    on BOTH the canonical-source path and the GGUF path -- never an uncaught traceback.
"""

from __future__ import annotations

import json
import os
import urllib.error

import pytest

import glyphhound.scan as scan
from glyphhound.acquire import AcquireError, ChatTemplate, RawTemplate, gguf, hf_source
from glyphhound.parse import ParseError, parse_template
from glyphhound.parse.jinja_ast import _MAX_AST_DEPTH

ROOT = os.path.dirname(os.path.dirname(__file__))


# --- (a) deep-nest DoS guard ---------------------------------------------------------------

def test_overdepth_template_raises_clean_parse_error():
    # ~204-deep concat: Jinja parses it, but it exceeds the _MAX_AST_DEPTH cap -> clean reject.
    deep = "{{ x[" + "'a'" + "+'a'" * 200 + "] }}"
    with pytest.raises(ParseError):
        parse_template(deep)


def test_extreme_depth_raises_parse_error_not_recursionerror():
    # Deep enough to overflow Jinja's own recursive parser -> caught + re-raised as ParseError.
    deep = "{{ x[" + "'a'" + "+'a'" * 20000 + "] }}"
    with pytest.raises(ParseError):
        parse_template(deep)


def test_benign_depth_parses_fine():
    parse_template("{{ x[" + "'a'" + "+'a'" * 50 + "] }}")  # ~54 deep, under the cap: no raise


def test_max_ast_depth_has_headroom_over_benign_corpus():
    corpus = os.path.join(ROOT, "corpus", "templates")
    for fname in os.listdir(corpus):
        if fname.endswith(".jinja"):
            parse_template(open(os.path.join(corpus, fname), encoding="utf-8").read())  # no raise
    assert _MAX_AST_DEPTH >= 100  # >= ~3x the deepest benign template (measured 29)


# --- (b) auto-pick smallest .gguf ----------------------------------------------------------

def _tree(*files):
    return json.dumps(list(files)).encode("utf-8")


def test_smallest_gguf_picks_smallest(monkeypatch):
    monkeypatch.setattr(hf_source, "_http_get", lambda url, **k: _tree(
        {"type": "file", "path": "big.Q8.gguf", "size": 900},
        {"type": "file", "path": "small.Q4.gguf", "size": 100},
        {"type": "file", "path": "README.md", "size": 5},
        {"type": "file", "path": "mid.Q6.gguf", "size": 500},
    ))
    assert hf_source.smallest_gguf_filename("o/r") == "small.Q4.gguf"


def test_smallest_gguf_reads_lfs_size(monkeypatch):
    monkeypatch.setattr(hf_source, "_http_get", lambda url, **k: _tree(
        {"type": "file", "path": "a.gguf", "lfs": {"size": 50}},
        {"type": "file", "path": "b.gguf", "size": 10},
    ))
    assert hf_source.smallest_gguf_filename("o/r") == "b.gguf"


def test_smallest_gguf_no_gguf_raises(monkeypatch):
    monkeypatch.setattr(hf_source, "_http_get",
                        lambda url, **k: _tree({"type": "file", "path": "x.txt", "size": 1}))
    with pytest.raises(AcquireError):
        hf_source.smallest_gguf_filename("o/r")


def test_scan_file_auto_routes_to_smallest_gguf(monkeypatch):
    monkeypatch.setattr(scan, "smallest_gguf_filename", lambda repo, revision="main": "tiny.gguf")
    captured = {}

    def fake_gguf(ref, filename=None, revision="main"):
        captured["filename"] = filename
        return RawTemplate(source_ref=ref, templates=(ChatTemplate(None, "{{ x }}"),),
                           bytes_fetched=1, total_size=1)

    monkeypatch.setattr(scan, "read_gguf_template", fake_gguf)
    scan.scan_source("owner/repo", source="hf", filename="auto")
    assert captured["filename"] == "tiny.gguf"


# --- (c) gated / private repos (401/403) -> clean AcquireError pointing at HF_TOKEN ---------

def test_canonical_source_gated_401_mentions_hf_token(monkeypatch):
    def raise_401(req):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
    monkeypatch.setattr(hf_source, "_open_with_retry", raise_401)
    monkeypatch.delenv("HF_TOKEN", raising=False)
    with pytest.raises(AcquireError) as ei:
        hf_source._http_get("https://huggingface.co/o/r/resolve/main/tokenizer_config.json")
    msg = str(ei.value)
    assert "401" in msg and "HF_TOKEN" in msg


def test_gguf_path_gated_403_mentions_hf_token(monkeypatch):
    def raise_403(req, timeout=None):
        raise urllib.error.HTTPError(getattr(req, "full_url", "u"), 403, "Forbidden", {}, None)
    monkeypatch.setattr("urllib.request.urlopen", raise_403)
    with pytest.raises(AcquireError) as ei:
        gguf.read_gguf_template("owner/repo", filename="x.gguf")
    assert "HF_TOKEN" in str(ei.value)


def test_gguf_sends_hf_token_when_set(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["auth"] = req.get_header("Authorization")
        raise urllib.error.HTTPError(getattr(req, "full_url", "u"), 403, "Forbidden", {}, None)

    monkeypatch.setenv("HF_TOKEN", "secret-token")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(AcquireError):
        gguf.read_gguf_template("owner/repo", filename="x.gguf")
    assert seen["auth"] == "Bearer secret-token"
