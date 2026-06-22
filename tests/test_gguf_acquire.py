"""Offline, deterministic tests for the GGUF acquirer (Phase 0a).

These never hit the network or a real model — they synthesize GGUF bytes and serve
them from a localhost range-capable server. Real-model verification lives in
``scripts/verify_phase0.py``.
"""

from __future__ import annotations

import struct

import pytest

from glyphhound.acquire import (
    AcquireError,
    ChatTemplate,
    RangeUnsupportedError,
    RawTemplate,
    TemplateNotFoundError,
    WeightsLoadedError,
    read_gguf_template,
)
from glyphhound.acquire.gguf import _CHUNK, _HttpRangeWindow, _extract_from_window
from synthetic import RangeServer, build_gguf

# A template with non-ASCII content to prove exact UTF-8 round-tripping.
TEMPLATE = "{% for m in messages %}{{ m.role }}: {{ m.content }}\n{% endfor %}☃ café"


def test_parse_from_local_file(tmp_path):
    payload = build_gguf(TEMPLATE) + b"\x00" * (2 * 1024 * 1024)  # + 2 MiB fake "weights"
    path = tmp_path / "model.gguf"
    path.write_bytes(payload)

    result = read_gguf_template(str(path))

    assert result.template_string == TEMPLATE
    assert result.total_size == len(payload)
    assert result.bytes_fetched < len(payload)
    assert result.bytes_fetched < 100 * 1024  # only the small metadata prefix was read
    # The no-weights invariant holds with a tiny fraction.
    result.assert_no_weights_loaded()
    assert result.fraction_fetched < 0.05


def test_parse_over_http_range():
    # Template placed after the arrays; trailing bytes simulate the weights we must
    # not download.
    payload = build_gguf(TEMPLATE, tokens=128) + b"\x00" * (4 * 1024 * 1024)
    with RangeServer(payload) as server:
        result = read_gguf_template(server.url)

    assert result.template_string == TEMPLATE
    assert result.total_size == len(payload)
    assert 0 < result.bytes_fetched < len(payload)
    # We fetched a bounded prefix (at most a couple of range chunks), not the file.
    assert result.bytes_fetched <= 2 * _CHUNK


def test_http_range_small_chunk_fraction_is_tiny():
    # With a small chunk the fetched fraction is clearly << total, demonstrating the
    # Rule 6 invariant on the network path too.
    payload = build_gguf(TEMPLATE, tokens=64) + b"\x00" * (8 * 1024 * 1024)
    with RangeServer(payload) as server:
        window = _HttpRangeWindow(server.url, chunk=64 * 1024)
        result = _extract_from_window(window, server.url)

    assert result.template_string == TEMPLATE
    result.assert_no_weights_loaded()
    assert result.fraction_fetched < 0.05


def test_refuses_when_server_ignores_range():
    payload = build_gguf(TEMPLATE) + b"\x00" * 1024
    with RangeServer(payload, honor_range=False) as server:
        with pytest.raises(RangeUnsupportedError):
            read_gguf_template(server.url)


def test_missing_template_raises(tmp_path):
    payload = build_gguf("", include_template=False)
    path = tmp_path / "no_template.gguf"
    path.write_bytes(payload)
    with pytest.raises(TemplateNotFoundError):
        read_gguf_template(str(path))


def test_bad_magic_raises(tmp_path):
    path = tmp_path / "not_gguf.bin"
    path.write_bytes(b"NOPE" + b"\x00" * 64)
    with pytest.raises(AcquireError):
        read_gguf_template(str(path))


def test_unsupported_version_raises(tmp_path):
    payload = b"GGUF" + struct.pack("<I", 1) + struct.pack("<Q", 0) + struct.pack("<Q", 0)
    path = tmp_path / "v1.gguf"
    path.write_bytes(payload)
    with pytest.raises(AcquireError):
        read_gguf_template(str(path))


def test_hf_repo_without_filename_raises():
    with pytest.raises(AcquireError):
        read_gguf_template("Some/Repo-GGUF")  # neither a file nor a URL, no filename


def test_non_utf8_template_raises_acquire_error(tmp_path):
    payload = build_gguf(template_bytes=b"\xff\xfe not valid utf8 \x80\x00")
    path = tmp_path / "bad_utf8.gguf"
    path.write_bytes(payload)
    with pytest.raises(AcquireError):  # must NOT escape as a raw UnicodeDecodeError
        read_gguf_template(str(path))


def test_named_only_template_fallback(tmp_path):
    payload = build_gguf(
        include_template=False,
        named_templates={
            "tokenizer.chat_template.tool_use": "TOOL-USE-TEMPLATE",
            "tokenizer.chat_template.default": "DEFAULT-NAMED-TEMPLATE",
        },
    )
    path = tmp_path / "named.gguf"
    path.write_bytes(payload)
    # Deterministic: lexicographically-first named key wins.
    assert read_gguf_template(str(path)).template_string == "DEFAULT-NAMED-TEMPLATE"


def test_nested_array_is_skipped(tmp_path):
    payload = build_gguf(TEMPLATE, nested_array=True)
    path = tmp_path / "nested.gguf"
    path.write_bytes(payload)
    assert read_gguf_template(str(path)).template_string == TEMPLATE


def test_multi_chunk_http_fetch():
    # ~1.6 MiB of metadata before the template forces more than one 1 MiB range fetch.
    payload = build_gguf(TEMPLATE, scores=420_000) + b"\x00" * (2 * 1024 * 1024)
    with RangeServer(payload) as server:
        result = read_gguf_template(server.url)
    assert result.template_string == TEMPLATE
    assert result.bytes_fetched > _CHUNK             # multiple chunks were genuinely needed
    assert result.bytes_fetched < len(payload)


def test_malicious_206_oversend_is_capped():
    # A hostile server claims a small range but floods the whole payload; we must read
    # only what we asked for (Rule 6 hardening).
    payload = build_gguf(TEMPLATE) + b"\x00" * (4 * 1024 * 1024)
    with RangeServer(payload, oversend=True) as server:
        window = _HttpRangeWindow(server.url, chunk=64 * 1024)
        assert len(window._buf) <= 64 * 1024         # prime read was capped, not flooded
        assert window.bytes_fetched <= 64 * 1024
        result = _extract_from_window(window, server.url)
    assert result.template_string == TEMPLATE


def test_metadata_cap_enforced(tmp_path, monkeypatch):
    # With the template beyond a tiny cap and no earlier match, refuse rather than read on.
    monkeypatch.setattr("glyphhound.acquire.gguf._MAX_METADATA_BYTES", 256)
    payload = build_gguf(TEMPLATE, tokens=200)        # metadata well over 256 bytes
    path = tmp_path / "big_meta.gguf"
    path.write_bytes(payload)
    with pytest.raises(AcquireError):
        read_gguf_template(str(path))


def test_assert_no_weights_loaded_raises_when_fraction_high():
    r = RawTemplate(
        source_ref="x",
        templates=(ChatTemplate(None, "t"),),
        bytes_fetched=60,
        total_size=100,
    )
    with pytest.raises(WeightsLoadedError):
        r.assert_no_weights_loaded()


def test_returns_all_templates_default_and_named(tmp_path):
    # A model with a default template AND a named one: BOTH must be returned, so a
    # malicious named template cannot hide from the analyzer (the security payoff of
    # scanning all templates). MARKER content only.
    payload = build_gguf(
        TEMPLATE,  # the default
        named_templates={
            "tokenizer.chat_template.tool_use": "NAMED-TOOL-USE-TEMPLATE",
            "tokenizer.chat_template.rag": "NAMED-RAG-TEMPLATE",
        },
    )
    path = tmp_path / "multi.gguf"
    path.write_bytes(payload)

    result = read_gguf_template(str(path))

    by_name = {t.name: t.text for t in result.templates}
    assert by_name == {
        None: TEMPLATE,
        "rag": "NAMED-RAG-TEMPLATE",
        "tool_use": "NAMED-TOOL-USE-TEMPLATE",
    }
    # Named variants come in deterministic (sorted) order after the default.
    assert [t.name for t in result.templates] == [None, "rag", "tool_use"]
    # Back-compat: .template_string is the default template.
    assert result.template_string == TEMPLATE
