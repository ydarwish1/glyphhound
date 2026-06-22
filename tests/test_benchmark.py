"""Offline, deterministic tests for the Phase-8 head-to-head benchmark harness.

The GlyphHound side + the table/summary logic are tested fully OFFLINE (no ModelAudit
needed), so the suite stays green in any environment. The single ModelAudit-dependent
test is skipped when the incumbent is not installed in the isolated `.venv-modelaudit`
env — it runs on a machine set up for the benchmark and is skipped in a bare CI, never
failing the suite.

Fixture-driven: the committed MARKER-only payloads in benchmark/payloads/ are the
should-catch / should-not-catch set; here we assert GlyphHound's verdict on each matches the
manifest's locked expectation, and that the payloads are MARKER-only.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import run_benchmark as bench  # noqa: E402
from synthetic import build_gguf  # noqa: E402

MANIFEST = bench.load_manifest()
PAYLOADS = MANIFEST["payloads"]
MARKER = MANIFEST["marker"]

# Substrings that would indicate a REAL harmful command rather than a harmless marker.
# A Phase-8 payload simulates exploitation with the sentinel only.
_REAL_HARM_DENYLIST = (
    "rm -rf", "rmdir", "del /", "format ", "shutdown", "reboot",
    "curl ", "wget ", "http://", "https://", "powershell", "cmd /c",
    "unlink(", ".remove(", ".rmtree(", "socket", "connect(",
)


def _payload_text(entry: dict) -> str:
    with open(os.path.join(bench.PAYLOAD_DIR, entry["file"]), encoding="utf-8") as fh:
        return fh.read()


def _gguf_for(entry: dict, tmp_path) -> str:
    path = os.path.join(str(tmp_path), entry["file"] + ".gguf")
    with open(path, "wb") as fh:
        fh.write(build_gguf(_payload_text(entry)))
    return path


def test_manifest_shape_and_set():
    # 10 malicious (1 plain control + 9 obfuscated) + 3 benign controls (Phase 10 added the
    # str.format / slice / |join / |replace families to the original concat/|attr/getattr set).
    malicious = [p for p in PAYLOADS if p["malicious"]]
    benign = [p for p in PAYLOADS if not p["malicious"]]
    assert len(malicious) == 10
    assert len(benign) == 3
    obf = [p for p in malicious if p["obfuscation"] != "none"]
    assert len(obf) == 9  # the obfuscated set (the headline metric is measured over these)
    # Diverse obfuscation techniques (no padding the set with copies of one evasion).
    assert len({p["obfuscation"] for p in obf}) >= 7
    # The honest edge: obfuscated payloads ModelAudit (strongest config) is expected to MISS
    # (the 3 concat-gated chains + the slice / |join / |replace families).
    edge = [p for p in malicious if not p["modelaudit_expected"]]
    assert len(edge) >= 5
    for p in PAYLOADS:
        assert os.path.exists(os.path.join(bench.PAYLOAD_DIR, p["file"]))


def test_payloads_are_marker_only():
    """Every payload simulates exploitation with the sentinel, no real command."""
    for entry in PAYLOADS:
        text = _payload_text(entry).lower()
        for bad in _REAL_HARM_DENYLIST:
            assert bad.lower() not in text, f"{entry['file']} contains real-harm token {bad!r}"
    # The call-bearing malicious payloads carry the marker; benign carry none.
    for entry in PAYLOADS:
        text = _payload_text(entry)
        if not entry["malicious"]:
            assert MARKER not in text


def test_payload_comments_have_no_literal_sink_tokens():
    """The scanned text must not contain literal sink tokens in PROSE: ModelAudit is a text
    scanner, so a comment token would be matched as if it were the payload and would falsely
    credit the incumbent with catches it never earned on the obfuscated code. Only
    payloads whose actual CODE legitimately contains a token may contain it."""
    # Tokens that, if present only in a comment, would contaminate the text scanner.
    tokens = ["__import__(", "__init__.__globals__", "__subclasses__", "|attr(", "getattr("]
    for entry in PAYLOADS:
        text = _payload_text(entry)
        # Strip Jinja comments to get the code-only portion.
        code_only = _strip_jinja_comments(text)
        for tok in tokens:
            if tok in text:
                assert tok in code_only, (
                    f"{entry['file']}: token {tok!r} appears only in a comment "
                    "(would contaminate the text scanner)"
                )


def _strip_jinja_comments(text: str) -> str:
    out, i = [], 0
    while i < len(text):
        start = text.find("{#", i)
        if start == -1:
            out.append(text[i:])
            break
        out.append(text[i:start])
        end = text.find("#}", start)
        if end == -1:
            break
        i = end + 2
    return "".join(out)


def test_glyphhound_verdict_matches_manifest(tmp_path):
    """GlyphHound (reading the template back out of the same GGUF) flags exactly the payloads
    the manifest locks as gh_expected — all malicious incl. obfuscated, zero benign FP."""
    for entry in PAYLOADS:
        gguf = _gguf_for(entry, tmp_path)
        verdict = bench.glyphhound_verdict(gguf)
        assert verdict["caught"] == entry["gh_expected"], (
            f"{entry['file']}: GlyphHound caught={verdict['caught']} != "
            f"expected {entry['gh_expected']} (reachable={verdict['reachable_rules']})"
        )


def test_glyphhound_catches_all_obfuscated_and_benign_clean(tmp_path):
    obfuscated = [p for p in PAYLOADS if p["malicious"] and p["obfuscation"] != "none"]
    benign = [p for p in PAYLOADS if not p["malicious"]]
    assert all(bench.glyphhound_verdict(_gguf_for(p, tmp_path))["caught"] for p in obfuscated)
    assert not any(bench.glyphhound_verdict(_gguf_for(p, tmp_path))["caught"] for p in benign)


def test_summary_math_on_synthetic_rows():
    """summarize() is pure and correct on hand-built rows (no ModelAudit needed)."""
    def row(file, malicious, obf, gh, ma):
        return {"entry": {"file": file, "label": file, "malicious": malicious,
                          "obfuscation": obf},
                "glyphhound": {"caught": gh}, "modelaudit": {"caught": ma}}
    rows = [
        row("p1", True, "none", True, True),    # plain control: both catch
        row("p2", True, "concat", True, False),  # obfuscated: GH only
        row("p3", True, "attr", True, True),     # obfuscated: both
        row("b1", False, "none", False, False),  # benign: clean
    ]
    s = bench.summarize(rows)
    assert s["malicious_total"] == 3
    assert s["obfuscated_total"] == 2
    assert s["benign_total"] == 1
    assert s["gh_obfuscated_caught"] == 2
    assert s["ma_obfuscated_caught"] == 1
    assert s["gh_benign_fp"] == 0 and s["ma_benign_fp"] == 0
    assert [e["file"] for e in s["ma_misses_gh_catches"]] == ["p2"]


def test_table_format_is_deterministic_and_ascii():
    def row(file, label, malicious, obf, gh, ma):
        return {"entry": {"file": file, "label": label, "malicious": malicious,
                          "obfuscation": obf},
                "glyphhound": {"caught": gh}, "modelaudit": {"caught": ma}}
    rows = [
        row("p1", "plain", True, "none", True, True),
        row("p2", "concat", True, "concat", True, False),
        row("b1", "benign", False, "none", False, False),
    ]
    t1 = bench.format_table(rows, modelaudit_version_str="0.2.47")
    t2 = bench.format_table(rows, modelaudit_version_str="0.2.47")
    assert t1 == t2
    assert t1.isascii()  # never crashes on a cp1252 console


# ---- ModelAudit integration (skipped when the incumbent isn't installed) ----

_MA = bench.find_modelaudit()


@pytest.mark.skipif(_MA is None, reason="ModelAudit not installed (.venv-modelaudit); offline run")
def test_modelaudit_matches_manifest_and_core_claim():
    rows = bench.run_benchmark(_MA, MANIFEST)
    by_file = {r["entry"]["file"]: r for r in rows}

    # Live ModelAudit verdicts match the measured-then-locked expectations.
    for r in rows:
        e = r["entry"]
        assert r["modelaudit"]["caught"] == e["modelaudit_expected"], (
            f"{e['file']}: ModelAudit live={r['modelaudit']['caught']} != "
            f"locked {e['modelaudit_expected']} (version drift or contamination?)"
        )

    # Fair invocation: ModelAudit catches the plain control, its dynamic sandbox test is
    # active (strongest config, not regex-only crippled), and it has no benign false positive.
    assert by_file["01_plain_chain.jinja"]["modelaudit"]["caught"] is True
    assert bench.modelaudit_sandbox_render_available(_MA) is True
    benign = [r for r in rows if not r["entry"]["malicious"]]
    assert not any(r["modelaudit"]["caught"] for r in benign)

    # Core claim: at least one obfuscation GlyphHound catches that even the strongest
    # ModelAudit misses (the concat-obfuscated, render-path-gated payloads).
    s = bench.summarize(rows)
    assert len(s["ma_misses_gh_catches"]) >= 1
