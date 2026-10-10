"""Offline tests for ``glyphhound scan --format markdown`` (roadmap step 4).

The Markdown report carries the same content as the human report, for a pull request
comment. Every value taken from a template or model (a target, a template name, evidence,
an error message) sits in an inline code span, so Markdown, HTML, links and @mentions in it
show as plain text.
"""

from __future__ import annotations

import io
import os
import re
import sys
from pathlib import Path

import pytest

from glyphhound.analyze.models import CRITICAL, HIGH, Finding
from glyphhound.cli import main
from glyphhound.report import (
    TargetResult,
    display_text,
    make_report,
    md_code,
    render_human,
    render_markdown,
    render_markdown_targets,
)
from glyphhound.scan import scan_source
from synthetic import build_gguf

ROOT = os.path.dirname(os.path.dirname(__file__))
MALICIOUS_PATH = os.path.join(ROOT, "fixtures", "malicious", "cve_2024_34359_marker.jinja")
BENIGN_PATH = os.path.join(ROOT, "fixtures", "benign", "Qwen__Qwen2.5-0.5B-Instruct-GGUF.jinja")
MALICIOUS = Path(MALICIOUS_PATH).read_text(encoding="utf-8")
BENIGN = Path(BENIGN_PATH).read_text(encoding="utf-8")
ESC = "\x1b"
# Markdown, HTML, a link, an @mention, an issue reference, backtick runs, an ANSI escape and a
# line break that would start a forged heading, all in one value (no "/", so it can be a file
# name too).
HOSTILE = ("<img src=x onerror=alert(1)> **bold** [link](javascript:alert(1)) @admin #1 "
           f"``` `tick` {ESC}[31m\n# forged heading")


@pytest.fixture(autouse=True)
def _offline(tmp_path, monkeypatch):
    """No test here may touch the network or the developer's ~/.ollama."""
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "ollama"))

    def no_network(*args, **kwargs):
        raise AssertionError("a Markdown report must not make a network call")
    monkeypatch.setattr("urllib.request.urlopen", no_network)


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    rc = main(["scan", *argv])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _span_text(span: str) -> str:
    """What CommonMark shows for the inline code span ``span`` (asserting it is one span)."""
    match = re.fullmatch(r"(`+)(?!`)(.*?)(?<!`)\1", span, re.S)
    assert match, span
    fence, inner = match.groups()
    assert len(fence) not in {len(run) for run in re.findall("`+", inner)}
    assert "\n" not in inner
    if inner.startswith(" ") and inner.endswith(" ") and inner.strip(" "):
        inner = inner[1:-1]
    return inner


def _outside_code_spans(line: str) -> str:
    """``line`` with every inline code span cut out, as CommonMark finds them: a backtick run
    opens a span closed by the next run of the same length; a run with none is literal."""
    runs = list(re.finditer("`+", line))
    kept, pos, k = [], 0, 0
    while k < len(runs):
        opener = runs[k]
        closer = next((j for j in range(k + 1, len(runs))
                       if len(runs[j].group()) == len(opener.group())), None)
        if closer is None:
            k += 1
            continue
        kept.append(line[pos:opener.start()])
        pos, k = runs[closer].end(), closer + 1
    kept.append(line[pos:])
    return "".join(kept)


def _assert_only_in_code_spans(markdown: str) -> None:
    """No piece of :data:`HOSTILE` reaches the Markdown outside a code span, and its line
    break forges no line."""
    for line in markdown.splitlines():
        rest = _outside_code_spans(line)
        for piece in ("<img", "onerror", "**bold**", "[link]", "javascript:", "@admin", "#1",
                      "tick", "forged", ESC):
            assert piece not in rest, line
    assert "\n# forged heading" not in markdown
    assert ESC not in markdown


# --------------------------------------------------------------------------- #
# md_code: any value is one code span that shows exactly the value, escaped
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value, expected", [
    ("plain.jinja", "`plain.jinja`"),
    ("a`b", "``a`b``"),
    ("a``b`c", "```a``b`c```"),
    ("`x", "`` `x ``"),
    ("x`", "`` x` ``"),
    (" x", "`  x `"),
    ("x ", "` x  `"),
    ("   ", "`   `"),
    ("", "` `"),
    (f"{ESC}[31mred\nnext", "`\\x1b[31mred\\nnext`"),
])
def test_md_code_spans(value, expected):
    assert md_code(value) == expected


@pytest.mark.parametrize("value", [
    "plain.jinja", "a`b", "``", "`", "``` fenced ```", " `x` ", "<b>@admin</b>", HOSTILE,
    "trailing space ", " leading", "‮evil line", "\r\n\t", "x" * 10_000,
])
def test_md_code_shows_the_escaped_value_and_nothing_else(value):
    span = md_code(value)
    shown = _span_text(span)
    assert shown == display_text(value) or (value == "" and shown == " ")
    assert _outside_code_spans(span) == ""


# --------------------------------------------------------------------------- #
# Same content as the human report
# --------------------------------------------------------------------------- #
def test_a_gating_report_has_the_human_report_content():
    report = scan_source(MALICIOUS_PATH)
    markdown = render_markdown(report)
    human = render_human(report)

    assert markdown.startswith("## GlyphHound scan report\n\n")
    assert "- threshold: fail CI on reachable findings of severity >= high\n" in markdown
    assert "- exit code: 1\n" in markdown
    assert f"findings ({report.summary.total}):\n\n" in markdown
    assert ("- `GH-S001` CRITICAL reachable `tokenizer.chat_template:17` **GATES CI**\n"
            "  - dunder-attribute: `.__globals__`\n"
            "  - reason: attribute/subscript/|attr access to a Python dunder used for sandbox "
            "escape\n") in markdown
    assert markdown.count("**GATES CI**") == report.summary.gating
    assert markdown.endswith(human.splitlines()[-1] + "\n")
    for line in human.splitlines():
        if line.strip().startswith("reason:"):
            assert f"  - {line.strip()}" in markdown


def test_a_clean_report():
    markdown = render_markdown(scan_source(BENIGN_PATH))
    assert markdown == (
        "## GlyphHound scan report\n\n"
        "- threshold: fail CI on reachable findings of severity >= high\n"
        "- exit code: 0\n\n"
        "findings: 0 (nothing flagged at or above the detection threshold)\n\n"
        "summary: 0 finding(s), 0 reachable; critical=0 high=0; 0 gating -> exit 0\n"
    )


@pytest.mark.parametrize("reachable, label", [(False, "presence-only"), (None, "unanalyzed")])
def test_findings_that_do_not_gate_read_as_in_the_human_report(reachable, label):
    finding = Finding(rule_id="GH-S004", severity=HIGH, sink_kind="reflection-call",
                      template_name="tool_use", source_line=2, evidence="getattr",
                      reachable=reachable)
    markdown = render_markdown(make_report([finding]))
    assert (f"- `GH-S004` HIGH {label} `tokenizer.chat_template.tool_use:2`\n"
            "  - reflection-call: `getattr`\n"
            "  - reason: use of getattr/setattr reflection to reach attributes dynamically\n"
            ) in markdown
    assert "GATES CI" not in markdown
    assert "- exit code: 0\n" in markdown


def test_hostile_evidence_and_template_name_stay_in_code_spans():
    finding = Finding(rule_id="GH-S001", severity=CRITICAL, sink_kind="dunder-attribute",
                      template_name=HOSTILE, source_line=3, evidence=HOSTILE, reachable=True)
    markdown = render_markdown(make_report([finding]))
    _assert_only_in_code_spans(markdown)
    assert md_code(f"tokenizer.chat_template.{HOSTILE}:3") in markdown
    assert f"  - dunder-attribute: {md_code(HOSTILE)}\n" in markdown


def test_several_targets_have_their_own_headings_and_an_overall_line():
    results = [
        TargetResult("a.jinja", report=scan_source(MALICIOUS_PATH)),
        TargetResult("b.jinja", report=scan_source(BENIGN_PATH)),
        TargetResult(HOSTILE, error=f"cannot read {HOSTILE}"),
    ]
    markdown = render_markdown_targets(results)

    assert markdown.startswith(
        f"## target: `a.jinja`\n\n### GlyphHound scan report\n\n- threshold:")
    assert "## target: `b.jinja`\n\n### GlyphHound scan report\n" in markdown
    assert (f"## target: {md_code(HOSTILE)}\n\n"
            f"- error: {md_code('cannot read ' + HOSTILE)}\n- exit code: 2\n") in markdown
    assert markdown.endswith(
        "overall: 3 target(s), 1 gating, 1 could not be scanned -> exit 1\n")
    _assert_only_in_code_spans(markdown)


def test_a_target_with_an_empty_error_still_has_a_code_span():
    markdown = render_markdown_targets([TargetResult("x", error="")])
    assert "- error: ` `\n" in markdown


# --------------------------------------------------------------------------- #
# Through glyphhound scan
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path, expected_rc", [(MALICIOUS_PATH, 1), (BENIGN_PATH, 0)])
def test_scan_prints_markdown_with_the_same_exit_code(capsys, path, expected_rc):
    rc, out, err = _run(capsys, path, "--format", "markdown")
    assert out == render_markdown(scan_source(path))
    assert err == ""
    assert rc == expected_rc == main(["scan", path])


def test_scan_several_targets_in_markdown(capsys):
    rc, out, err = _run(capsys, MALICIOUS_PATH, BENIGN_PATH, "--format", "markdown")
    assert rc == 1
    assert err == ""
    assert out == render_markdown_targets([
        TargetResult(MALICIOUS_PATH, report=scan_source(MALICIOUS_PATH), template_file=True),
        TargetResult(BENIGN_PATH, report=scan_source(BENIGN_PATH), template_file=True),
    ])


def test_scan_stdin_with_a_hostile_template_name(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(MALICIOUS.encode("utf-8"))))
    rc, out, _ = _run(capsys, "-", "--template-name", HOSTILE, "--format", "markdown")
    assert rc == 1
    assert md_code(f"tokenizer.chat_template.{HOSTILE}:17") in out
    _assert_only_in_code_spans(out)


def test_scan_a_gguf_with_a_hostile_named_template(tmp_path, capsys):
    gguf = tmp_path / "model.gguf"
    gguf.write_bytes(build_gguf(
        chat_template=BENIGN, named_templates={f"tokenizer.chat_template.{HOSTILE}": MALICIOUS}))
    rc, out, _ = _run(capsys, str(gguf), "--format", "markdown")
    assert rc == 1
    assert md_code(f"tokenizer.chat_template.{HOSTILE}:17") in out
    _assert_only_in_code_spans(out)


def test_a_hostile_target_that_cannot_be_scanned_exits_2(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc, out, err = _run(capsys, BENIGN_PATH, HOSTILE, "--format", "markdown")
    assert rc == 2
    assert f"## target: {md_code(HOSTILE)}\n\n- error: `" in out
    assert out.endswith("overall: 2 target(s), 0 gating, 1 could not be scanned -> exit 2\n")
    _assert_only_in_code_spans(out)
    assert ESC not in err


def test_a_single_target_that_cannot_be_scanned_prints_no_report(tmp_path, capsys):
    rc, out, err = _run(capsys, str(tmp_path / "missing.gguf"), "--format", "markdown")
    assert rc == 2
    assert out == ""
    assert "missing.gguf" in err


@pytest.mark.skipif(sys.platform == "win32", reason="the file name is not valid on Windows")
def test_a_directory_with_a_hostile_file_name(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / f"{HOSTILE}.jinja").write_text(MALICIOUS, encoding="utf-8")
    rc, out, _ = _run(capsys, "models", "--format", "markdown")
    assert rc == 1
    assert f"## target: {md_code(os.path.join('models', HOSTILE + '.jinja'))}\n" in out
    _assert_only_in_code_spans(out)


def test_an_empty_template_file_is_clean_in_markdown(tmp_path, capsys):
    empty = tmp_path / "empty.jinja"
    empty.write_bytes(b"")
    rc, out, _ = _run(capsys, str(empty), "--format", "markdown")
    assert rc == 0
    assert "findings: 0 (nothing flagged" in out


def test_output_writes_markdown_and_prints_the_human_report(tmp_path, capsys):
    out_file = tmp_path / "comment.md"
    rc, out, err = _run(capsys, MALICIOUS_PATH, BENIGN_PATH, "--format", "markdown",
                        "--output", str(out_file))
    assert rc == 1
    assert err == ""
    results = [
        TargetResult(MALICIOUS_PATH, report=scan_source(MALICIOUS_PATH), template_file=True),
        TargetResult(BENIGN_PATH, report=scan_source(BENIGN_PATH), template_file=True),
    ]
    assert out_file.read_text(encoding="utf-8") == render_markdown_targets(results)
    assert out.startswith(f"=== target: {MALICIOUS_PATH} ===\n{render_human(results[0].report)}")

