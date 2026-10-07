"""Offline tests for scanning several targets in one ``glyphhound scan A B C`` (roadmap step 1).

Each target is scanned on its own and reported under its own heading; the exit code is 1 if
any target gates CI, else 2 if any target could not be scanned, else 0. JSON is a list with
one report per target, SARIF one run listing every target as an artifact, and with a single
target every format is byte-identical to the single-target renderers.
"""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from jsonschema import Draft7Validator

from glyphhound.acquire import AcquireError
from glyphhound.cli import main
from glyphhound.report import (
    TargetResult,
    display_text,
    make_report,
    render_human,
    render_json,
    render_sarif,
    render_sarif_targets,
    targets_exit_code,
)
from glyphhound.report.json_report import dump_json
from glyphhound.scan import scan_source
from synthetic import build_gguf

ROOT = os.path.dirname(os.path.dirname(__file__))
MALICIOUS_PATH = os.path.join(ROOT, "fixtures", "malicious", "cve_2024_34359_marker.jinja")
BENIGN_PATH = os.path.join(ROOT, "fixtures", "benign", "Qwen__Qwen2.5-0.5B-Instruct-GGUF.jinja")
MALICIOUS = Path(MALICIOUS_PATH).read_text(encoding="utf-8")
SARIF_SCHEMA_PATH = os.path.join(ROOT, "schemas", "sarif-2.1.0.json")
ESC = "\x1b"
RLO = "\u202e"  # RIGHT-TO-LEFT OVERRIDE
CSI = "\x9b"  # C1 CONTROL SEQUENCE INTRODUCER
LINE_SEPARATOR = "\u2028"


@pytest.fixture(autouse=True)
def _no_home_ollama(tmp_path, monkeypatch):
    """Keep any Ollama lookup inside the test's temporary directory, never ~/.ollama."""
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "ollama"))


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    rc = main(["scan", *argv])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _missing(tmp_path) -> str:
    return str(tmp_path / "missing" / "template.jinja")


def _stdin(monkeypatch, data: bytes) -> None:
    """Feed ``data`` to the CLI as stdin bytes (the CLI reads ``sys.stdin.buffer``)."""
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(data), encoding="utf-8"))


def _sarif_errors(doc: dict) -> list:
    schema = json.loads(Path(SARIF_SCHEMA_PATH).read_text(encoding="utf-8"))
    return [(list(e.path), e.message) for e in Draft7Validator(schema).iter_errors(doc)]


# --------------------------------------------------------------------------- #
# One target: every format is exactly what it was
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fmt, render", [
    ("human", render_human), ("json", render_json), ("sarif", render_sarif),
])
@pytest.mark.parametrize("path", [MALICIOUS_PATH, BENIGN_PATH])
def test_one_target_output_is_unchanged(capsys, fmt, render, path):
    rc, out, _ = _run(capsys, path, "--format", fmt)
    report = scan_source(path)
    assert out == render(report)
    assert rc == report.exit_code


def test_a_repeated_target_is_scanned_once_with_single_target_output(capsys):
    rc, out, _ = _run(capsys, MALICIOUS_PATH, MALICIOUS_PATH, "--format", "json")
    assert rc == 1
    assert out == render_json(scan_source(MALICIOUS_PATH))


def test_one_unscannable_target_keeps_the_single_target_error(tmp_path, capsys):
    rc, out, err = _run(capsys, _missing(tmp_path))
    assert rc == 2
    assert out == ""
    assert err.startswith("glyphhound: could not determine")


# --------------------------------------------------------------------------- #
# Exit code across targets
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("kinds, expected", [
    (("benign", "benign"), 0),
    (("benign", "malicious"), 1),
    (("malicious", "benign"), 1),
    (("benign", "missing"), 2),
    (("missing", "missing"), 2),
    (("missing", "malicious"), 1),      # a gating finding outranks a failed target
    (("malicious", "missing", "benign"), 1),
])
def test_exit_code_across_targets(tmp_path, capsys, kinds, expected):
    paths = {"benign": BENIGN_PATH, "malicious": MALICIOUS_PATH}
    # Each missing target gets its own path: a repeated target would be scanned once.
    argv = [paths.get(k) or str(tmp_path / f"missing{i}" / "t.jinja") for i, k in enumerate(kinds)]
    for fmt in ("human", "json", "sarif"):
        rc, _, _ = _run(capsys, *argv, "--format", fmt)
        assert rc == expected, fmt


def test_targets_exit_code_of_no_failures_or_findings_is_zero():
    clean = TargetResult("a", report=make_report([]))
    assert targets_exit_code([clean, clean]) == 0
    assert targets_exit_code([clean, TargetResult("b", error="boom")]) == 2


# --------------------------------------------------------------------------- #
# Human: each target under its own heading
# --------------------------------------------------------------------------- #
def test_human_reports_each_target_under_its_own_heading(tmp_path, capsys):
    missing = _missing(tmp_path)
    rc, out, err = _run(capsys, MALICIOUS_PATH, missing, BENIGN_PATH)

    assert rc == 1
    expected = "\n".join([
        f"=== target: {MALICIOUS_PATH} ===\n{render_human(scan_source(MALICIOUS_PATH))}",
        f"=== target: {missing} ===\nerror: ",
    ])
    assert out.startswith(expected)
    assert f"=== target: {BENIGN_PATH} ===\n{render_human(scan_source(BENIGN_PATH))}" in out
    assert out.index(MALICIOUS_PATH) < out.index(missing) < out.index(BENIGN_PATH)
    assert out.endswith("overall: 3 target(s), 1 gating, 1 could not be scanned -> exit 1\n")
    # The failed target is also told on stderr, named.
    assert err.startswith(f"glyphhound: {missing}: could not determine")


def test_odd_inputs_among_targets_are_reported_not_crashed(tmp_path, capsys):
    empty = tmp_path / "empty.jinja"
    empty.write_bytes(b"")
    bad_utf8 = tmp_path / "bad.jinja"
    bad_utf8.write_bytes(b"{{ \xff\xfe }}")
    truncated = tmp_path / "truncated.gguf"
    truncated.write_bytes(build_gguf(chat_template=MALICIOUS)[:40])
    directory = tmp_path / "subdir"
    directory.mkdir()

    rc, out, err = _run(capsys, str(empty), str(bad_utf8), str(truncated), str(directory))

    assert rc == 2
    assert out.count("exit code: 2") == 3
    assert "summary: 0 finding(s)" in out  # the empty template is scanned and clean
    assert "overall: 4 target(s), 0 gating, 3 could not be scanned -> exit 2" in out
    assert "not a valid UTF-8 template file" in out
    assert "is not a file" in out
    assert len(err.splitlines()) == 3


def test_stdin_target_is_read_once_among_others(monkeypatch, capsys):
    _stdin(monkeypatch, MALICIOUS.encode("utf-8"))
    rc, out, _ = _run(capsys, "-", BENIGN_PATH, "-", "--format", "json")

    reports = json.loads(out)
    assert rc == 1
    assert [r["target"] for r in reports] == ["-", BENIGN_PATH]
    assert reports[0]["exit_code"] == 1


@pytest.mark.parametrize("others, expected", [
    ((BENIGN_PATH,), 2),
    ((BENIGN_PATH, MALICIOUS_PATH), 1),
])
def test_undecodable_stdin_among_targets_is_reported_not_crashed(monkeypatch, capsys,
                                                                   others, expected):
    _stdin(monkeypatch, b"{{ messages }}\xff\xfe")
    rc, out, err = _run(capsys, "-", *others, "--format", "json")

    reports = json.loads(out)
    assert rc == expected
    assert [r["target"] for r in reports] == ["-", *others]  # every target still reported
    assert reports[0]["exit_code"] == 2
    assert "stdin: template is not valid UTF-8" in reports[0]["error"]
    assert err.startswith("glyphhound: -: stdin: template is not valid UTF-8")


def test_undecodable_stdin_alone_exits_2(monkeypatch, capsys):
    _stdin(monkeypatch, b"\xff")
    rc, out, err = _run(capsys, "-")
    assert (rc, out) == (2, "")
    assert err.startswith("glyphhound: stdin: template is not valid UTF-8")


def test_options_apply_to_every_target(capsys):
    rc, out, _ = _run(capsys, MALICIOUS_PATH, BENIGN_PATH, "--threshold", "critical",
                      "--format", "json")
    assert rc == 1
    assert [r["summary"]["severity_threshold"] for r in json.loads(out)] == ["critical"] * 2


# --------------------------------------------------------------------------- #
# Values from the model or the command line cannot drive the terminal
# --------------------------------------------------------------------------- #
def test_display_text_escapes_non_printable_characters():
    assert display_text("plain name.jinja") == "plain name.jinja"
    assert display_text(f"{ESC}[31mred{RLO}\nnext") == "\\x1b[31mred\\u202e\\nnext"


def test_hostile_named_template_is_escaped_in_human_output(tmp_path, capsys):
    hostile = f"tool{ESC}]8;;https://evil.example{ESC}\\{RLO}\nexit code: 0"
    path = tmp_path / "model.gguf"
    path.write_bytes(build_gguf(chat_template="hi",
                                named_templates={f"tokenizer.chat_template.{hostile}": MALICIOUS}))

    for argv in ([str(path)], [str(path), BENIGN_PATH]):
        rc, out, _ = _run(capsys, *argv)
        assert rc == 1
        assert ESC not in out and RLO not in out
        assert "tokenizer.chat_template.tool\\x1b]8;;https://evil.example" in out
        assert "\\nexit code: 0" in out  # the forged line stays inside the name
        assert out.splitlines().count("exit code: 0") == len(argv) - 1  # only the benign target


def test_hostile_target_and_error_text_are_escaped(monkeypatch, capsys):
    def fail(ref, **_):
        raise AcquireError(f"bad header {ESC}[2J{RLO}")
    monkeypatch.setattr("glyphhound.cli.scan_source", fail)

    rc, out, err = _run(capsys, f"owner/{ESC}[31mname", "other/name", "--source", "hf")

    assert rc == 2
    assert ESC not in out + err and RLO not in out + err
    assert "=== target: owner/\\x1b[31mname ===" in out
    assert "error: bad header \\x1b[2J\\u202e" in out
    assert "glyphhound: owner/\\x1b[31mname: bad header \\x1b[2J\\u202e" in err

    rc, out, err = _run(capsys, "owner/name")
    assert (rc, out) == (2, "")
    assert err == "glyphhound: bad header \\x1b[2J\\u202e\n"


def test_dump_json_escapes_non_printable_and_keeps_readable_text():
    value = {"name": f"café {RLO}{CSI}{LINE_SEPARATOR}\U000e0001{ESC}"}
    text = dump_json(value)
    assert text == ('{\n  "name": "café \\u202e\\u009b\\u2028\\udb40\\udc01\\u001b"\n}\n')
    assert json.loads(text) == value


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_hostile_values_are_escaped_in_json_and_sarif(tmp_path, capsys, fmt):
    hostile = f"tool{RLO}{CSI}31m{LINE_SEPARATOR}"
    path = tmp_path / "model.gguf"
    path.write_bytes(build_gguf(chat_template="hi",
                                named_templates={f"tokenizer.chat_template.{hostile}": MALICIOUS}))
    missing = str(tmp_path / f"missing{RLO}{CSI}" / "t.jinja")  # a hostile target name

    for argv in ([str(path)], [str(path), missing]):
        rc, out, _ = _run(capsys, *argv, "--format", fmt)
        assert rc == 1
        assert not any(ch in out for ch in (RLO, CSI, LINE_SEPARATOR))
        assert "tool\\u202e\\u009b31m\\u2028" in out
        assert hostile in json.dumps(json.loads(out), ensure_ascii=False)  # the value reads back


# --------------------------------------------------------------------------- #
# JSON: a list with one report per target
# --------------------------------------------------------------------------- #
def test_json_is_a_list_with_one_report_per_target(tmp_path, capsys):
    missing = _missing(tmp_path)
    rc, out, _ = _run(capsys, MALICIOUS_PATH, missing, BENIGN_PATH, "--format", "json")

    reports = json.loads(out)
    assert rc == 1
    assert [r["target"] for r in reports] == [MALICIOUS_PATH, missing, BENIGN_PATH]
    for entry, path in ((reports[0], MALICIOUS_PATH), (reports[2], BENIGN_PATH)):
        assert entry == {"target": path, **json.loads(render_json(scan_source(path)))}
    failed = reports[1]
    assert failed["exit_code"] == 2
    assert failed["tool"] == "glyphhound"
    assert "could not determine" in failed["error"]
    assert "findings" not in failed


# --------------------------------------------------------------------------- #
# SARIF: one run listing every artifact
# --------------------------------------------------------------------------- #
def test_sarif_is_one_valid_run_listing_every_target(tmp_path, capsys):
    gguf = tmp_path / "model.gguf"
    gguf.write_bytes(build_gguf(chat_template="hi",
                                named_templates={"tokenizer.chat_template.tool_use": MALICIOUS}))
    missing = _missing(tmp_path)

    rc, out, _ = _run(capsys, MALICIOUS_PATH, str(gguf), missing, BENIGN_PATH,
                      "--format", "sarif")

    doc = json.loads(out)
    assert rc == 1
    assert _sarif_errors(doc) == []
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert [a["location"]["uri"] for a in run["artifacts"]] == \
        [Path(p).as_uri() for p in (MALICIOUS_PATH, gguf, missing, BENIGN_PATH)]

    by_artifact: dict[int, list] = {}
    for result in run["results"]:
        location = result["locations"][0]
        artifact = location["physicalLocation"]["artifactLocation"]
        assert run["artifacts"][artifact["index"]]["location"]["uri"] == artifact["uri"]
        by_artifact.setdefault(artifact["index"], []).append(location)
    assert set(by_artifact) == {0, 1}  # the benign and the missing target have no results
    assert len(by_artifact[0]) == len(scan_source(MALICIOUS_PATH).findings)
    assert {loc["logicalLocations"][0]["fullyQualifiedName"] for loc in by_artifact[0]} == \
        {"tokenizer.chat_template"}
    assert {loc["logicalLocations"][0]["fullyQualifiedName"] for loc in by_artifact[1]} == \
        {"tokenizer.chat_template.tool_use"}
    # A raw template file: the template line is a line of the artifact, so it is the region.
    assert all(loc["physicalLocation"]["region"]["startLine"] == loc["properties"]["templateLine"]
               for loc in by_artifact[0])
    # A GGUF: the template line is not a line of the binary file, so there is no region and
    # the line rides along as a property only.
    assert all("region" not in loc["physicalLocation"] for loc in by_artifact[1])
    assert all(loc["properties"]["templateLine"] >= 1 for loc in by_artifact[1])

    invocation, = run["invocations"]
    assert invocation["executionSuccessful"] is False
    notification, = invocation["toolExecutionNotifications"]
    assert notification["level"] == "error"
    assert "could not determine" in notification["message"]["text"]
    assert notification["locations"][0]["physicalLocation"]["artifactLocation"] == \
        {"uri": Path(missing).as_uri(), "index": 2}


def test_sarif_all_scanned_is_a_successful_invocation(capsys):
    rc, out, _ = _run(capsys, BENIGN_PATH, MALICIOUS_PATH, "--format", "sarif")
    run = json.loads(out)["runs"][0]
    assert rc == 1
    assert run["invocations"] == [{"executionSuccessful": True, "toolExecutionNotifications": []}]
    gating = [r["properties"]["gating"] for r in run["results"]]
    assert gating and all(gating)


def test_sarif_distinct_local_files_get_distinct_uris(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    names = ["my template\u00e9.jinja", "my%20template%C3%A9.jinja", "100%.jinja"]
    for name in names:
        (tmp_path / name).write_text(MALICIOUS, encoding="utf-8")

    rc, out, _ = _run(capsys, *names, "--format", "sarif")

    doc = json.loads(out)
    run = doc["runs"][0]
    assert rc == 1
    assert _sarif_errors(doc) == []
    # A literal "%" is encoded too, so a file named like another's encoding stays its own.
    assert [a["location"]["uri"] for a in run["artifacts"]] == [
        "my%20template%C3%A9.jinja", "my%2520template%25C3%25A9.jinja", "100%25.jinja"]
    per_artifact = len(scan_source(names[0]).findings)
    indexes = [r["locations"][0]["physicalLocation"]["artifactLocation"]["index"]
               for r in run["results"]]
    assert indexes == [0] * per_artifact + [1] * per_artifact + [2] * per_artifact


def test_sarif_target_uris_by_kind(tmp_path):
    absolute = str(tmp_path / "a b%.jinja")
    targets = {
        "https://host.example/m.gguf?rev=%41&x=a b": "https://host.example/m.gguf?rev=%41&x=a%20b",
        "https://host.example/100%.gguf?p=%zz&q=%": "https://host.example/100%25.gguf?p=%25zz&q=%25",
        absolute: Path(absolute).as_uri(),
        "owner/name": "owner/name",
        "llama3:8b": "llama3%3A8b",  # not read as a URI with scheme "llama3"
        "./sub/t.jinja": "sub/t.jinja",
        "-": "-",
    }
    results = [TargetResult(t, error="unscanned") for t in targets]

    doc = json.loads(render_sarif_targets(results))

    uris = [a["location"]["uri"] for a in doc["runs"][0]["artifacts"]]
    assert uris == list(targets.values())
    assert {urlsplit(u).scheme for u in uris} == {"", "file", "https"}
    assert _sarif_errors(doc) == []


@pytest.mark.skipif(os.name == "nt", reason="a backslash is a path separator on Windows")
def test_sarif_backslash_path_is_not_a_uri_scheme():
    doc = json.loads(render_sarif_targets([TargetResult("C:\\x\\a.jinja", error="unscanned")]))
    uri = doc["runs"][0]["artifacts"][0]["location"]["uri"]
    assert uri == "C%3A%5Cx%5Ca.jinja"
    assert urlsplit(uri).scheme == ""


@pytest.mark.skipif(os.name == "nt" or sys.getfilesystemencoding().lower() != "utf-8",
                    reason="needs a POSIX file system that decodes names with surrogateescape")
@pytest.mark.parametrize("fmt", ["human", "json", "sarif"])
def test_non_utf8_file_name_is_reported_in_every_format(tmp_path, monkeypatch, capsys, fmt):
    monkeypatch.chdir(tmp_path)
    name = os.fsdecode(b"bad\xff.jinja")  # holds a lone surrogate, as a POSIX argv would
    Path(name).write_text(MALICIOUS, encoding="utf-8")

    rc, out, _ = _run(capsys, name, BENIGN_PATH, "--format", fmt)

    assert rc == 1
    out.encode("utf-8")  # no lone surrogate reaches stdout
    if fmt == "sarif":
        doc = json.loads(out)
        assert _sarif_errors(doc) == []
        assert doc["runs"][0]["artifacts"][0] == {"location": {"uri": "bad%FF.jinja"}}
    elif fmt == "json":
        assert json.loads(out)[0]["target"] == name
    else:
        assert "=== target: bad\\udcff.jinja ===" in out
