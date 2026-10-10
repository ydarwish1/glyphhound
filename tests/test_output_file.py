"""Offline tests for ``glyphhound scan --output FILE`` (roadmap step 3).

``--output FILE`` writes the chosen ``--format`` to FILE and still prints the human report to
stdout, so one CI run can upload SARIF and show a readable log. The exit code does not change;
FILE that is an existing directory (or one of the targets) exits 2 before anything is scanned.
"""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from glyphhound.cli import main
from glyphhound.report import (
    render_human,
    render_json,
    render_sarif,
)
from glyphhound.scan import scan_source

ROOT = os.path.dirname(os.path.dirname(__file__))
MALICIOUS_PATH = os.path.join(ROOT, "fixtures", "malicious", "cve_2024_34359_marker.jinja")
BENIGN_PATH = os.path.join(ROOT, "fixtures", "benign", "Qwen__Qwen2.5-0.5B-Instruct-GGUF.jinja")
MALICIOUS = Path(MALICIOUS_PATH).read_text(encoding="utf-8")
SARIF_SCHEMA_PATH = os.path.join(ROOT, "schemas", "sarif-2.1.0.json")
ESC = "\x1b"

needs_posix_permissions = pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="needs POSIX permissions that apply to the current user",
)


@pytest.fixture(autouse=True)
def _no_home_ollama(tmp_path, monkeypatch):
    """Keep any Ollama lookup inside the test's temporary directory, never ~/.ollama."""
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "ollama"))


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    rc = main(["scan", *argv])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _sarif_errors(doc: dict) -> list:
    schema = json.loads(Path(SARIF_SCHEMA_PATH).read_text(encoding="utf-8"))
    return [(list(e.path), e.message) for e in Draft7Validator(schema).iter_errors(doc)]


# --------------------------------------------------------------------------- #
# One target: FILE holds --format, stdout the human report, the exit code is the same
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fmt, render", [
    ("human", render_human), ("json", render_json), ("sarif", render_sarif),
])
@pytest.mark.parametrize("path", [MALICIOUS_PATH, BENIGN_PATH])
def test_one_target_writes_the_format_and_prints_human(tmp_path, capsys, fmt, render, path):
    out_file = tmp_path / f"report.{fmt}"
    rc, out, err = _run(capsys, path, "--format", fmt, "--output", str(out_file))

    report = scan_source(path)
    assert out_file.read_text(encoding="utf-8") == render(report)
    assert out == render_human(report)
    assert err == ""
    assert rc == report.exit_code == main(["scan", path, "--format", fmt])


def test_sarif_file_is_schema_valid(tmp_path, capsys):
    out_file = tmp_path / "glyphhound.sarif"
    rc, out, _ = _run(capsys, MALICIOUS_PATH, "--format", "sarif", "--output", str(out_file))
    assert rc == 1
    doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert _sarif_errors(doc) == []
    assert doc["runs"][0]["results"]
    assert "summary:" in out


def test_an_existing_file_is_replaced(tmp_path, capsys):
    out_file = tmp_path / "report.json"
    out_file.write_text("stale " * 10_000, encoding="utf-8")
    rc, _, _ = _run(capsys, BENIGN_PATH, "--format", "json", "--output", str(out_file))
    assert rc == 0
    assert out_file.read_text(encoding="utf-8") == render_json(scan_source(BENIGN_PATH))


def test_stdin_template_is_written(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(MALICIOUS.encode("utf-8"))))
    out_file = tmp_path / "report.json"
    rc, out, _ = _run(capsys, "-", "--format", "json", "--output", str(out_file))
    assert rc == 1
    assert json.loads(out_file.read_text(encoding="utf-8"))["exit_code"] == 1
    assert "-> exit 1" in out


def test_a_target_that_cannot_be_scanned_writes_nothing(tmp_path, capsys):
    out_file = tmp_path / "report.sarif"
    missing = str(tmp_path / "missing" / "t.jinja")
    rc, out, err = _run(capsys, missing, "--format", "sarif", "--output", str(out_file))
    assert rc == 2
    assert out == ""
    assert err.startswith("glyphhound: could not determine")
    assert not out_file.exists()


# --------------------------------------------------------------------------- #
# Several targets and directories
# --------------------------------------------------------------------------- #
def test_several_targets_write_the_list_and_print_every_heading(tmp_path, capsys):
    missing = str(tmp_path / "missing" / "t.jinja")
    out_file = tmp_path / "report.json"
    argv = [MALICIOUS_PATH, missing, BENIGN_PATH]
    rc, out, _ = _run(capsys, *argv, "--format", "json", "--output", str(out_file))
    expected_rc, expected_json, _ = _run(capsys, *argv, "--format", "json")
    _, expected_human, _ = _run(capsys, *argv)

    assert rc == expected_rc == 1
    assert out_file.read_text(encoding="utf-8") == expected_json
    assert out == expected_human
    assert [t["exit_code"] for t in json.loads(expected_json)] == [1, 2, 0]


def test_a_directory_scan_writes_sarif(tmp_path, capsys):
    models = tmp_path / "models"
    (models / "sub").mkdir(parents=True)
    (models / "sub" / "evil.jinja").write_text(MALICIOUS, encoding="utf-8")
    (models / "ok.jinja").write_text("{{ messages[0].content }}", encoding="utf-8")
    out_file = tmp_path / "report.sarif"
    rc, out, _ = _run(capsys, str(models), "--format", "sarif", "--output", str(out_file))

    assert rc == 1
    doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert _sarif_errors(doc) == []
    assert len(doc["runs"][0]["artifacts"]) == 2
    assert "overall: 2 target(s), 1 gating, 0 could not be scanned -> exit 1" in out


def test_several_targets_human_format_matches_stdout(tmp_path, capsys):
    out_file = tmp_path / "report.txt"
    rc, out, _ = _run(capsys, MALICIOUS_PATH, BENIGN_PATH, "--output", str(out_file))
    assert rc == 1
    assert out_file.read_text(encoding="utf-8") == out
    assert out.startswith(f"=== target: {MALICIOUS_PATH} ===")


# --------------------------------------------------------------------------- #
# FILE that must not or cannot be written
# --------------------------------------------------------------------------- #
def test_an_existing_directory_exits_2_before_scanning(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(MALICIOUS.encode("utf-8"))))
    rc, out, err = _run(capsys, "-", "--format", "sarif", "--output", str(tmp_path))
    assert rc == 2
    assert out == ""
    assert err == f"glyphhound: --output {tmp_path}: is a directory\n"
    assert sys.stdin.read() == MALICIOUS  # stdin was never read: nothing was scanned


def test_a_symlink_to_a_directory_exits_2(tmp_path, capsys):
    (tmp_path / "out").mkdir()
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "out")
    rc, out, err = _run(capsys, MALICIOUS_PATH, BENIGN_PATH, "--output", str(link))
    assert rc == 2
    assert out == ""
    assert err.endswith(": is a directory\n")
    assert list((tmp_path / "out").iterdir()) == []


def test_a_directory_name_with_escape_codes_is_shown_escaped(tmp_path, capsys):
    hostile = tmp_path / f"out{ESC}[31m"
    hostile.mkdir()
    rc, _, err = _run(capsys, BENIGN_PATH, "--output", str(hostile))
    assert rc == 2
    assert ESC not in err
    assert "out\\x1b[31m: is a directory" in err


def test_a_typed_target_is_never_overwritten(tmp_path, capsys):
    template = tmp_path / "t.jinja"
    template.write_text(MALICIOUS, encoding="utf-8")
    rc, out, err = _run(capsys, str(template), "--format", "json", "--output", str(template))
    assert rc == 2
    assert out == ""
    assert err.endswith(": is one of the scan targets\n")
    assert template.read_text(encoding="utf-8") == MALICIOUS


def test_a_target_found_in_a_directory_is_never_overwritten(tmp_path, capsys):
    models = tmp_path / "models"
    models.mkdir()
    template = models / "chat_template.jinja"
    template.write_text(MALICIOUS, encoding="utf-8")
    link = tmp_path / "report.jinja"
    link.symlink_to(template)  # FILE spelled differently: a symlink to the found template
    rc, _, err = _run(capsys, str(models), "--format", "sarif", "--output", str(link))
    assert rc == 2
    assert err.endswith(": is one of the scan targets\n")
    assert template.read_text(encoding="utf-8") == MALICIOUS


def test_file_written_inside_the_scanned_directory_stops_the_next_run(tmp_path, capsys):
    models = tmp_path / "models"
    models.mkdir()
    (models / "chat_template.jinja").write_text(MALICIOUS, encoding="utf-8")
    out_file = models / "report.jinja"
    argv = [str(models), "--output", str(out_file)]

    first_rc, _, _ = _run(capsys, *argv)
    first_report = out_file.read_text(encoding="utf-8")
    rc, out, err = _run(capsys, *argv)

    assert first_rc == 1
    assert rc == 2
    assert out == ""
    assert err == f"glyphhound: --output {out_file}: is one of the scan targets\n"
    assert out_file.read_text(encoding="utf-8") == first_report


def test_a_missing_parent_directory_exits_2_after_printing(tmp_path, capsys):
    out_file = tmp_path / "missing" / "report.sarif"
    rc, out, err = _run(capsys, BENIGN_PATH, "--format", "sarif", "--output", str(out_file))
    assert rc == 2
    assert out == render_human(scan_source(BENIGN_PATH))
    assert err == f"glyphhound: --output {out_file}: No such file or directory\n"
    assert not out_file.exists()


def test_a_gating_finding_still_exits_1_when_file_cannot_be_written(tmp_path, capsys):
    out_file = tmp_path / "missing" / "report.sarif"
    rc, out, err = _run(capsys, MALICIOUS_PATH, BENIGN_PATH, "--output", str(out_file))
    assert rc == 1
    assert "-> exit 1" in out
    assert err == f"glyphhound: --output {out_file}: No such file or directory\n"


@needs_posix_permissions
def test_a_file_without_write_permission_exits_2(tmp_path, capsys):
    out_file = tmp_path / "report.json"
    out_file.write_text("old", encoding="utf-8")
    out_file.chmod(0o444)
    rc, out, err = _run(capsys, BENIGN_PATH, "--format", "json", "--output", str(out_file))
    assert rc == 2
    assert "summary: 0 finding(s)" in out
    assert err == f"glyphhound: --output {out_file}: Permission denied\n"
    assert out_file.read_text(encoding="utf-8") == "old"
