"""Offline tests for scanning a local directory with ``glyphhound scan DIR`` (roadmap step 2).

A directory stands for every ``*.jinja``, ``chat_template.jinja``, ``tokenizer_config.json``
and ``*.gguf`` file under it, each scanned and reported as a target of its own. Symlinks out
of the directory are not followed; a matching file that cannot be read or parsed is
reported and exits 2, and a directory with no matching file exits 2.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from glyphhound import scan
from glyphhound.acquire import (
    AcquireError,
    TemplateNotFoundError,
    hf_source,
    read_tokenizer_config_file,
)
from glyphhound.cli import main
from glyphhound.report import render_human
from glyphhound.scan import ScanError, ScanTarget, find_template_files, scan_source
from synthetic import build_gguf

ROOT = os.path.dirname(os.path.dirname(__file__))
MALICIOUS_PATH = os.path.join(ROOT, "fixtures", "malicious", "cve_2024_34359_marker.jinja")
BENIGN_PATH = os.path.join(ROOT, "fixtures", "benign", "Qwen__Qwen2.5-0.5B-Instruct-GGUF.jinja")
MALICIOUS = Path(MALICIOUS_PATH).read_text(encoding="utf-8")
BENIGN = Path(BENIGN_PATH).read_text(encoding="utf-8")
SARIF_SCHEMA_PATH = os.path.join(ROOT, "schemas", "sarif-2.1.0.json")
ESC = "\x1b"

needs_posix_permissions = pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="needs POSIX permissions that apply to the current user",
)


@pytest.fixture(autouse=True)
def _offline(tmp_path, monkeypatch):
    """No test here may touch the network or the developer's ~/.ollama."""
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "ollama"))

    def no_network(*args, **kwargs):
        raise AssertionError("a directory scan must not make a network call")
    monkeypatch.setattr("urllib.request.urlopen", no_network)


@pytest.fixture
def scan_dir(tmp_path, monkeypatch):
    """An empty directory to scan, with the working directory at its parent so targets
    are short relative paths (``models/...``)."""
    monkeypatch.chdir(tmp_path)
    directory = tmp_path / "models"
    directory.mkdir()
    return directory


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    rc = main(["scan", *argv])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _write(path: Path, data: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)
    return path


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")


def _json_targets(capsys, *argv: str) -> tuple[int, dict]:
    rc, out, _ = _run(capsys, *argv, "--format", "json")
    return rc, {entry["target"]: entry for entry in json.loads(out)}


# --------------------------------------------------------------------------- #
# Which files a directory scan finds
# --------------------------------------------------------------------------- #
def test_finds_every_matching_file_recursively_in_sorted_order(scan_dir):
    for rel in ("b/chat_template.jinja", "a/x.jinja", "tokenizer_config.json", "m.gguf",
                "z/deeper/UPPER.JINJA", "Q4.GGUF"):
        _write(scan_dir / rel, b"")
    for rel in ("README.md", "config.json", "x.jinja.bak", "tokenizer_config.json.orig",
                "generation_config.json", "model.safetensors"):
        _write(scan_dir / rel, b"")

    found = find_template_files("models")

    assert [(t.ref, t.source, t.error) for t in found] == [
        (os.path.join("models", "Q4.GGUF"), "gguf", None),
        (os.path.join("models", "m.gguf"), "gguf", None),
        (os.path.join("models", "tokenizer_config.json"), "tokenizer-config", None),
        (os.path.join("models", "a", "x.jinja"), "file", None),
        (os.path.join("models", "b", "chat_template.jinja"), "file", None),
        (os.path.join("models", "z", "deeper", "UPPER.JINJA"), "file", None),
    ]


def test_a_directory_named_like_a_template_is_entered_not_read(scan_dir):
    _write(scan_dir / "trap.jinja" / "inner.jinja", MALICIOUS)
    assert [t.ref for t in find_template_files("models")] == [
        os.path.join("models", "trap.jinja", "inner.jinja"),
    ]


def test_each_found_file_is_a_target_and_a_finding_anywhere_gates(scan_dir, capsys):
    _write(scan_dir / "chat_template.jinja", BENIGN)
    _write(scan_dir / "nested" / "deep" / "evil.jinja", MALICIOUS)

    rc, out, err = _run(capsys, "models")

    evil = os.path.join("models", "nested", "deep", "evil.jinja")
    assert rc == 1
    assert err == ""
    assert f"=== target: {evil} ===\n{render_human(scan_source(MALICIOUS_PATH))}" in out
    assert out.index("chat_template.jinja ===") < out.index("evil.jinja ===")
    assert out.endswith("overall: 2 target(s), 1 gating, 0 could not be scanned -> exit 1\n")


def test_a_clean_directory_exits_0(scan_dir, capsys):
    _write(scan_dir / "chat_template.jinja", BENIGN)
    _write(scan_dir / "tokenizer_config.json", json.dumps({"chat_template": BENIGN}))
    _write(scan_dir / "model.gguf", build_gguf(chat_template=BENIGN))
    rc, out, _ = _run(capsys, "models")
    assert rc == 0
    assert "overall: 3 target(s), 0 gating, 0 could not be scanned -> exit 0" in out


def test_a_directory_with_one_file_still_names_it(scan_dir, capsys):
    _write(scan_dir / "chat_template.jinja", MALICIOUS)
    rc, out, _ = _run(capsys, "models")
    assert rc == 1
    assert out.startswith(f"=== target: {os.path.join('models', 'chat_template.jinja')} ===\n")


@pytest.mark.parametrize("name", ["model.gguf", "MODEL.GGUF"])
def test_a_malicious_gguf_in_a_directory_gates(scan_dir, capsys, name):
    named = {"tokenizer.chat_template.tool_use": MALICIOUS}
    _write(scan_dir / "quants" / name, build_gguf(chat_template=BENIGN, named_templates=named))
    rc, targets = _json_targets(capsys, "models")
    assert rc == 1
    report = targets[os.path.join("models", "quants", name)]
    assert {f["template_name"] for f in report["findings"]} == {"tool_use"}


# --------------------------------------------------------------------------- #
# tokenizer_config.json is read as a config, not as a raw template
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("chat_template, template_name", [
    (MALICIOUS, None),
    ([{"name": "default", "template": BENIGN}, {"name": "tool_use", "template": MALICIOUS}],
     "tool_use"),
])
def test_a_malicious_tokenizer_config_gates(scan_dir, capsys, chat_template, template_name):
    _write(scan_dir / "tokenizer_config.json",
           json.dumps({"model_max_length": 4096, "chat_template": chat_template}, indent=2))
    rc, targets = _json_targets(capsys, "models")
    assert rc == 1
    findings = targets[os.path.join("models", "tokenizer_config.json")]["findings"]
    assert findings and {f["template_name"] for f in findings} == {template_name}


@pytest.mark.parametrize("config", [{"model_max_length": 4096}, {"chat_template": None}])
def test_a_tokenizer_config_without_a_template_has_nothing_to_scan(scan_dir, capsys, config):
    # Newer repos keep the template in chat_template.jinja, scanned as its own target.
    _write(scan_dir / "tokenizer_config.json", json.dumps(config))
    _write(scan_dir / "chat_template.jinja", MALICIOUS)
    rc, targets = _json_targets(capsys, "models")
    assert rc == 1
    config_report = targets[os.path.join("models", "tokenizer_config.json")]
    assert config_report["exit_code"] == 0 and config_report["findings"] == []
    assert targets[os.path.join("models", "chat_template.jinja")]["exit_code"] == 1


@pytest.mark.parametrize("files", [
    {"tokenizer_config.json": {"model_max_length": 4096}},
    {"tokenizer_config.json": {"chat_template": None}},
    # A multimodal repo's chat_template.json is not read; the config alone has no template.
    {"tokenizer_config.json": {"model_max_length": 4096},
     "chat_template.json": {"chat_template": MALICIOUS}},
    # chat_template.jinja in another folder is not the one beside the config.
    {"tokenizer_config.json": {}, "other/tokenizer_config.json": {"model_max_length": 1}},
])
def test_a_directory_that_analyzes_no_template_exits_2(scan_dir, capsys, files):
    for rel, config in files.items():
        _write(scan_dir / rel, json.dumps(config))

    rc, out, err = _run(capsys, "models")

    assert rc == 2
    assert "no chat_template in tokenizer_config.json and no chat_template.jinja beside it" in out
    assert "0 gating" in out and err


def test_a_template_less_config_needs_chat_template_jinja_beside_it(scan_dir, capsys):
    _write(scan_dir / "tokenizer_config.json", json.dumps({"model_max_length": 4096}))
    _write(scan_dir / "sub" / "chat_template.jinja", BENIGN)
    rc, targets = _json_targets(capsys, "models")
    assert rc == 2
    assert targets[os.path.join("models", "tokenizer_config.json")]["exit_code"] == 2
    assert targets[os.path.join("models", "sub", "chat_template.jinja")]["exit_code"] == 0


def test_read_tokenizer_config_file_without_a_template(tmp_path):
    path = _write(tmp_path / "tokenizer_config.json", json.dumps({"model_max_length": 4096}))
    with pytest.raises(TemplateNotFoundError, match="no chat_template"):
        read_tokenizer_config_file(str(path))
    _write(tmp_path / "chat_template.jinja", BENIGN)
    assert read_tokenizer_config_file(str(path)).templates == ()


def test_read_tokenizer_config_file_reads_every_template(tmp_path):
    path = _write(tmp_path / "tokenizer_config.json", json.dumps({"chat_template": [
        {"name": "tool_use", "template": MALICIOUS}, {"template": BENIGN},
    ]}))
    raw = read_tokenizer_config_file(str(path))
    assert [(t.name, t.text) for t in raw.templates] == [(None, BENIGN), ("tool_use", MALICIOUS)]
    assert raw.source_ref == str(path)


@pytest.mark.parametrize("data, message", [
    (b"", "not valid JSON"),
    (b"{\"chat_template\": ", "not valid JSON"),
    (b"\xef\xbb\xbf{}", "not valid JSON"),                  # a UTF-8 BOM, as transformers
    (b"{\"chat_template\": \"\xff\xfe\"}", "not valid UTF-8"),
    (b"[" * 200_000 + b"]" * 200_000, "not valid JSON"),    # too deep to parse
    (b"[\"chat_template\"]", "not a JSON object"),
    (b"{\"chat_template\": 42}", "neither a string nor a list"),
    (b"{\"chat_template\": [\"{{ x }}\"]}", "neither a string nor a list"),
    (b"{\"chat_template\": [{\"name\": \"x\", \"template\": 7}]}", "neither a string nor a list"),
])
def test_an_unparseable_tokenizer_config_is_reported_and_exits_2(scan_dir, capsys, data,
                                                                   message):
    _write(scan_dir / "tokenizer_config.json", data)
    _write(scan_dir / "chat_template.jinja", BENIGN)

    rc, out, err = _run(capsys, "models")

    assert rc == 2
    assert message in out and message in err
    assert "overall: 2 target(s), 0 gating, 1 could not be scanned -> exit 2" in out
    with pytest.raises(AcquireError, match=message):
        read_tokenizer_config_file(str(scan_dir / "tokenizer_config.json"))


def test_an_oversized_tokenizer_config_is_reported_not_read(scan_dir, capsys, monkeypatch):
    monkeypatch.setattr(hf_source, "_HF_SOURCE_MAX_BYTES", 64)
    _write(scan_dir / "tokenizer_config.json",
           json.dumps({"pad": " " * 64, "chat_template": MALICIOUS}))
    rc, out, _ = _run(capsys, "models")
    assert rc == 2
    assert "exceeds the 64-byte cap" in out


# --------------------------------------------------------------------------- #
# Nothing matching, nothing readable: exit 2, never skipped
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("files", [(), ("README.md", "config.json", "sub/notes.txt")])
@pytest.mark.parametrize("fmt", ["human", "json", "sarif"])
def test_a_directory_with_no_matching_file_exits_2_saying_so(scan_dir, capsys, files, fmt):
    for rel in files:
        _write(scan_dir / rel, b"{{ ''.__class__ }}")

    rc, out, err = _run(capsys, "models", "--format", fmt)

    assert rc == 2
    assert "no *.jinja, tokenizer_config.json or *.gguf file under it" in err
    assert "no *.jinja, tokenizer_config.json or *.gguf file under it" in out
    with pytest.raises(ScanError, match="no \\*.jinja"):
        find_template_files("models")


def test_an_empty_directory_among_other_targets_is_reported(scan_dir, capsys):
    rc, targets = _json_targets(capsys, "models", MALICIOUS_PATH)
    assert rc == 1  # a gating finding outranks a failed target
    assert targets["models"]["exit_code"] == 2
    assert "no *.jinja" in targets["models"]["error"]


@pytest.mark.parametrize("rel, data, message", [
    ("bad.jinja", b"{{ \xff\xfe }}", "not a valid UTF-8 template file"),
    ("broken.jinja", b"{% if %}", ""),
    ("truncated.gguf", build_gguf(chat_template=MALICIOUS)[:40], ""),
    ("not-really.gguf", b"{{ ''.__class__ }}", ""),
    ("no-template.gguf", build_gguf(include_template=False), ""),
])
def test_an_unreadable_match_is_reported_while_the_rest_are_scanned(scan_dir, capsys, rel,
                                                                     data, message):
    _write(scan_dir / rel, data)
    _write(scan_dir / "ok.jinja", BENIGN)

    rc, targets = _json_targets(capsys, "models")

    assert rc == 2
    failed = targets[os.path.join("models", rel)]
    assert failed["exit_code"] == 2 and message in failed["error"]
    assert targets[os.path.join("models", "ok.jinja")]["exit_code"] == 0


def test_an_empty_template_file_is_scanned_and_clean(scan_dir, capsys):
    _write(scan_dir / "empty.jinja", b"")
    rc, out, _ = _run(capsys, "models")
    assert rc == 0
    assert "summary: 0 finding(s)" in out


@needs_posix_permissions
def test_a_file_without_read_permission_is_reported(scan_dir, capsys):
    locked = _write(scan_dir / "locked.jinja", MALICIOUS)
    locked.chmod(0)
    rc, out, err = _run(capsys, "models")
    assert rc == 2
    assert "locked.jinja" in err
    assert "overall: 1 target(s), 0 gating, 1 could not be scanned -> exit 2" in out


@needs_posix_permissions
def test_a_subdirectory_that_cannot_be_listed_is_reported(scan_dir, capsys):
    _write(scan_dir / "ok.jinja", BENIGN)
    hidden = scan_dir / "hidden"
    _write(hidden / "evil.jinja", MALICIOUS)
    hidden.chmod(0)
    try:
        rc, targets = _json_targets(capsys, "models")
    finally:
        hidden.chmod(0o755)
    assert rc == 2
    assert "cannot list directory" in targets[os.path.join("models", "hidden")]["error"]
    assert targets[os.path.join("models", "ok.jinja")]["exit_code"] == 0


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_named_pipe_with_a_matching_name_is_reported_not_opened(scan_dir, capsys):
    os.mkfifo(scan_dir / "pipe.jinja")  # opening it would block the scan forever
    rc, out, _ = _run(capsys, "models")
    assert rc == 2
    assert "not a regular file" in out


# --------------------------------------------------------------------------- #
# Symlinks
# --------------------------------------------------------------------------- #
def test_a_file_symlink_out_of_the_directory_is_reported_not_followed(scan_dir, tmp_path,
                                                                       capsys):
    outside = _write(tmp_path / "outside" / "evil.jinja", MALICIOUS)
    _symlink(scan_dir / "link.jinja", outside)

    rc, targets = _json_targets(capsys, "models")

    assert rc == 2  # reported, and the malicious file behind it is never read
    link = targets[os.path.join("models", "link.jinja")]
    assert "symlink out of the scanned directory; not followed" in link["error"]


def test_a_relative_symlink_escaping_with_dotdot_is_not_followed(scan_dir, tmp_path, capsys):
    _write(tmp_path / "evil.jinja", MALICIOUS)
    _symlink(scan_dir / "up.jinja", Path("..") / "evil.jinja")
    rc, out, _ = _run(capsys, "models")
    assert rc == 2
    assert "not followed" in out


def test_a_file_symlink_inside_the_directory_is_scanned(scan_dir, capsys):
    real = _write(scan_dir / "real" / "template.txt", MALICIOUS)
    _symlink(scan_dir / "alias.jinja", real)
    rc, targets = _json_targets(capsys, "models")
    assert rc == 1
    assert targets[os.path.join("models", "alias.jinja")]["exit_code"] == 1


def test_a_directory_symlink_out_of_the_directory_is_reported_not_entered(scan_dir, tmp_path,
                                                                          capsys):
    _write(tmp_path / "outside" / "evil.jinja", MALICIOUS)
    _symlink(scan_dir / "linked", tmp_path / "outside")
    _write(scan_dir / "ok.jinja", BENIGN)

    rc, targets = _json_targets(capsys, "models")

    assert rc == 2  # reported, and the malicious file behind it is never read
    assert list(targets) == [os.path.join("models", "linked"), os.path.join("models", "ok.jinja")]
    assert targets[os.path.join("models", "linked")]["error"] == (
        "a directory symlink out of the scanned directory; not entered"
    )


def test_a_directory_symlink_inside_the_directory_is_walked_once(scan_dir, capsys):
    _write(scan_dir / "real" / "evil.jinja", MALICIOUS)
    _symlink(scan_dir / "alias", scan_dir / "real")
    rc, targets = _json_targets(capsys, "models")
    assert rc == 1
    assert list(targets) == [os.path.join("models", "real", "evil.jinja")]


def test_a_broken_or_looping_symlink_is_reported(scan_dir, capsys):
    _symlink(scan_dir / "dangling.jinja", scan_dir / "missing.jinja")
    _symlink(scan_dir / "loop.gguf", scan_dir / "loop.gguf")
    rc, targets = _json_targets(capsys, "models")
    assert rc == 2
    assert "cannot read" in targets[os.path.join("models", "dangling.jinja")]["error"]
    assert targets[os.path.join("models", "loop.gguf")]["exit_code"] == 2


def test_the_scanned_directory_may_itself_be_a_symlink(scan_dir, tmp_path, capsys):
    _write(scan_dir / "chat_template.jinja", MALICIOUS)
    _symlink(tmp_path / "alias", scan_dir)
    rc, targets = _json_targets(capsys, "alias")
    assert rc == 1
    assert list(targets) == [os.path.join("alias", "chat_template.jinja")]


# --------------------------------------------------------------------------- #
# Several refs, options, and the formats
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("typed", [
    os.path.join("models", "chat_template.jinja"),
    os.path.join(".", "models", "chat_template.jinja"),
    os.path.join("models", "sub", "..", "chat_template.jinja"),
])
@pytest.mark.parametrize("typed_first", [True, False])
def test_a_file_typed_and_found_in_a_directory_is_scanned_once(scan_dir, capsys, typed,
                                                               typed_first):
    _write(scan_dir / "chat_template.jinja", MALICIOUS)
    (scan_dir / "sub").mkdir()
    argv = [typed, "models"] if typed_first else ["models", typed]
    rc, out, _ = _run(capsys, *argv)
    assert rc == 1
    assert out.count("=== target:") == 1


@pytest.mark.parametrize("typed_first", [True, False])
def test_a_typed_tokenizer_config_in_a_scanned_directory_is_read_as_a_config(scan_dir, capsys,
                                                                              typed_first):
    config = json.dumps({"chat_template": [{"name": "tool_use", "template": MALICIOUS}]})
    _write(scan_dir / "tokenizer_config.json", config)
    typed = os.path.join(".", "models", "tokenizer_config.json")
    argv = [typed, "models"] if typed_first else ["models", typed]

    rc, out, _ = _run(capsys, *argv, "--format", "json")

    entries = json.loads(out)
    assert rc == 1
    assert [e["target"] for e in entries] == [os.path.join("models", "tokenizer_config.json")]
    assert {f["template_name"] for f in entries[0]["findings"]} == {"tool_use"}


def test_dotdot_after_a_symlinked_folder_is_not_folded_into_another_file(scan_dir, tmp_path,
                                                                          capsys):
    _write(scan_dir / "chat_template.jinja", BENIGN)
    _write(tmp_path / "elsewhere" / "chat_template.jinja", MALICIOUS)
    _symlink(scan_dir / "hop", tmp_path / "elsewhere" / "deep")
    (tmp_path / "elsewhere" / "deep").mkdir()
    typed = os.path.join("models", "hop", "..", "chat_template.jinja")  # elsewhere/...
    rc, out, _ = _run(capsys, "models", typed)
    assert rc == 1  # the typed malicious file is scanned, not merged with models/...
    assert out.count("=== target:") == 3  # models/chat_template.jinja, models/hop, typed


def test_a_symlink_to_a_typed_file_stays_a_target_of_its_own(scan_dir, capsys):
    _write(scan_dir / "real.jinja", MALICIOUS)
    _symlink(scan_dir / "alias.jinja", scan_dir / "real.jinja")
    rc, out, _ = _run(capsys, os.path.join("models", "real.jinja"), "models")
    assert rc == 1
    assert out.count("=== target:") == 2


@pytest.mark.parametrize("found", [True, False])
def test_a_template_file_over_the_cap_is_reported_not_read(scan_dir, capsys, monkeypatch,
                                                           found):
    monkeypatch.setattr(scan, "_MAX_TEMPLATE_FILE_BYTES", 64)
    _write(scan_dir / "at-cap.jinja", "x" * 64)
    _write(scan_dir / "huge.jinja", MALICIOUS + " " * 64)
    huge = os.path.join("models", "huge.jinja")

    rc, out, err = _run(capsys, "models") if found else _run(capsys, huge)

    assert rc == 2
    assert "template file exceeds the 64-byte cap" in err
    if found:
        assert "overall: 2 target(s), 0 gating, 1 could not be scanned -> exit 2" in out


def test_an_explicit_source_does_not_search_a_directory(scan_dir, capsys):
    _write(scan_dir / "chat_template.jinja", MALICIOUS)
    rc, out, err = _run(capsys, "models", "--source", "file")
    assert rc == 2
    assert out == ""
    assert "cannot read template file" in err


def test_a_hostile_file_name_is_escaped(scan_dir, capsys):
    if sys.platform == "win32":
        pytest.skip("Windows file names cannot hold control characters")
    _write(scan_dir / f"{ESC}[31mred.jinja", MALICIOUS)
    rc, out, err = _run(capsys, "models")
    assert rc == 1
    assert ESC not in out and ESC not in err
    assert "\\x1b[31mred.jinja" in out


def test_json_is_one_report_per_found_file(scan_dir, capsys):
    _write(scan_dir / "a.jinja", MALICIOUS)
    _write(scan_dir / "b" / "tokenizer_config.json", "{")
    rc, out, _ = _run(capsys, "models", "--format", "json")
    entries = json.loads(out)
    assert rc == 1
    assert [e["target"] for e in entries] == [
        os.path.join("models", "a.jinja"), os.path.join("models", "b", "tokenizer_config.json"),
    ]
    assert [e["exit_code"] for e in entries] == [1, 2]


def test_sarif_lists_every_found_file_and_stays_valid(scan_dir, capsys):
    _write(scan_dir / "chat_template.jinja", MALICIOUS)
    _write(scan_dir / "sub" / "tokenizer_config.json", json.dumps({"chat_template": MALICIOUS}))
    _write(scan_dir / "sub" / "bad.gguf", b"GGUF")

    rc, out, _ = _run(capsys, "models", "--format", "sarif")

    doc = json.loads(out)
    schema = json.loads(Path(SARIF_SCHEMA_PATH).read_text(encoding="utf-8"))
    assert list(Draft7Validator(schema).iter_errors(doc)) == []
    assert rc == 1
    run = doc["runs"][0]
    assert [a["location"]["uri"] for a in run["artifacts"]] == [
        "models/chat_template.jinja", "models/sub/bad.gguf", "models/sub/tokenizer_config.json",
    ]
    by_uri = {}
    for result in run["results"]:
        by_uri.setdefault(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                          []).append(result["locations"][0])
    # A raw template file has a line region; the template inside a config does not.
    assert all("region" in loc["physicalLocation"]
               for loc in by_uri["models/chat_template.jinja"])
    assert all("region" not in loc["physicalLocation"] and "templateLine" in loc["properties"]
               for loc in by_uri["models/sub/tokenizer_config.json"])
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert [n["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for n in invocation["toolExecutionNotifications"]] == ["models/sub/bad.gguf"]


def test_find_template_files_returns_scan_targets(scan_dir):
    _write(scan_dir / "a.jinja", b"")
    assert find_template_files(str(scan_dir)) == [
        ScanTarget(os.path.join(str(scan_dir), "a.jinja"), "file", None),
    ]


def test_a_directory_copied_from_the_fixtures_keeps_every_verdict(scan_dir, capsys):
    shutil.copytree(os.path.join(ROOT, "fixtures", "malicious"), scan_dir / "malicious")
    rc, targets = _json_targets(capsys, "models")
    assert rc == 1
    assert targets and all(r["exit_code"] == 1 for r in targets.values())
