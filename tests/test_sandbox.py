"""Offline, deterministic tests for the Stage-4 sandbox confirmer (Phase 6).

Fixture-driven: an exploitable MARKER fixture that, when RENDERED
inside the locked-down subprocess, reaches code execution and writes a sentinel (->
confirmed=True), and two containment probes whose blocked-syscall attempts prove the
sandbox contains. The benign corpus must never confirm. This is the ONLY stage
that renders a template, and it does so ONLY in a contained child process -- never here in
the test (main) process.

The checks for the sandbox confirmer are covered:
  (a) the MARKER fixture, run through the contained confirmer, yields confirmed=True;
  (b) the CONTAINMENT probes prove a real syscall attempt (out-of-scratch write / network
      connect) is BLOCKED, with no out-of-scratch side effect, and the scratch is cleaned;
  (c) a benign template (and a real attacker os.system payload) yields confirmed != True;
  (d) with the sandbox OFF, the static pipeline + reports are unchanged (confirmed = None).

Everything is offline: the network probe is blocked before any OS connect is issued.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from glyphhound.analyze import analyze_template
from glyphhound.analyze.models import CRITICAL, Finding
from glyphhound.report import make_report, render_human, render_json, render_sarif
from glyphhound.sandbox import (
    MARKER,
    ConfirmResult,
    confirm_findings,
    confirm_template,
    is_supported,
)
from glyphhound.sandbox.policy import make_audit_hook
from glyphhound.scan import scan_template_string

ROOT = os.path.dirname(os.path.dirname(__file__))
SANDBOX_DIR = os.path.join(ROOT, "fixtures", "sandbox")
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")

MARKER_FIXTURE = os.path.join(SANDBOX_DIR, "sandbox_exec_marker.jinja")
FS_PROBE_FIXTURE = os.path.join(SANDBOX_DIR, "containment_fs_probe.jinja")
NET_PROBE_FIXTURE = os.path.join(SANDBOX_DIR, "containment_net_probe.jinja")

BENIGN = "{% for m in messages %}{{ m.role }}: {{ m.content }}\n{% endfor %}"
# A loop that does unbounded trivial work (no output growth) -> hits the wall-clock timeout.
INFINITE = "{% for _ in range(10**11) %}{% set x = 1 %}{% endfor %}"


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


# --- the audit-hook policy (unit-tested in-process; the hook is NOT installed here) ---
# Calling the hook function directly exercises its deny/allow decisions without making
# the audit hook permanent in the test process.

def test_policy_blocks_out_of_scratch_write(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    events = []
    hook = make_audit_hook(str(scratch), events)
    outside = str(tmp_path / "OUTSIDE")
    with pytest.raises(Exception):
        hook("open", (outside, "w", None))
    assert events, "the blocked write must be recorded as evidence"


def test_policy_allows_in_scratch_write(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    hook = make_audit_hook(str(scratch), [])
    inside = str(scratch / "sentinel")
    hook("open", (inside, "w", None))  # must NOT raise


def test_policy_allows_reads_anywhere(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    hook = make_audit_hook(str(scratch), [])
    hook("open", (str(tmp_path / "anything"), "r", None))  # reads are not the threat


def test_policy_blocks_network(tmp_path):
    events = []
    hook = make_audit_hook(str(tmp_path), events)
    with pytest.raises(Exception):
        hook("socket.connect", (object(), ("192.0.2.1", 9)))
    assert events


def test_policy_blocks_process_spawn(tmp_path):
    hook = make_audit_hook(str(tmp_path), [])
    with pytest.raises(Exception):
        hook("os.system", (b"echo hi",))
    with pytest.raises(Exception):
        hook("subprocess.Popen", ("exe", "args", None, None))


def test_policy_blocks_ctypes(tmp_path):
    hook = make_audit_hook(str(tmp_path), [])
    with pytest.raises(Exception):
        hook("ctypes.dlopen", ("libc",))


def test_policy_ignores_unrelated_events(tmp_path):
    hook = make_audit_hook(str(tmp_path), [])
    hook("import", ("os", None, None, None, None))  # imports are not blocked
    hook("compile", (None, "<string>"))


# --- (a) the MARKER fires for the exploitable fixture (confirmed=True) ----------

def test_is_supported_on_this_platform():
    assert is_supported() is True


def test_marker_fixture_confirms():
    result = confirm_template(_read(MARKER_FIXTURE))
    assert isinstance(result, ConfirmResult)
    assert result.ran is True
    assert result.confirmed is True, f"the marker should fire: {result}"
    assert result.error is None
    assert result.out_of_scratch_write_occurred is False


def test_marker_render_happens_in_a_separate_process():
    # Safety boundary: the dangerous render must NOT run in the main process.
    result = confirm_template(_read(MARKER_FIXTURE))
    assert result.pid is not None
    assert result.pid != os.getpid()


def test_confirm_findings_sets_confirmed_true_on_reachable_sinks():
    text = _read(MARKER_FIXTURE)
    findings = analyze_template(text)
    confirmed = confirm_findings(text, findings)
    reachable = [f for f in confirmed if f.reachable is True]
    assert reachable, "the marker fixture must have reachable findings to confirm"
    assert any(f.confirmed is True and f.rule_id == "GH-S001" for f in reachable)


def test_marker_fixture_statically_flags_reachable_gh_s001():
    # The fixture is a genuine sink: the static analyzer already flags it reachable, so the
    # sandbox CONFIRMS an existing static finding rather than inventing one.
    findings = analyze_template(_read(MARKER_FIXTURE))
    assert any(f.rule_id == "GH-S001" and f.reachable for f in findings)


def test_marker_fixture_carries_the_marker_constant():
    assert MARKER in _read(MARKER_FIXTURE)


# --- (b) containment: a real syscall attempt is BLOCKED -------------------------

def test_containment_blocks_out_of_scratch_write():
    result = confirm_template(_read(FS_PROBE_FIXTURE))
    assert result.confirmed is False
    assert result.out_of_scratch_write_occurred is False, "the out-of-scratch file must NOT exist"
    assert any("write" in e for e in result.blocked_events), result.blocked_events
    assert result.error is not None, "the blocked write must surface as a render error"


def test_containment_blocks_network():
    result = confirm_template(_read(NET_PROBE_FIXTURE))
    assert result.confirmed is False
    assert any("network" in e or "connect" in e for e in result.blocked_events), result.blocked_events


def test_scratch_dir_is_cleaned_up():
    result = confirm_template(_read(MARKER_FIXTURE))
    assert result.workdir is not None
    assert not os.path.exists(result.workdir), "the scratch workdir must be removed"
    assert result.cleaned_up is True


# --- (c) benign + real attacker payloads never confirm --------------------------

def test_benign_template_is_not_confirmed():
    result = confirm_template(BENIGN)
    assert result.confirmed is False


def test_real_benign_corpus_template_is_not_confirmed():
    # Render a real Hugging Face template in the sandbox; it must produce no sentinel.
    sample = os.path.join(BENIGN_DIR, "bartowski__Llama-3.2-1B-Instruct-GGUF.jinja")
    result = confirm_template(_read(sample))
    assert result.confirmed is not True


def test_real_os_system_payload_is_contained_not_confirmed():
    # The existing CVE fixture's payload is os.system(...). The sandbox BLOCKS process
    # spawn, so it cannot run -> confirmed stays False (and nothing crashes).
    text = _read(os.path.join(MALICIOUS_DIR, "cve_2024_34359_marker.jinja"))
    result = confirm_template(text)
    assert result.confirmed is False
    assert any("spawn" in e or "system" in e for e in result.blocked_events), result.blocked_events


def test_confirm_findings_leaves_presence_only_findings_unconfirmed():
    # A presence-only (reachable=False) finding is not a confirmation target -> stays None.
    presence = Finding("GH-S002", CRITICAL, "code-exec-name", None, 1, "system",
                       "Name@line1", reachable=False)
    out = confirm_findings(BENIGN, [presence])
    assert out[0].confirmed is None


# --- timeouts map to not-confirmed, never a crash (determinism boundary) --------

def test_timeout_maps_to_not_confirmed():
    result = confirm_template(INFINITE, timeout=3.0)
    assert result.confirmed is False
    assert result.timed_out is True


def test_confirm_result_is_deterministic():
    a = confirm_template(_read(MARKER_FIXTURE))
    b = confirm_template(_read(MARKER_FIXTURE))
    assert a.confirmed == b.confirmed is True


# --- (d) sandbox OFF leaves the static pipeline + reports unchanged --------------

def test_scan_with_confirm_off_leaves_confirmed_none():
    report = scan_template_string(_read(MARKER_FIXTURE))  # confirm defaults to off
    assert report.findings
    assert all(f.confirmed is None for f in report.findings)


def test_scan_with_confirm_off_reports_are_byte_identical_to_phase5_path():
    text = _read(MARKER_FIXTURE)
    off = scan_template_string(text)                       # new opt-in path, confirm off
    baseline = make_report(analyze_template(text))         # the Phase-5 path
    for render in (render_human, render_json, render_sarif):
        assert render(off) == render(baseline)


def test_scan_with_confirm_on_sets_confirmed_and_keeps_exit_code():
    text = _read(MARKER_FIXTURE)
    off = scan_template_string(text)
    on = scan_template_string(text, confirm=True)
    assert any(f.confirmed is True for f in on.findings), "confirm=True must set confirmed"
    # confirmed is annotation-only: the exit-code gate is reachable-based and unchanged.
    assert on.exit_code == off.exit_code != 0


def test_confirm_on_does_not_change_gating_count():
    text = _read(MARKER_FIXTURE)
    off = scan_template_string(text)
    on = scan_template_string(text, confirm=True)
    assert on.summary.gating == off.summary.gating


# --- the CLI --confirm flag (real process; respects the contained-render boundary) ---

def test_cli_confirm_flag_confirms_marker_fixture():
    proc = subprocess.run(
        [sys.executable, "-m", "glyphhound", "scan", MARKER_FIXTURE,
         "--format", "json", "--confirm"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode != 0, "a reachable sink still gates CI"
    doc = json.loads(proc.stdout)
    assert any(f["confirmed"] is True for f in doc["findings"]), proc.stdout[:400]


def test_cli_without_confirm_leaves_confirmed_null():
    proc = subprocess.run(
        [sys.executable, "-m", "glyphhound", "scan", MARKER_FIXTURE, "--format", "json"],
        cwd=ROOT, capture_output=True, text=True,
    )
    doc = json.loads(proc.stdout)
    assert all(f["confirmed"] is None for f in doc["findings"])
