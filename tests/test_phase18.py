"""Phase 18 — Linux sandbox hardening tests (the project conventions, fixture/observation-driven).

The Linux kernel/OS backstops (seccomp, rlimits) are proven via SUBPROCESSES so a SIGSYS /
SIGXCPU kill is isolated from the test runner; they skip off Linux. The symlink-escape fix in
the audit-hook policy is exercised wherever symlink creation is permitted (skipped on Windows,
where it needs privileges). ``apply_linux_hardening`` must be a no-op off Linux so the Windows
path stays byte-identical (Rule 10). MARKER-only (Rule 4); no weights (Rule 6).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys

import pytest

from glyphhound.sandbox import confirm_template, harden
from glyphhound.sandbox.policy import ContainmentViolation, make_audit_hook

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
LINUX = sys.platform.startswith("linux")
WINDOWS = sys.platform == "win32"


def _run_py(snippet: str, timeout: float = 20.0) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-c", snippet], capture_output=True, text=True,
                          env=env, timeout=timeout)


# --- hardening is a no-op off Linux; applies (in a subprocess!) on Linux ------------------
# NOTE: apply_linux_hardening / install_seccomp_filter / apply_rlimits have process-global,
# inherited-across-fork effects, so on Linux they are ONLY ever exercised in a subprocess —
# calling them in this (long-lived) test process would poison every later test's subprocess.

@pytest.mark.skipif(LINUX, reason="off-Linux no-op is safe to call in-process")
def test_hardening_is_noop_off_linux():
    assert harden.apply_linux_hardening() == {"platform": sys.platform, "applied": False}


@pytest.mark.skipif(not LINUX, reason="Linux hardening, applied in an isolated subprocess")
def test_apply_linux_hardening_applies_on_linux():
    out = _run_py("import json;"
                  "from glyphhound.sandbox.harden import apply_linux_hardening;"
                  "print(json.dumps(apply_linux_hardening('/tmp')))")
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert data["applied"] is True
    assert data["seccomp"].startswith("loaded:"), data["seccomp"]
    assert "RLIMIT_FSIZE" in data["rlimits"]


# --- the symlink-escape fix (the out-of-scratch hole Phase 18 closes) ---------------------

@pytest.mark.skipif(WINDOWS, reason="symlink creation needs privileges on Windows")
def test_symlink_in_scratch_pointing_outside_is_blocked(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    outside = tmp_path / "OUTSIDE"
    link = scratch / "link"                       # the path string is INSIDE scratch...
    os.symlink(str(outside), str(link))            # ...but it resolves OUTSIDE
    events: list = []
    hook = make_audit_hook(str(scratch), events)
    with pytest.raises(ContainmentViolation):
        hook("open", (str(link), "w", None))
    assert events, "the blocked symlink write must be recorded"
    assert not outside.exists()


@pytest.mark.skipif(WINDOWS, reason="symlink creation needs privileges on Windows")
def test_in_scratch_write_still_allowed_after_symlink_fix(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    hook = make_audit_hook(str(scratch), [])
    hook("open", (str(scratch / "sentinel"), "w", None))  # ordinary in-scratch write: no raise


@pytest.mark.skipif(WINDOWS, reason="symlink creation needs privileges on Windows")
def test_symlink_resolving_back_into_scratch_is_allowed(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    link = scratch / "link"
    os.symlink(str(scratch / "real"), str(link))   # resolves to a path INSIDE scratch
    hook = make_audit_hook(str(scratch), [])
    hook("open", (str(link), "w", None))           # only escapes are blocked: no raise


# --- the hardlink / symlink / rename CREATION denial (closes the inode-aliasing escape) ---
# A hardlink aliases an out-of-scratch inode under an in-scratch NAME; realpath cannot see it
# (no symlink signal), so the policy must deny link/symlink/rename creation outright. These
# drive the hook function directly (no real link is created), so they run cross-platform.

def test_policy_blocks_hardlink_creation(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    events: list = []
    hook = make_audit_hook(str(scratch), events)
    with pytest.raises(ContainmentViolation):
        hook("os.link", (str(tmp_path / "OUTSIDE"), str(scratch / "h"), None, None, True))
    assert events, "the blocked hardlink must be recorded"


def test_policy_blocks_symlink_creation(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    events: list = []
    hook = make_audit_hook(str(scratch), events)
    with pytest.raises(ContainmentViolation):
        hook("os.symlink", (str(tmp_path / "OUTSIDE"), str(scratch / "s"), None))
    assert events


def test_policy_blocks_rename(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    hook = make_audit_hook(str(scratch), [])
    with pytest.raises(ContainmentViolation):
        hook("os.rename", (str(tmp_path / "OUTSIDE"), str(scratch / "r"), None, None))


def test_hardlink_escape_is_contained_end_to_end():
    # Render the hardlink probe in the contained child: os.link is denied -> not confirmed.
    fixture = os.path.join(ROOT, "fixtures", "sandbox", "containment_hardlink_probe.jinja")
    result = confirm_template(open(fixture, encoding="utf-8").read())
    assert result.confirmed is False
    assert result.out_of_scratch_write_occurred is False
    assert any("link" in e for e in result.blocked_events), result.blocked_events


# --- Linux-only: seccomp kernel backstop -------------------------------------------------

@pytest.mark.skipif(not LINUX, reason="seccomp is Linux-only")
def test_install_seccomp_filter_reports_loaded():
    out = _run_py("from glyphhound.sandbox.harden import install_seccomp_filter;"
                  "print(install_seccomp_filter())")
    assert out.stdout.strip().startswith("loaded:"), (out.stdout, out.stderr)


@pytest.mark.skipif(not LINUX, reason="seccomp is Linux-only")
def test_seccomp_blocks_execve_at_kernel_level():
    base = _run_py("import os; os.execv('/bin/true', ['true'])")
    assert base.returncode == 0, "baseline execve must run without a filter"
    armed = _run_py("import os;"
                    "from glyphhound.sandbox.harden import install_seccomp_filter;"
                    "install_seccomp_filter();"
                    "os.execv('/bin/true', ['true'])")
    assert armed.returncode == -signal.SIGSYS, (armed.returncode, armed.stderr)


@pytest.mark.skipif(not LINUX, reason="seccomp is Linux-only")
def test_seccomp_blocks_network_connect_at_kernel_level():
    armed = _run_py("import socket;"
                    "from glyphhound.sandbox.harden import install_seccomp_filter;"
                    "install_seccomp_filter();"
                    "socket.socket().connect(('192.0.2.1', 9))")
    assert armed.returncode == -signal.SIGSYS, (armed.returncode, armed.stderr)


# --- Linux-only: resource rlimits --------------------------------------------------------

@pytest.mark.skipif(not LINUX, reason="rlimits proof is Linux-only")
def test_rlimits_are_applied():
    out = _run_py("import json, resource;"
                  "from glyphhound.sandbox.harden import apply_rlimits;"
                  "ap = apply_rlimits();"
                  "print(json.dumps({'ap': ap,"
                  " 'fsize': resource.getrlimit(resource.RLIMIT_FSIZE)[0],"
                  " 'core': resource.getrlimit(resource.RLIMIT_CORE)[0]}))")
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert "RLIMIT_FSIZE" in data["ap"]
    assert data["fsize"] == 16 * 1024 * 1024
    assert data["core"] == 0


@pytest.mark.skipif(not LINUX, reason="rlimits proof is Linux-only")
def test_rlimit_cpu_kills_busy_loop():
    cpu = _run_py("import resource\n"
                  "resource.setrlimit(resource.RLIMIT_CPU, (1, 2))\n"
                  "while True:\n    pass\n", timeout=15.0)
    # SIGXCPU at the soft limit (default action terminates); SIGKILL if it races to the hard
    # limit first. Either proves the CPU cap is enforced.
    assert cpu.returncode in (-signal.SIGXCPU, -signal.SIGKILL), cpu.returncode


# --- Linux-only: privilege drop is an honest no-op when not root --------------------------

@pytest.mark.skipif(not LINUX, reason="Linux privilege model")
def test_drop_privileges_is_noop_when_not_root():
    if os.geteuid() == 0:
        pytest.skip("test runner is root")
    assert harden.drop_privileges() == "skipped (not root)"


# --- Linux-only: a legitimate MARKER render still confirms WITH hardening active ----------

@pytest.mark.skipif(not LINUX, reason="Linux child render")
def test_marker_still_confirms_with_hardening():
    fixture = os.path.join(ROOT, "fixtures", "sandbox", "sandbox_exec_marker.jinja")
    result = confirm_template(open(fixture, encoding="utf-8").read())
    assert result.confirmed is True, result
