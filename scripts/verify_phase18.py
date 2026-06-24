"""Phase 18 verification -- Linux sandbox hardening + containment proof.

Phase 6 proved a CROSS-PLATFORM audit-hook contains a hostile render (and still PASSES on
Linux). Phase 18 adds the Linux-only kernel/OS backstops in :mod:`glyphhound.sandbox.harden`
(applied in the child under the audit hook) and OS-enforced symlink resolution in the
out-of-scratch write check, then PROVES them -- mirroring verify_phase6 on Linux:

  (a) the exploitable MARKER fixture still CONFIRMS (confirmed=True) WITH hardening active in
      the child -- hardening does not break a legitimate render -- and the child applies the
      full hardening set (rlimits + privilege-drop + seccomp);
  (b) CONTAINMENT is proven four ways:
        * out-of-scratch write BLOCKED (audit hook),
        * outbound network connect BLOCKED (audit hook),
        * a symlink planted INSIDE scratch that points OUTSIDE is BLOCKED (Phase-18 realpath
          fix -- the string-only check used to ALLOW it),
        * seccomp KILLS a real syscall at the KERNEL level, independent of the audit hook
          (a no-filter child execve's freely; a seccomp child is killed by SIGSYS), and
          rlimits are enforced (a tiny RLIMIT_CPU child is killed by SIGXCPU);
  (c) no false confirmations: benign template + real benign corpus + a real
      os.system payload all yield confirmed != True;
  (d) with the sandbox OFF the static pipeline + reports are unchanged (confirmed=None,
      byte-identical), and confirmation stays annotation-only.

Run (Linux):  .venv/bin/python scripts/verify_phase18.py
Exit code is non-zero if any check fails. On non-Linux it prints SKIP and exits 0 (there is
no Linux hardening to prove there; the cross-platform layer is covered by verify_phase6).
MARKER payloads only; no model weights are ever loaded.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from glyphhound.analyze import analyze_template  # noqa: E402
from glyphhound.report import (  # noqa: E402
    make_report,
    render_human,
    render_json,
    render_sarif,
)
from glyphhound.sandbox import confirm_template, is_supported  # noqa: E402
from glyphhound.sandbox.policy import ContainmentViolation, make_audit_hook  # noqa: E402
from glyphhound.scan import scan_template_string  # noqa: E402

SANDBOX_DIR = os.path.join(ROOT, "fixtures", "sandbox")
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
MARKER_FIXTURE = os.path.join(SANDBOX_DIR, "sandbox_exec_marker.jinja")
FS_PROBE_FIXTURE = os.path.join(SANDBOX_DIR, "containment_fs_probe.jinja")
NET_PROBE_FIXTURE = os.path.join(SANDBOX_DIR, "containment_net_probe.jinja")
HARDLINK_PROBE_FIXTURE = os.path.join(SANDBOX_DIR, "containment_hardlink_probe.jinja")
CVE_FIXTURE = os.path.join(MALICIOUS_DIR, "cve_2024_34359_marker.jinja")

BENIGN = "{% for m in messages %}{{ m.role }}: {{ m.content }}\n{% endfor %}"


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _run_py(snippet: str, timeout: float = 20.0) -> subprocess.CompletedProcess:
    """Run a snippet in a SEPARATE Python so a seccomp/rlimit kill is isolated from us."""
    env = {**os.environ, "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-c", snippet], capture_output=True, text=True,
                          env=env, timeout=timeout)


# --- (a) the marker still confirms WITH hardening; the child applies the full set ---------

def verify_marker_with_hardening() -> bool:
    print("=" * 78)
    print("Phase 18 (a) -- the MARKER fixture still CONFIRMS with Linux hardening active")
    print("=" * 78)
    result = confirm_template(_read(MARKER_FIXTURE))
    separate = result.pid is not None and result.pid != os.getpid()
    marker_ok = result.confirmed is True and result.ran and result.error is None and separate
    print(f"[{'OK' if marker_ok else 'FAIL'}]   marker confirmed={result.confirmed} ran={result.ran} "
          f"separate_proc={separate} (child pid={result.pid})")

    # What the child actually applied (run the same hardening in an isolated process).
    summary_proc = _run_py(
        "import json;"
        "from glyphhound.sandbox.harden import apply_linux_hardening;"
        "print(json.dumps(apply_linux_hardening('/tmp')))"
    )
    try:
        summary = json.loads(summary_proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        summary = {}
    seccomp = str(summary.get("seccomp", ""))
    rlimits = summary.get("rlimits", [])
    harden_ok = (summary.get("applied") is True and seccomp.startswith("loaded:")
                 and "RLIMIT_FSIZE" in rlimits)
    print(f"[{'OK' if harden_ok else 'FAIL'}]   child hardening: seccomp={seccomp!r} "
          f"rlimits={rlimits} priv={summary.get('privilege_drop')!r}")

    ok = marker_ok and harden_ok
    print(f"[{'OK' if ok else 'FAIL'}] hardening is applied AND a legitimate render still confirms.")
    return ok


# --- (b) containment proven: audit hook + symlink fix + seccomp/rlimit kernel backstop ----

def verify_containment() -> bool:
    print("\n" + "=" * 78)
    print("Phase 18 (b) -- CONTAINMENT proven (audit hook + symlink + seccomp/rlimit)")
    print("=" * 78)

    fs = confirm_template(_read(FS_PROBE_FIXTURE))
    fs_ok = (fs.confirmed is False and fs.out_of_scratch_write_occurred is False
             and any("write" in e for e in fs.blocked_events) and fs.error is not None)
    print(f"[{'OK' if fs_ok else 'FAIL'}]   out-of-scratch write blocked: {fs.blocked_events}")

    net = confirm_template(_read(NET_PROBE_FIXTURE))
    net_ok = net.confirmed is False and any(("network" in e or "connect" in e)
                                            for e in net.blocked_events)
    print(f"[{'OK' if net_ok else 'FAIL'}]   network connect blocked:     {net.blocked_events}")

    # Symlink escape: a symlink INSIDE scratch pointing OUTSIDE must be treated as out-of-scratch.
    sym_ok = _check_symlink_escape_blocked()
    print(f"[{'OK' if sym_ok else 'FAIL'}]   in-scratch symlink -> outside write blocked (realpath)")

    # Hardlink escape: aliasing an out-of-scratch inode into scratch must be denied at creation
    # (a hardlink is invisible to realpath), proven end-to-end through the contained render.
    hl = confirm_template(_read(HARDLINK_PROBE_FIXTURE))
    hl_ok = (hl.confirmed is False and hl.out_of_scratch_write_occurred is False
             and any("link" in e for e in hl.blocked_events) and hl.error is not None)
    print(f"[{'OK' if hl_ok else 'FAIL'}]   in-scratch hardlink -> outside denied: {hl.blocked_events}")

    # seccomp KERNEL backstop, independent of the audit hook: no filter -> execve runs;
    # with the filter -> the kernel kills the process with SIGSYS.
    base = _run_py("import os; os.execv('/bin/true', ['true'])")
    armed = _run_py(
        "import sys, os;"
        "from glyphhound.sandbox.harden import install_seccomp_filter;"
        "st = install_seccomp_filter(); sys.stderr.write('seccomp=' + st + chr(10));"
        "os.execv('/bin/true', ['true'])"
    )
    seccomp_ok = base.returncode == 0 and armed.returncode == -signal.SIGSYS
    print(f"[{'OK' if seccomp_ok else 'FAIL'}]   seccomp kernel-block: no-filter execve rc={base.returncode} "
          f"-> seccomp execve rc={armed.returncode} (SIGSYS={-signal.SIGSYS}); {armed.stderr.strip()}")

    # rlimits enforced: caps are in effect (readback) AND a tiny RLIMIT_CPU kills a busy loop.
    rlim_ok = _check_rlimits_enforced()
    print(f"[{'OK' if rlim_ok else 'FAIL'}]   resource rlimits enforced (FSIZE readback + RLIMIT_CPU kill)")

    cleaned = (fs.cleaned_up and net.cleaned_up
               and not os.path.exists(fs.workdir) and not os.path.exists(net.workdir))
    print(f"[{'OK' if cleaned else 'FAIL'}]   scratch dirs cleaned up")

    ok = fs_ok and net_ok and sym_ok and hl_ok and seccomp_ok and rlim_ok and cleaned
    print(f"[{'OK' if ok else 'FAIL'}] every containment layer blocks a real attempt.")
    return ok


def _check_symlink_escape_blocked() -> bool:
    d = tempfile.mkdtemp(prefix="glyphhound_p18_")
    try:
        scratch = os.path.join(d, "scratch")
        os.mkdir(scratch)
        outside = os.path.join(d, "OUTSIDE_TARGET")
        link = os.path.join(scratch, "link")           # path string is inside scratch...
        os.symlink(outside, link)                       # ...but it resolves OUTSIDE
        events: list = []
        hook = make_audit_hook(scratch, events)
        try:
            hook("open", (link, "w", None))
            return False                                # not blocked -> the bug is back
        except ContainmentViolation:
            return bool(events) and not os.path.exists(outside)
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def _check_rlimits_enforced() -> bool:
    readback = _run_py(
        "import json, resource;"
        "from glyphhound.sandbox.harden import apply_rlimits;"
        "ap = apply_rlimits();"
        "print(json.dumps({'applied': ap,"
        " 'fsize': resource.getrlimit(resource.RLIMIT_FSIZE)[0],"
        " 'core': resource.getrlimit(resource.RLIMIT_CORE)[0]}))"
    )
    try:
        rb = json.loads(readback.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return False
    caps_ok = ("RLIMIT_FSIZE" in rb.get("applied", [])
               and rb.get("fsize") == 16 * 1024 * 1024 and rb.get("core") == 0)
    # Behavioural: a 1-second CPU limit kills a busy loop -- SIGXCPU at the soft limit, or
    # SIGKILL if it races to the hard limit first. Either proves the cap is enforced.
    cpu = _run_py("import resource\n"
                  "resource.setrlimit(resource.RLIMIT_CPU, (1, 2))\n"
                  "while True:\n    pass\n", timeout=15.0)
    cpu_ok = cpu.returncode in (-signal.SIGXCPU, -signal.SIGKILL)
    if not (caps_ok and cpu_ok):
        print(f"      rlimit detail: readback={readback.stdout.strip()!r} cpu_rc={cpu.returncode}")
    return caps_ok and cpu_ok


# --- (c) no false confirmations on benign + real attacker payloads ------------------------

def verify_no_false_confirmations() -> bool:
    print("\n" + "=" * 78)
    print("Phase 18 (c) -- no false confirmations (benign + corpus + attacker payload)")
    print("=" * 78)
    simple = confirm_template(BENIGN)
    simple_ok = simple.confirmed is not True
    print(f"[{'OK' if simple_ok else 'FAIL'}]   trivial benign: confirmed={simple.confirmed}")

    attacker = confirm_template(_read(CVE_FIXTURE))
    attacker_ok = attacker.confirmed is False and any(("spawn" in e or "system" in e)
                                                      for e in attacker.blocked_events)
    print(f"[{'OK' if attacker_ok else 'FAIL'}]   real os.system payload contained: {attacker.blocked_events}")

    files = sorted(f for f in os.listdir(BENIGN_DIR) if f.endswith(".jinja"))
    false_confirms = sum(1 for f in files
                         if confirm_template(_read(os.path.join(BENIGN_DIR, f))).confirmed is True)
    print(f"  false confirmations on the real benign corpus: {false_confirms}/{len(files)}")

    ok = simple_ok and attacker_ok and false_confirms == 0 and len(files) >= 10
    print(f"[{'OK' if ok else 'FAIL'}] nothing benign is confirmed.")
    return ok


# --- (d) sandbox OFF leaves the static pipeline + reports unchanged -----------------------

def verify_sandbox_off_unchanged() -> bool:
    print("\n" + "=" * 78)
    print("Phase 18 (d) -- sandbox OFF leaves the static pipeline + reports unchanged")
    print("=" * 78)
    text = _read(MARKER_FIXTURE)
    off = scan_template_string(text)
    baseline = make_report(analyze_template(text))
    byte_identical = all(render(off) == render(baseline)
                         for render in (render_human, render_json, render_sarif))
    confirmed_none = all(f.confirmed is None for f in off.findings)
    on = scan_template_string(text, confirm=True)
    confirmed_set = any(f.confirmed is True for f in on.findings)
    gate_unchanged = on.exit_code == off.exit_code != 0 and on.summary.gating == off.summary.gating
    print(f"  confirm=off byte-identical to static path: {byte_identical}; confirmed all None: {confirmed_none}")
    print(f"  confirm=on sets confirmed + gate unchanged (annotation-only): "
          f"{confirmed_set and gate_unchanged} (exit {off.exit_code}/{on.exit_code}, "
          f"gating {off.summary.gating}/{on.summary.gating})")
    ok = byte_identical and confirmed_none and confirmed_set and gate_unchanged
    print(f"[{'OK' if ok else 'FAIL'}] the static pipeline is unchanged; confirmation is annotation-only.")
    return ok


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("Phase 18: SKIP (Linux-only hardening; nothing to prove on "
              f"{sys.platform}. The cross-platform layer is covered by verify_phase6).")
        return 0
    if not is_supported():
        print("Phase 18: FAIL -- the sandbox is not supported here (no audit hooks?).")
        return 1
    a_ok = verify_marker_with_hardening()
    b_ok = verify_containment()
    c_ok = verify_no_false_confirmations()
    d_ok = verify_sandbox_off_unchanged()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok and d_ok
    print(f"Phase 18: {'PASS' if ok else 'FAIL'} "
          f"(marker+hardening {'ok' if a_ok else 'FAIL'}, "
          f"containment {'ok' if b_ok else 'FAIL'}, "
          f"no-false-confirm {'ok' if c_ok else 'FAIL'}, "
          f"sandbox-off {'ok' if d_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
