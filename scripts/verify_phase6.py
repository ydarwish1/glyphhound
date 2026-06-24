"""Phase 6 verification -- Stage-4 sandbox confirmer (gated) + containment proof.

This is the ONE stage that renders a template, and it renders ONLY inside a locked-down
subprocess (never this process). The script is offline and deterministic: the network containment probe is blocked before any OS connect is issued, and a
confirmed result is decided by an observable sentinel file, not by timing. No model weights
are ever loaded; MARKER payloads only.

Checks (render in locked-down subprocess
with MARKER: marker fires for known-exploitable fixture; sandbox BLOCKS a real syscall
attempt (containment proven)):
  (a) the exploitable MARKER fixture, run through the contained confirmer, yields
      confirmed=True (the sentinel was written in the scratch dir, in a separate process);
  (b) CONTAINMENT is proven: an out-of-scratch write AND an outbound network connect are
      both BLOCKED inside the sandbox, with no out-of-scratch side effect, and the scratch
      dir is cleaned up afterwards;
  (c) no false confirmations: a benign template, the real benign corpus, and a
      real os.system attacker payload all yield confirmed != True;
  (d) with the sandbox OFF, the static pipeline + reports are unchanged (confirmed stays
      None and all three rendered reports are byte-identical to the static path), and
      confirmation is annotation-only (it never changes the CI exit-code gate).

Run:  .venv/Scripts/python.exe scripts/verify_phase6.py
Exit code is non-zero if any check fails (i.e. if containment could not be proven).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.analyze import analyze_template  # noqa: E402
from glyphhound.report import (  # noqa: E402
    make_report,
    render_human,
    render_json,
    render_sarif,
)
from glyphhound.sandbox import (  # noqa: E402
    confirm_findings,
    confirm_template,
    is_supported,
)
from glyphhound.scan import scan_template_string  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
SANDBOX_DIR = os.path.join(ROOT, "fixtures", "sandbox")
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")

MARKER_FIXTURE = os.path.join(SANDBOX_DIR, "sandbox_exec_marker.jinja")
FS_PROBE_FIXTURE = os.path.join(SANDBOX_DIR, "containment_fs_probe.jinja")
NET_PROBE_FIXTURE = os.path.join(SANDBOX_DIR, "containment_net_probe.jinja")
CVE_FIXTURE = os.path.join(MALICIOUS_DIR, "cve_2024_34359_marker.jinja")

BENIGN = "{% for m in messages %}{{ m.role }}: {{ m.content }}\n{% endfor %}"


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


def verify_marker_fires() -> bool:
    print("=" * 78)
    print("Phase 6 (a) -- the MARKER fixture is CONFIRMED by the contained render")
    print("=" * 78)
    text = _read(MARKER_FIXTURE)
    result = confirm_template(text)
    separate_proc = result.pid is not None and result.pid != os.getpid()
    print(f"is_supported(): {is_supported()}")
    print(f"  confirmed={result.confirmed}  ran={result.ran}  error={result.error}")
    print(f"  rendered in a separate process: {separate_proc} "
          f"(child pid={result.pid}, this pid={os.getpid()})")

    # The fixture is a genuine static sink: the analyzer already flags it reachable GH-S001,
    # so the sandbox CONFIRMS an existing finding rather than inventing one.
    findings = analyze_template(text)
    static_reachable = any(f.rule_id == "GH-S001" and f.reachable for f in findings)
    confirmed_findings = confirm_findings(text, findings)
    reachable_confirmed = any(
        f.confirmed is True and f.rule_id == "GH-S001" and f.reachable
        for f in confirmed_findings
    )
    print(f"  static analyzer flags it reachable GH-S001: {static_reachable}")
    print(f"  confirm_findings sets confirmed=True on the reachable sink: {reachable_confirmed}")

    ok = (result.confirmed is True and result.ran and result.error is None
          and separate_proc and static_reachable and reachable_confirmed)
    print(f"[{'OK' if ok else 'FAIL'}] the marker fires -> confirmed=True for the exploitable fixture.")
    return ok


def verify_containment() -> bool:
    print("\n" + "=" * 78)
    print("Phase 6 (b) -- CONTAINMENT proven: a real syscall attempt is BLOCKED")
    print("=" * 78)
    fs = confirm_template(_read(FS_PROBE_FIXTURE))
    fs_blocked = any("write" in e for e in fs.blocked_events)
    fs_ok = (fs.confirmed is False and fs.out_of_scratch_write_occurred is False
             and fs_blocked and fs.error is not None)
    print(f"[{'OK' if fs_ok else 'FAIL'}]   out-of-scratch write: confirmed={fs.confirmed} "
          f"escaped={fs.out_of_scratch_write_occurred} blocked={fs.blocked_events}")

    net = confirm_template(_read(NET_PROBE_FIXTURE))
    net_blocked = any(("network" in e or "connect" in e) for e in net.blocked_events)
    net_ok = net.confirmed is False and net_blocked
    print(f"[{'OK' if net_ok else 'FAIL'}]   network connect:     confirmed={net.confirmed} "
          f"blocked={net.blocked_events}")

    cleaned = (fs.cleaned_up and net.cleaned_up
               and not os.path.exists(fs.workdir) and not os.path.exists(net.workdir))
    print(f"[{'OK' if cleaned else 'FAIL'}]   scratch dirs cleaned up: fs={fs.cleaned_up} net={net.cleaned_up}")

    ok = fs_ok and net_ok and cleaned
    print(f"[{'OK' if ok else 'FAIL'}] the sandbox blocks a real filesystem AND network syscall attempt.")
    return ok


def verify_no_false_confirmations() -> bool:
    print("\n" + "=" * 78)
    print("Phase 6 (c) -- no false confirmations: benign + real corpus + attacker payload")
    print("=" * 78)
    simple = confirm_template(BENIGN)
    simple_ok = simple.confirmed is not True
    print(f"[{'OK' if simple_ok else 'FAIL'}]   trivial benign template: confirmed={simple.confirmed}")

    # The real os.system payload cannot run -- process spawn is blocked (contained, not confirmed).
    attacker = confirm_template(_read(CVE_FIXTURE))
    attacker_blocked = any(("spawn" in e or "system" in e) for e in attacker.blocked_events)
    attacker_ok = attacker.confirmed is False and attacker_blocked
    print(f"[{'OK' if attacker_ok else 'FAIL'}]   real os.system payload: confirmed={attacker.confirmed} "
          f"blocked={attacker.blocked_events}")

    print("-" * 78)
    files = _jinja_files(BENIGN_DIR)
    false_confirms = 0
    for fname in files:
        result = confirm_template(_read(os.path.join(BENIGN_DIR, fname)))
        if result.confirmed is True:
            false_confirms += 1
            print(f"[FAIL] {fname:46s} FALSELY confirmed")
        else:
            print(f"[OK]   {fname:46s} confirmed={result.confirmed}")
    rate = false_confirms / len(files) if files else 1.0
    print(f"\nFalse confirmations on the real benign corpus: {false_confirms}/{len(files)} ({rate:.1%}).")

    ok = simple_ok and attacker_ok and false_confirms == 0 and len(files) >= 10
    print(f"[{'OK' if ok else 'FAIL'}] nothing benign is confirmed.")
    return ok


def verify_sandbox_off_unchanged() -> bool:
    print("\n" + "=" * 78)
    print("Phase 6 (d) -- sandbox OFF leaves the static pipeline + reports unchanged")
    print("=" * 78)
    text = _read(MARKER_FIXTURE)
    off = scan_template_string(text)                  # confirm defaults to OFF
    baseline = make_report(analyze_template(text))    # the Phase-5 static path
    byte_identical = all(render(off) == render(baseline)
                         for render in (render_human, render_json, render_sarif))
    confirmed_none = all(f.confirmed is None for f in off.findings)
    print(f"  confirm=off: all findings confirmed is None: {confirmed_none}")
    print(f"  confirm=off: human/JSON/SARIF byte-identical to the static path: {byte_identical}")

    on = scan_template_string(text, confirm=True)
    confirmed_set = any(f.confirmed is True for f in on.findings)
    gate_unchanged = on.exit_code == off.exit_code != 0 and on.summary.gating == off.summary.gating
    print(f"  confirm=on:  sets confirmed=True on a finding: {confirmed_set}")
    print(f"  confirm=on:  exit-code gate unchanged (annotation-only): {gate_unchanged} "
          f"(exit off={off.exit_code} on={on.exit_code}, gating off={off.summary.gating} on={on.summary.gating})")

    ok = byte_identical and confirmed_none and confirmed_set and gate_unchanged
    print(f"[{'OK' if ok else 'FAIL'}] the static pipeline is unchanged; confirmation is annotation-only.")
    return ok


def main() -> int:
    a_ok = verify_marker_fires()
    b_ok = verify_containment()
    c_ok = verify_no_false_confirmations()
    d_ok = verify_sandbox_off_unchanged()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok and c_ok and d_ok
    print(f"Phase 6: {'PASS' if ok else 'FAIL'} "
          f"(marker-fires {'ok' if a_ok else 'FAIL'}, "
          f"containment {'ok' if b_ok else 'FAIL'}, "
          f"no-false-confirm {'ok' if c_ok else 'FAIL'}, "
          f"sandbox-off {'ok' if d_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
