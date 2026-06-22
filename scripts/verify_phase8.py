"""Phase 8 verification — head-to-head benchmark vs ModelAudit (the design docs row 8).

The phase gate: prove the project's ONE defensible claim with MEASURED output (Rule 2),
honestly (Rule 3). Like verify_phase0 (which needs network + Ollama), this verifier needs
ModelAudit installed in the isolated `.venv-modelaudit` env (the offline guarantee covers
pytest + verify_phase1..7, which stay green without it). It runs BOTH tools over the same
GGUF artifacts and asserts:

  (a) GlyphHound catches EVERY malicious payload, including all obfuscated ones (100%).
  (b) GlyphHound has ZERO false positives on the benign controls (Rule 9, no regression).
  (c) ModelAudit catches the PLAIN control (un-obfuscated chain) -> it is invoked FAIRLY,
      not crippled; a miss there would mean a broken/limited invocation (Rule 3).
  (d) ModelAudit has ZERO false positives on the benign controls (it is a real, fair tool).
  (e) The CORE CLAIM is substantiated: there is >=1 obfuscation GlyphHound catches that
      ModelAudit MISSES (measured, not asserted).
  (f) Live results match the manifest's measured-then-LOCKED *_expected for every payload,
      at the pinned ModelAudit version (so the recorded table is the real one; catches both
      version drift and accidental comment-token contamination of the scanned text).
  (g) Determinism: two independent benchmark runs yield a byte-identical table (Rule 7).

Run:  .venv/Scripts/python.exe scripts/verify_phase8.py
Exit code is non-zero if any check fails (cp1252 consoles may mojibake glyphs — judge by
[OK]/[FAIL] + exit code, not console rendering).
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)  # import the harness module

try:  # pragma: no cover - environment dependent
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

import run_benchmark as bench  # noqa: E402


def _print_header(title: str) -> None:
    print("=" * 78)
    print(title)
    print("=" * 78)


def main() -> int:
    _print_header("Phase 8 - head-to-head benchmark vs ModelAudit (obfuscated catch/miss)")
    exe = bench.find_modelaudit()
    if exe is None:
        print("[FAIL] ModelAudit CLI not found. Set up the isolated env first:")
        print('       python -m venv .venv-modelaudit')
        print('       .venv-modelaudit/Scripts/python -m pip install "modelaudit==0.2.47"')
        print("       (or set GLYPHHOUND_MODELAUDIT to the modelaudit executable)")
        return 1

    manifest = bench.load_manifest()
    pinned = manifest["modelaudit_version"]
    live_version = bench.modelaudit_version(exe)
    print(f"ModelAudit: {exe}")
    print(f"  version (live): {live_version}   (manifest pin: {pinned})")
    version_ok = live_version == pinned
    print(f"[{'OK' if version_ok else 'FAIL'}] ModelAudit version matches the manifest pin "
          f"(the locked table reproduces only at the pinned version).")

    try:
        rows = bench.run_benchmark(exe, manifest)
    except bench.HarnessError as exc:
        print(f"[FAIL] harness error: {exc}")
        return 1

    print()
    print(bench.format_table(rows, modelaudit_version_str=live_version))
    print()
    print(bench.format_summary(bench.summarize(rows)))
    print()

    by_file = {r["entry"]["file"]: r for r in rows}
    malicious = [r for r in rows if r["entry"]["malicious"]]
    benign = [r for r in rows if not r["entry"]["malicious"]]
    obfuscated = [r for r in malicious if r["entry"]["obfuscation"] != "none"]

    checks: list[tuple[str, bool]] = []

    # (a) GlyphHound catches every malicious payload (incl. all obfuscated).
    gh_all_malicious = all(r["glyphhound"]["caught"] for r in malicious)
    checks.append(("(a) GlyphHound catches every malicious payload, incl. all obfuscated "
                   f"({sum(r['glyphhound']['caught'] for r in malicious)}/{len(malicious)})",
                   gh_all_malicious))

    # (b) GlyphHound zero FP on benign.
    gh_no_fp = not any(r["glyphhound"]["caught"] for r in benign)
    checks.append((f"(b) GlyphHound zero false positives on benign controls "
                   f"({sum(r['glyphhound']['caught'] for r in benign)}/{len(benign)})", gh_no_fp))

    # (c) ModelAudit catches the plain control -> fair invocation.
    plain = by_file.get("01_plain_chain.jinja")
    ma_plain_ok = bool(plain and plain["modelaudit"]["caught"])
    checks.append(("(c) ModelAudit catches the PLAIN control (fair invocation proof)", ma_plain_ok))

    # (c2) ModelAudit's optional dynamic sandbox-render test is ACTIVE (jinja2 importable) ->
    # we benchmark its STRONGEST config, not a regex-only crippled one (Rule 3). Checked
    # deterministically (jinja2 present), NOT via a render catch (that worker is timing-
    # dependent and non-deterministic -- see benchmark/README.md).
    ma_sandbox_active = bench.modelaudit_sandbox_render_available(exe)
    checks.append(("(c2) ModelAudit's dynamic sandbox test is active (jinja2 present -> "
                   "strongest config benchmarked, incumbent not under-powered)", ma_sandbox_active))

    # (d) ModelAudit zero FP on benign.
    ma_no_fp = not any(r["modelaudit"]["caught"] for r in benign)
    checks.append((f"(d) ModelAudit zero false positives on benign controls "
                   f"({sum(r['modelaudit']['caught'] for r in benign)}/{len(benign)})", ma_no_fp))

    # (e) Core claim: >=1 obfuscation GlyphHound catches and ModelAudit misses.
    edge = [r for r in obfuscated if r["glyphhound"]["caught"] and not r["modelaudit"]["caught"]]
    checks.append((f"(e) CORE CLAIM substantiated: >=1 obfuscation GlyphHound catches that "
                   f"ModelAudit misses (measured {len(edge)})", len(edge) >= 1))

    # (f) Live results match the manifest's locked expectations (per payload).
    mismatches = []
    for r in rows:
        e = r["entry"]
        if r["glyphhound"]["caught"] != e["gh_expected"]:
            mismatches.append(f"{e['file']}: GlyphHound live={r['glyphhound']['caught']} != locked={e['gh_expected']}")
        if r["modelaudit"]["caught"] != e["modelaudit_expected"]:
            mismatches.append(f"{e['file']}: ModelAudit live={r['modelaudit']['caught']} != locked={e['modelaudit_expected']}")
    for m in mismatches:
        print(f"    MISMATCH: {m}")
    checks.append(("(f) Live results match the manifest's measured-then-locked expectations",
                   not mismatches and version_ok))

    # (g) Determinism: a second independent run yields a byte-identical table.
    rows2 = bench.run_benchmark(exe, manifest)
    table1 = bench.format_table(rows, modelaudit_version_str=live_version)
    table2 = bench.format_table(rows2, modelaudit_version_str=live_version)
    checks.append(("(g) Determinism: two runs produce a byte-identical table (Rule 7)",
                   table1 == table2))

    print()
    all_ok = True
    for label, ok in checks:
        print(f"[{'OK' if ok else 'FAIL'}] {label}")
        all_ok = all_ok and ok

    print()
    _print_header(f"Phase 8: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
