"""Phase 2 verification — sink detection (string/structural baseline).

Offline and deterministic (the project conventions): it analyzes on-disk fixtures and the
vendored benign corpus — no network, no weights, and it never *renders* a template
(only parses + walks the AST), so reading the malicious fixtures cannot execute them.

Checks (the design docs / the project history Phase 2 tracker):
  1. The CVE-2024-34359 MARKER fixture (and the |attr pivot fixture) are FLAGGED.
  2. The real benign corpus is CLEAN — zero false positives (Rule 9).
  3. §7 payoff: a model whose DEFAULT template is benign but a NAMED template carries
     the sink is caught, and the finding is tagged with the named template.

Run:  .venv/Scripts/python.exe scripts/verify_phase2.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.acquire import ChatTemplate, RawTemplate  # noqa: E402
from glyphhound.analyze import analyze_raw, analyze_template  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


def verify_malicious_flagged() -> bool:
    print("=" * 78)
    print("Phase 2 — malicious MARKER fixtures must be FLAGGED")
    print("=" * 78)
    files = _jinja_files(MALICIOUS_DIR)
    all_ok = bool(files)
    for fname in files:
        findings = analyze_template(_read(os.path.join(MALICIOUS_DIR, fname)))
        if findings:
            rules = ", ".join(sorted({f.rule_id for f in findings}))
            lines = sorted({f.source_line for f in findings})
            print(f"[OK]   {fname:38s} {len(findings)} finding(s)  rules: {rules}  line(s): {lines}")
        else:
            all_ok = False
            print(f"[FAIL] {fname:38s} produced NO findings (should flag)")
    return all_ok


def verify_benign_clean() -> bool:
    print("\n" + "=" * 78)
    print("Phase 2 — real benign corpus must be CLEAN (Rule 9: measured false positives)")
    print("=" * 78)
    files = _jinja_files(BENIGN_DIR)
    flagged = 0
    for fname in files:
        findings = analyze_template(_read(os.path.join(BENIGN_DIR, fname)))
        if findings:
            flagged += 1
            rules = ", ".join(sorted({f.rule_id for f in findings}))
            print(f"[FAIL] {fname:46s} wrongly flagged: {rules}")
        else:
            print(f"[OK]   {fname:46s} clean")
    fp_rate = flagged / len(files) if files else 1.0
    print(f"\nFalse positives: {flagged}/{len(files)} benign templates ({fp_rate:.1%}).")
    return flagged == 0 and len(files) >= 10


def verify_named_template_payoff() -> bool:
    print("\n" + "=" * 78)
    print("Phase 2 — §7 payoff: sink hidden in a NAMED template is still caught")
    print("=" * 78)
    raw = RawTemplate(
        source_ref="synthetic://hidden-sink",
        templates=(
            ChatTemplate(None, "{% for m in messages %}{{ m.role }}: {{ m.content }}{% endfor %}"),
            ChatTemplate("tool_use", "{{ self.__init__.__globals__.__builtins__ }}"),
        ),
        bytes_fetched=1,
        total_size=1000,
    )
    findings = analyze_raw(raw)
    tagged = sorted({f.template_name for f in findings}, key=lambda n: (n is not None, n or ""))
    print(f"Default template (benign): {sum(1 for f in findings if f.template_name is None)} finding(s)")
    print(f"Named template 'tool_use': {sum(1 for f in findings if f.template_name == 'tool_use')} finding(s)")
    ok = bool(findings) and {f.template_name for f in findings} == {"tool_use"}
    print(f"\n[{'OK' if ok else 'FAIL'}] findings exist and are tagged exactly to the named template "
          f"(tags seen: {tagged}).")
    return ok


def main() -> int:
    mal_ok = verify_malicious_flagged()
    benign_ok = verify_benign_clean()
    named_ok = verify_named_template_payoff()
    print("\n" + "=" * 78)
    ok = mal_ok and benign_ok and named_ok
    print(f"Phase 2: {'PASS' if ok else 'FAIL'} "
          f"(malicious {'ok' if mal_ok else 'FAIL'}, benign {'ok' if benign_ok else 'FAIL'}, "
          f"named {'ok' if named_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
