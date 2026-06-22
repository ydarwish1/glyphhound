"""Phase 1 verification -- parse real chat templates into Jinja2 ASTs.

Offline and deterministic: it parses the vendored benign
corpus (real templates extracted earlier by ``scripts/build_corpus.py``, pinned by
commit SHA in ``fixtures/benign/PROVENANCE.json``) -- no network, no weights.

Checks:
  1. >=10 real templates parse with no error.
  2. The AST dump of a known template matches the expected golden, exactly.
  3. Parsing is deterministic: same template -> identical dump.

Run:  .venv/Scripts/python.exe scripts/verify_phase1.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from jinja2 import nodes  # noqa: E402

from glyphhound.parse import ParseError, dump_ast, parse_template  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
GOLDEN_DIR = os.path.join(ROOT, "tests", "golden")


def _node_count(ast: nodes.Node) -> int:
    return sum(1 for _ in ast.find_all(nodes.Node)) + 1  # +1 for the Template root


def verify_corpus() -> bool:
    print("=" * 78)
    print("Phase 1 -- parse real chat templates -> Jinja2 AST (offline corpus)")
    print("=" * 78)
    provenance = json.load(open(os.path.join(BENIGN_DIR, "PROVENANCE.json"), encoding="utf-8"))
    parsed = 0
    all_ok = True
    for entry in provenance:
        path = os.path.join(BENIGN_DIR, entry["file"])
        src = open(path, encoding="utf-8").read()
        try:
            ast = parse_template(src)
        except ParseError as e:
            all_ok = False
            print(f"\n[FAIL] {entry['model']}: {e}")
            continue
        # Determinism: a second parse must yield an identical dump.
        if dump_ast(ast) != dump_ast(parse_template(src)):
            all_ok = False
            print(f"\n[FAIL] {entry['model']}: non-deterministic dump")
            continue
        parsed += 1
        print(f"[OK] {entry['model']:46s} {entry['template_chars']:5d} chars  "
              f"{_node_count(ast):4d} AST nodes  rev {entry['revision'][:10]}")
    print(f"\nParsed {parsed} real templates with no error (need >=10).")
    return all_ok and parsed >= 10


def verify_golden() -> bool:
    print("\n" + "=" * 78)
    print("Phase 1 -- AST dump matches expected golden for a known template")
    print("=" * 78)
    src = open(os.path.join(GOLDEN_DIR, "known_template.jinja"), encoding="utf-8").read()
    expected = open(os.path.join(GOLDEN_DIR, "known_template.ast.txt"), encoding="utf-8").read()
    actual = dump_ast(parse_template(src)) + "\n"
    if actual == expected:
        print(f"\n[OK] dump matches golden ({expected.count(chr(10))} lines), "
              "incl. Getattr chains, getattr() Call, Add string-concat, attr Filter.")
        return True
    print("\n[FAIL] golden mismatch:")
    exp_lines, act_lines = expected.splitlines(), actual.splitlines()
    for i in range(max(len(exp_lines), len(act_lines))):
        e = exp_lines[i] if i < len(exp_lines) else "<none>"
        a = act_lines[i] if i < len(act_lines) else "<none>"
        if e != a:
            print(f"  line {i+1}: expected {e!r} got {a!r}")
    return False


def main() -> int:
    corpus_ok = verify_corpus()
    golden_ok = verify_golden()
    print("\n" + "=" * 78)
    print(f"Phase 1: {'PASS' if corpus_ok and golden_ok else 'FAIL'} "
          f"(corpus {'ok' if corpus_ok else 'FAIL'}, golden {'ok' if golden_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if corpus_ok and golden_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
