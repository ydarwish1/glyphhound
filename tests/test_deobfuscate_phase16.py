"""Offline, deterministic tests for the Phase-16 de-obfuscation: close the confirmed
case-fold and reverse-slice bypasses (Rule 8).

A live read-only test (2026-06-22) confirmed two obfuscations slipped past the analyzer:
case-fold filters (``''['__CLASS__'|lower]``) and negative/reverse slices
(``''['__ssalc__'[::-1]]``). Phase 16 extends the constant-string fold to a whitelist of
pure, side-effect-free string transforms (``lower``/``upper``/``title``/``capitalize``/
``swapcase``/``trim``/``strip``/``reverse``) and teaches the slice/index bound to accept a
``Neg(Const(int))``, so each obfuscated identifier folds to its constant value BEFORE the
unchanged identifier-only walk. Each obfuscated form must fold to a *reachable* dunder sink,
while the same transforms over benign content must stay clean (the false-positive guard,
Rule 9). Folding is a static AST rewrite over string literals only — nothing is evaluated
dynamically or rendered (Rule 4/Rule 6).
"""

from __future__ import annotations

import copy
import os

import pytest

from glyphhound.analyze import analyze_ast, analyze_template
from glyphhound.analyze.models import CODE_EXEC_NAMES, DANGEROUS_DUNDERS
from glyphhound.parse import normalize, parse_template
from glyphhound.report import make_report

ROOT = os.path.dirname(os.path.dirname(__file__))
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
_DANGEROUS = DANGEROUS_DUNDERS | CODE_EXEC_NAMES


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


def _normalize(src: str):
    return normalize(parse_template(src), dangerous_names=_DANGEROUS)


def _reachable_rules(findings) -> set[str]:
    return {f.rule_id for f in findings if f.reachable}


# --------------------------------------------------------------------------- #
# Each newly-folded obfuscation exposes a reachable dunder sink (GH-S001).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("form", [
    "{{ ''['__CLASS__'|lower] }}",            # the reported case-fold bypass
    "{{ ''['__ssalc__'[::-1]] }}",            # the reported reverse-slice bypass
    "{{ ''['__ssalc__'|reverse] }}",          # reverse via the filter form
    "{{ ''['__CLASS__'|swapcase] }}",         # swapcase
    "{{ ''[' __class__ '|trim] }}",           # whitespace trim
    "{{ ''[' __class__ '|strip] }}",          # whitespace strip
    "{{ ''['__class__'|upper|lower] }}",      # chained transforms fold bottom-up
    "{{ ''['__CL'|lower + 'ASS__'|lower] }}", # transform feeding a concat
])
def test_obfuscated_dunder_folds_to_reachable_critical(form):
    findings = analyze_template(form)
    assert any(f.rule_id == "GH-S001" and f.reachable for f in findings), form
    assert make_report(findings).exit_code == 1, form


# --------------------------------------------------------------------------- #
# The two MARKER fixtures: 0 findings WITHOUT folding, reachable + gating WITH.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fname", [
    "casefold_filter_marker.jinja",
    "reverse_slice_marker.jinja",
])
def test_phase16_fixture_misses_raw_but_gates_with_fold(fname):
    src = _read(os.path.join(MALICIOUS_DIR, fname))
    assert analyze_ast(parse_template(src)) == []          # raw walker sees nothing
    findings = analyze_template(src)
    assert _reachable_rules(findings) >= {"GH-S001", "GH-S002"}
    assert make_report(findings).exit_code == 1


# --------------------------------------------------------------------------- #
# `normalize` produces the right constant value, and only over constants.
# --------------------------------------------------------------------------- #
def test_lower_filter_folds_to_its_constant_value():
    n = _normalize("{{ ''['__CLASS__'|lower] }}")
    assert any("lower -> '__class__'" in a for a in n.deobfuscations_applied)


def test_reverse_slice_folds_to_its_constant_value():
    n = _normalize("{{ ''['__ssalc__'[::-1]] }}")
    assert any("const-slice -> '__class__'" in a for a in n.deobfuscations_applied)


def test_transform_on_a_variable_operand_is_not_folded():
    # The operand is a Name (runtime value), not a Const — nothing to fold (left to taint).
    n = _normalize("{{ x|lower }}")
    assert n.deobfuscations_applied == ()


def test_transform_with_an_argument_is_left_unfolded():
    # Only the pure no-argument transforms fold; an argument-bearing form is left to taint.
    n = _normalize("{{ '__CLASS__'|lower('x') }}")
    assert not any("lower ->" in a for a in n.deobfuscations_applied)


def test_negative_index_bound_is_recognised_in_a_slice():
    # `[1:-1]` — the stop bound is Neg(Const(1)); the slice must still fold.
    n = _normalize("{{ 'X__class__X'[1:-1] }}")
    assert any("const-slice -> '__class__'" in a for a in n.deobfuscations_applied)


# --------------------------------------------------------------------------- #
# Robustness: a zero-step slice must not crash the scanner and must not fold.
# --------------------------------------------------------------------------- #
def test_zero_step_slice_does_not_crash_or_fold():
    findings = analyze_template("{{ ''['abc'[::0]] }}")  # must not raise ValueError
    assert findings == []


# --------------------------------------------------------------------------- #
# False-positive guard (Rule 9): benign transforms over real content stay clean.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("benign", [
    "{{ 'Hello'|lower }}",                         # a folded Const is never inspected
    "{{ message['role']|lower }}: {{ message['content'] }}",  # variable operand, not folded
    "{{ 'system'|upper }}",                        # 'SYSTEM' is not a catalog identifier
    "{{ cfg['SYSTEM'|lower] }}",                   # cfg['system'] on an untainted base (Phase 15)
    "{{ 'elor'[::-1] }}",                          # reversed benign word ('role')
    "{{ name|trim }} {{ content|capitalize }}",    # variable operands
])
def test_benign_transforms_stay_clean(benign):
    assert analyze_template(benign) == []


def test_benign_fixtures_stay_clean_after_phase16():
    for fname in _jinja_files(BENIGN_DIR):
        findings = analyze_template(_read(os.path.join(BENIGN_DIR, fname)))
        assert not any(f.reachable for f in findings), fname
        assert findings == [], fname


# --------------------------------------------------------------------------- #
# The permanent static ceiling: a fully dynamic / runtime name is NOT folded.
# Documented limit — the gated sandbox (`--confirm`) is the backstop, never rendering here.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dynamic", [
    "{{ ''[messages[0].role] }}",                  # runtime-built name
    "{% for ch in '__class__' %}{{ ''[ch] }}{% endfor %}",  # loop-built, char by char
])
def test_fully_dynamic_names_remain_a_documented_limit(dynamic):
    assert not any(f.reachable for f in analyze_template(dynamic)), dynamic


# --------------------------------------------------------------------------- #
# Determinism + non-mutation (Rule 7): normalize rewrites a copy, twice == once.
# --------------------------------------------------------------------------- #
def test_normalize_does_not_mutate_input_and_is_deterministic():
    src = "{{ ''['__CLASS__'|lower] }}"
    ast = parse_template(src)
    before = copy.deepcopy(ast)
    a = normalize(ast, dangerous_names=_DANGEROUS)
    b = normalize(before, dangerous_names=_DANGEROUS)
    assert a.deobfuscations_applied == b.deobfuscations_applied
    # the original `ast` still has the unfolded Filter node (input was not mutated)
    assert any("lower ->" in x for x in a.deobfuscations_applied)
