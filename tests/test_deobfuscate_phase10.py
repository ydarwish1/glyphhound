"""Offline, deterministic tests for the Phase-10 de-obfuscation coverage++ (Rule 8).

Phase 10 widens the fold from constant `+`/`~` concatenation to the other ways an identifier
can be assembled from string literals — `str.format()`, constant slice/index, the `|join`
and `|replace` filters — and resolves the dunder name when it hides in a keyword argument
(`getattr(obj, name=...)`, `x|attr(name=...)`). Each obfuscated form must fold to a
*reachable* dunder/code-exec sink, while the same operations over benign content must stay
clean (the false-positive guard, Rule 9). Folding is a static AST rewrite over string
literals only — nothing is evaluated dynamically or rendered (Rule 4/Rule 6).
"""

from __future__ import annotations

import os

import pytest

from glyphhound.analyze import analyze_ast, analyze_template
from glyphhound.analyze.models import DANGEROUS_DUNDERS, CODE_EXEC_NAMES
from glyphhound.parse import dump_ast, normalize, parse_template

ROOT = os.path.dirname(os.path.dirname(__file__))
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
_DANGER = DANGEROUS_DUNDERS | CODE_EXEC_NAMES


def _read(fname: str) -> str:
    return open(os.path.join(MALICIOUS_DIR, fname), encoding="utf-8").read()


def _reachable_rules(findings) -> set[str]:
    return {f.rule_id for f in findings if f.reachable}


# --------------------------------------------------------------------------- #
# Each new obfuscation family folds to a reachable dunder/code-exec sink.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("form", [
    "{{ x['{0}{1}'.format('__cl', 'ass__')] }}",
    "{{ x['{a}'.format(a='__class__')] }}",
    "{{ x['__class__ZZ'[:9]] }}",
    "{{ x[['__cl', 'ass__']|join] }}",
    "{{ x['__ZZZZ__'|replace('ZZZZ', 'class')] }}",
    "{{ getattr(x, name='__cl' + 'ass__') }}",
    "{{ x|attr(name='__cl' + 'ass__') }}",
    "{{ getattr(x, '{}'.format('__class__')) }}",
])
def test_obfuscated_dunder_folds_to_reachable_critical(form):
    findings = analyze_template(form)
    assert any(f.rule_id == "GH-S001" and f.reachable for f in findings), form


@pytest.mark.parametrize("fname", [
    "format_builder_marker.jinja",
    "slice_builder_marker.jinja",
    "join_builder_marker.jinja",
    "replace_builder_marker.jinja",
    "kwarg_call_marker.jinja",
])
def test_family_fixture_is_reachable(fname):
    findings = analyze_template(_read(fname))
    reach = _reachable_rules(findings)
    assert "GH-S001" in reach and "GH-S002" in reach, (fname, reach)
    assert any(f.severity == "critical" and f.reachable for f in findings)


@pytest.mark.parametrize("fname", [
    "format_builder_marker.jinja",
    "slice_builder_marker.jinja",
    "join_builder_marker.jinja",
    "replace_builder_marker.jinja",
])
def test_family_fixture_invisible_without_folding(fname):
    """The headline contrast: a string-matcher (and the raw, un-folded walk) sees nothing."""
    raw = analyze_ast(parse_template(_read(fname)))
    assert raw == [], fname


def test_kwarg_getattr_is_upgraded_from_reflection_to_dunder():
    """getattr(obj, name='__class__') was a GH-S004 reflection call; Phase 10 makes it the
    precise GH-S001 dunder (the redundant reflection finding is replaced)."""
    src = "{{ getattr(x, name='__cl' + 'ass__') }}"
    before = {f.rule_id for f in analyze_ast(parse_template(src))}
    after = analyze_template(src)
    assert "GH-S004" in before  # raw walker still sees only the reflection call
    assert any(f.rule_id == "GH-S001" and f.reachable for f in after)
    assert all(f.rule_id != "GH-S004" for f in after)


# --------------------------------------------------------------------------- #
# The same operations over benign content must NOT flag (Rule 9 — no new FPs).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("benign", [
    "{{ 'r{}e'.format('ol') }}",            # builds 'role'
    "{{ '{}: {}'.format(a, b) }}",          # real formatting, non-constant args -> not folded
    "{{ 'hello world'[:5] }}",              # 'hello'
    "{{ messages[0]['content'] }}",         # ordinary subscripting of a real object
    "{{ ['a', 'b', 'c']|join(', ') }}",     # 'a, b, c'
    "{{ 'a_b_c'|replace('_', ' ') }}",      # 'a b c'
    "{{ '{}'.format(user_name) }}",         # non-constant -> not folded
])
def test_benign_string_ops_stay_clean(benign):
    assert analyze_template(benign) == [], benign


# --------------------------------------------------------------------------- #
# Audit trail, determinism, and safety bounds.
# --------------------------------------------------------------------------- #
def test_deobfuscations_applied_records_the_fold():
    norm = normalize(parse_template("{{ x['{0}{1}'.format('__cl', 'ass__')] }}"),
                     dangerous_names=_DANGER)
    assert any("str.format" in note and "__class__" in note for note in norm.deobfuscations_applied)


def test_fold_is_deterministic():
    src = "{{ x[['__cl', 'ass__']|join]['{}'.format('__globals__')] }}"
    assert analyze_template(src) == analyze_template(src)
    a = normalize(parse_template(src), dangerous_names=_DANGER).deobfuscations_applied
    b = normalize(parse_template(src), dangerous_names=_DANGER).deobfuscations_applied
    assert a == b


def test_normalize_does_not_mutate_input_ast():
    ast = parse_template("{{ x['{}'.format('__class__')] }}")
    before = dump_ast(ast)
    normalize(ast, dangerous_names=_DANGER)
    assert dump_ast(ast) == before  # the fold rewrites a deep copy


def test_non_constant_operands_are_not_folded():
    # A format/slice/join/replace with a non-constant operand must be left untouched, so no
    # phantom identifier is invented from runtime data.
    for src in ("{{ x['{}'.format(evil)] }}", "{{ x[s[:9]] }}", "{{ x[parts|join] }}",
                "{{ x[s|replace('a', 'b')] }}"):
        assert analyze_template(src) == [], src


def test_format_field_access_is_never_evaluated():
    """A str.format field that accesses attributes (`{0.__class__...}`) must NOT be folded —
    folding would make str.format traverse Python internals at analysis time (Rule 4/6). It is
    left unfolded (so no fold note, and no dunder finding is invented from the traversal)."""
    for src in ("{{ y['{0.__class__}'.format('x')] }}",
                "{{ y['{0.__class__.__init__.__globals__}'.format('x')] }}",
                "{{ y['{0[0]}'.format('abc')] }}"):
        norm = normalize(parse_template(src), dangerous_names=_DANGER)
        assert all("str.format" not in n for n in norm.deobfuscations_applied), src
        # And it must not produce a reachable dunder finding from the un-evaluated access.
        assert not any(f.reachable for f in analyze_template(src)), src


def test_pathological_format_width_is_not_folded():
    # '{:>9999999}'.format('x') would expand to a multi-MB string; the length cap rejects it
    # (it is never a hidden identifier) and the analysis stays bounded.
    src = "{{ x['{:>9999999}'.format('y')] }}"
    norm = normalize(parse_template(src), dangerous_names=_DANGER)
    assert all("str.format" not in n for n in norm.deobfuscations_applied)
