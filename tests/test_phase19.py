"""Phase 19 — close hidden string-building obfuscation bypasses (Mul / printf / |string).

Fixture-driven (the project conventions): a dunder hidden behind ``'_' * 2``, ``'%s' % (...)`` /
``|format``, or wrapped in ``|string`` folds to its constant value before the unchanged
identifier-only walk, so the chain gates. Benign uses of the same ops (separator lines, printf
with variables) stay clean (Rule 9). The folds are bounded so a pathological repetition / width
cannot allocate a giant transient (Rule 7). All offline, parse-only — fixtures are never rendered.
"""

from __future__ import annotations

import os

import pytest

from glyphhound.analyze import analyze_ast, analyze_template
from glyphhound.parse import parse_template
from glyphhound.report import make_report

ROOT = os.path.dirname(os.path.dirname(__file__))
MAL = os.path.join(ROOT, "fixtures", "malicious")
FIXTURES = ["mul_repeat_marker.jinja", "printf_marker.jinja", "string_cast_marker.jinja"]


def _read(p: str) -> str:
    return open(p, encoding="utf-8").read()


def _gates(t: str) -> bool:
    return make_report(analyze_template(t)).exit_code == 1


def _reach(findings) -> set[str]:
    return {f.rule_id for f in findings if f.reachable}


@pytest.mark.parametrize("fname", FIXTURES)
def test_fixture_zero_raw_then_reachable_gating(fname):
    src = _read(os.path.join(MAL, fname))
    assert analyze_ast(parse_template(src)) == []          # 0 findings without the fold
    full = analyze_template(src)
    assert {"GH-S001", "GH-S002"} <= _reach(full)          # reachable dunder + code-exec name
    assert make_report(full).exit_code == 1                 # gates CI


@pytest.mark.parametrize("form", [
    "{{ cycler['_'*2 ~ 'init' ~ '_'*2] }}",          # repetition (Mul), ~ join
    "{{ cycler['_'*2 + 'init' + '_'*2] }}",          # repetition (Mul), + join
    "{{ cycler['__'*1 ~ 'init' ~ '__'*1] }}",        # repetition by 1
    "{{ cycler['%sinit%s' % ('__','__')] }}",        # printf via % (tuple)
    "{{ cycler['__%s__' % 'init'] }}",               # printf via % (single arg)
    "{{ cycler['%sinit%s'|format('__','__')] }}",    # printf via |format
    "{{ cycler|attr('%sinit%s'|format('__','__')) }}",  # |format inside |attr
    "{{ cycler[('__in'+'it__')|string] }}",          # |string cast around a folded concat
])
def test_hidden_builder_gates(form):
    assert _gates(form)
    assert "GH-S001" in _reach(analyze_template(form))


@pytest.mark.parametrize("form", [
    "{{ '=' * 40 }}",                       # separator line — folds to a long string, no sink
    "{{ '-' * 3 }}",
    "{{ '%s: %s' % (role, content) }}",     # printf with VARIABLES -> not folded
    "{{ 'Total: %d%%' % 100 }}",            # all-const printf -> 'Total: 100%' (not a sink)
    "{{ '%d'|format(count) }}",             # |format with a variable -> not folded
    "{{ name|string }}",
    "{{ messages|first }}{{ messages|last }}",
])
def test_benign_uses_stay_clean(form):
    assert analyze_template(form) == []


def test_huge_mul_is_bounded_not_folded_no_crash():
    # 'x' * 10**9 would be ~1 GB if computed; the bound rejects it BEFORE computing.
    findings = analyze_template("{{ cycler['_' * 1000000000 ~ 'init'] }}")
    assert not any(f.reachable for f in findings)


def test_huge_printf_width_is_bounded_not_folded():
    findings = analyze_template("{{ cycler['%99999999s' % '__init__'] }}")
    assert not any(f.reachable for f in findings)


@pytest.mark.parametrize("form", [
    "{{ cycler['%*s' % (1000000000, 'x')] }}",        # arg-supplied width via %
    "{{ cycler['%-*s' % (1000000000, 'x')] }}",       # arg-supplied width, left-justified
    "{{ cycler['%.*f' % (1000000000, 1.0)] }}",       # arg-supplied precision via %
    "{{ cycler['%*s'|format(1000000000, 'x')] }}",    # arg-supplied width via |format
])
def test_arg_supplied_printf_width_is_refused_no_giant_alloc(form):
    # The `*` width/precision comes from an argument, not the format string; folding it would
    # allocate a ~1 GB transient. _apply_printf must refuse it BEFORE computing (Rule 7).
    findings = analyze_template(form)
    assert not any(f.reachable for f in findings)


def test_zero_and_negative_mul_do_not_crash():
    analyze_template("{{ cycler['x' * 0] }}")
    analyze_template("{{ cycler['x' * -3] }}")


@pytest.mark.parametrize("form", [
    "{{ cycler[['__init__'][0]] }}",                          # literal visible: list index
    "{{ cycler[{'k':'__init__'}['k']] }}",                    # literal visible: dict subscript
    "{% set ns = namespace(c='__init__') %}{{ cycler[ns.c] }}",  # literal visible: namespace attr
    "{{ ''[messages[0].role] }}",                             # dynamic name (permanent ceiling)
])
def test_documented_gap_stays_unflagged(form):
    assert not any(f.reachable for f in analyze_template(form))
