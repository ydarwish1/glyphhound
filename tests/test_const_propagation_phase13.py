"""Offline tests for Phase 13 — constant-propagation.

Fixture-driven (the project conventions): a dangerous identifier held in a ``{% set %}``
variable must flag reachable after propagation, while benign / re-bound / loop / parameter
variables must NOT be propagated (Rule 9 — the real benign corpus stays clean). The
analyzer only parses + walks the AST here; nothing is rendered.
"""

from __future__ import annotations

import os

import pytest
from jinja2 import nodes

from glyphhound.analyze import analyze_ast, analyze_template
from glyphhound.analyze.models import CODE_EXEC_NAMES, DANGEROUS_DUNDERS
from glyphhound.parse import normalize, parse_template
from glyphhound.report import make_report

ROOT = os.path.dirname(os.path.dirname(__file__))
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
FIXTURE = os.path.join(MALICIOUS_DIR, "const_propagation_marker.jinja")

_DANGEROUS = DANGEROUS_DUNDERS | CODE_EXEC_NAMES


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _jinja_files(directory: str) -> list[str]:
    return sorted(f for f in os.listdir(directory) if f.endswith(".jinja"))


# --- the fixture: 0 without propagation, reachable + gating with it -------------

def test_fixture_misses_raw_but_flags_reachable_and_gates():
    src = _read(FIXTURE)
    # the raw walker (no normalize) sees the subscript keys as Name loads -> nothing.
    assert analyze_ast(parse_template(src)) == []
    findings = analyze_template(src)
    assert any(f.reachable and f.rule_id == "GH-S001" for f in findings)
    assert make_report(findings).exit_code == 1


def test_single_variable_held_dunder_subscript_flags():
    findings = analyze_template("{% set c = '__class__' %}{{ x[c] }}")
    assert any(f.reachable and f.rule_id == "GH-S001" for f in findings)


def test_propagate_then_fold_reaches_concatenated_dunder():
    # {% set a='__re' %}{% set b='duce__' %}{{ x[a+b] }} -> x['__reduce__'] (propagate, then fold)
    findings = analyze_template("{% set a = '__re' %}{% set b = 'duce__' %}{{ x[a + b] }}")
    assert any(f.reachable and "__reduce__" in f.evidence for f in findings)


def test_propagated_dunder_in_attr_filter_reaches():
    # Without propagation `x|attr(g)` is a generic, non-reachable GH-S003 pivot (computed arg);
    # propagating g='__globals__' makes the |attr argument a dangerous Const -> reachable GH-S001.
    findings = analyze_template("{% set g = '__globals__' %}{{ x|attr(g) }}")
    assert any(f.reachable and f.rule_id == "GH-S001" for f in findings)


# --- conservative scoping: these must NOT be propagated (no false positives) -----

@pytest.mark.parametrize("template", [
    # 'system' lands as a filter argument, which the walk never inspects.
    "{% set role = 'system' %}{{ messages|selectattr('role','eq',role)|list }}",
    # a benign constant key.
    "{% set k = 'content' %}{{ m[k] }}",
    # re-bound to a non-constant -> the name is dropped entirely (conservative).
    "{% set y = '__class__' %}{% set y = user %}{{ obj[y] }}",
    # two different constant bindings -> ambiguous -> dropped.
    "{% if t %}{% set z = '__class__' %}{% else %}{% set z = 'role' %}{% endif %}{{ obj[z] }}",
    # a loop variable is not a constant set.
    "{% for x in items %}{{ obj[x] }}{% endfor %}",
    # bound to a runtime value (a Getattr) -> never propagated.
    "{% set c = item.key %}{{ x[c] }}",
    # a bare load becomes a Const, which is not an identifier the walk inspects.
    "{% set role = 'system' %}{{ role }}",
])
def test_propagation_introduces_no_false_positive(template):
    assert analyze_template(template) == []


def test_rebind_drops_even_the_constant_binding():
    # 'c' has a non-constant store occurrence too -> not propagated at all (conservative).
    findings = analyze_template("{% set c = '__class__' %}{{ x[c] }}{% set c = user %}")
    assert findings == []


# --- determinism + isolation -----------------------------------------------------

def test_normalize_does_not_mutate_input_ast():
    ast = parse_template("{% set c = '__class__' %}{{ x[c] }}")
    normalize(ast, dangerous_names=_DANGEROUS)
    # the ORIGINAL ast is untouched (normalize rewrites a deep copy): the load is still a Name.
    load_names = {n.name for n in ast.find_all(nodes.Name) if n.ctx == "load"}
    assert "c" in load_names


def test_propagation_is_deterministic():
    src = _read(FIXTURE)
    a = [(f.rule_id, f.evidence, f.reachable) for f in analyze_template(src)]
    b = [(f.rule_id, f.evidence, f.reachable) for f in analyze_template(src)]
    assert a == b


# --- Rule 9: the real benign fixtures stay clean after propagation ---------------

@pytest.mark.parametrize("fname", _jinja_files(BENIGN_DIR))
def test_benign_fixtures_stay_clean_after_propagation(fname):
    findings = analyze_template(_read(os.path.join(BENIGN_DIR, fname)))
    assert findings == [], f"{fname} wrongly flagged after constant-propagation: {findings}"
