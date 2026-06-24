"""Offline, deterministic tests for the Stage-2 parser (Phase 1).

No network and no weights: the golden-template test is fully self-contained, and the
real-template tests parse the vendored benign corpus (``fixtures/benign/``, extracted
once by ``scripts/build_corpus.py`` and pinned by commit SHA in PROVENANCE.json).
"""

from __future__ import annotations

import json
import os

import pytest
from jinja2 import nodes

from glyphhound.parse import (
    PARSE_EXTENSIONS,
    ParseError,
    dump_ast,
    make_parse_environment,
    parse_template,
)

ROOT = os.path.dirname(os.path.dirname(__file__))
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
GOLDEN_DIR = os.path.join(ROOT, "tests", "golden")


def _corpus_files() -> list[str]:
    provenance = json.load(open(os.path.join(BENIGN_DIR, "PROVENANCE.json"), encoding="utf-8"))
    return [entry["file"] for entry in provenance]


# --- the golden "known template" ------------------------------------------------

def test_known_template_dump_matches_golden():
    src = open(os.path.join(GOLDEN_DIR, "known_template.jinja"), encoding="utf-8").read()
    expected = open(os.path.join(GOLDEN_DIR, "known_template.ast.txt"), encoding="utf-8").read()
    assert dump_ast(parse_template(src)) + "\n" == expected


def test_dump_is_deterministic():
    src = open(os.path.join(GOLDEN_DIR, "known_template.jinja"), encoding="utf-8").read()
    assert dump_ast(parse_template(src)) == dump_ast(parse_template(src))


def test_dump_has_no_line_numbers():
    # A comment produces no AST node but still advances the line counter, so the
    # Getattr sits on a later lineno in b. The dump walks node.fields only (never
    # node.attributes: lineno/environment), so both dumps must be identical.
    a = dump_ast(parse_template("{{ x.__class__ }}"))
    b = dump_ast(parse_template("{#\n\n\n#}{{ x.__class__ }}"))
    assert a == b


# --- real corpus parses (>=10 distinct real templates, no error) ----------------

def test_corpus_has_at_least_ten_templates():
    assert len(_corpus_files()) >= 10


@pytest.mark.parametrize("fname", _corpus_files())
def test_real_template_parses(fname):
    src = open(os.path.join(BENIGN_DIR, fname), encoding="utf-8").read()
    ast = parse_template(src)
    assert isinstance(ast, nodes.Template)
    # A real chat template is non-trivial: it has more than just the root node.
    assert sum(1 for _ in ast.find_all(nodes.Node)) > 1


# --- security-relevant node capture ---------------------------------------------

def test_attribute_chain_is_captured():
    # The analyzer (Phase 2/3) relies on Getattr chains being visible in the AST.
    ast = parse_template("{{ cycler.__init__.__globals__ }}")
    attrs = [n.attr for n in ast.find_all(nodes.Getattr)]
    assert attrs == ["__globals__", "__init__"]  # outermost first


def test_attr_filter_pivot_is_captured():
    ast = parse_template("{{ ''|attr('__class__') }}")
    filters = [n.name for n in ast.find_all(nodes.Filter)]
    assert "attr" in filters


def test_do_and_loopcontrols_extensions_parse():
    # Without these extensions Jinja raises TemplateSyntaxError; we enable them so a
    # malicious {% do evil() %} is analyzed, not silently unparseable.
    assert "jinja2.ext.do" in PARSE_EXTENSIONS
    parse_template("{% set ns = namespace(x=1) %}{% do ns.update() %}")
    parse_template("{% for i in [1, 2] %}{% break %}{% endfor %}")


# --- error handling -------------------------------------------------------------

def test_malformed_template_raises_parse_error():
    with pytest.raises(ParseError):
        parse_template("{% for x in %}")  # syntax error


def test_unclosed_block_raises_parse_error():
    with pytest.raises(ParseError):
        parse_template("{% if x %}never closed")


def test_parse_environment_has_extensions():
    # env.extensions is keyed by the extension class identifier, not the alias we pass.
    loaded = set(make_parse_environment().extensions)
    assert "jinja2.ext.ExprStmtExtension" in loaded     # enables {% do %}
    assert "jinja2.ext.LoopControlExtension" in loaded   # enables {% break %}/{% continue %}
