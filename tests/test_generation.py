"""Offline tests for the Phase-11 ``{% generation %}`` parser extension.

HuggingFace chat templates wrap the assistant-generated span in
``{% generation %}...{% endgeneration %}`` (a transformers extension that builds a token
mask). Phase 1's parser enabled only ``do``+``loopcontrols``, so such templates raised a
``ParseError`` and were build-skipped from the FP corpus. Phase 11 adds a minimal passthrough
extension that parses the tag and **preserves the inner nodes**, so the block is analyzable --
a sink hidden inside it must still be caught -- while a benign generation template stays clean.
"""

from __future__ import annotations

import os

import pytest

from glyphhound.analyze import analyze_template
from glyphhound.parse import ParseError, dump_ast, parse_template

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")


def test_generation_template_dump_matches_golden():
    src = open(os.path.join(GOLDEN_DIR, "generation_template.jinja"), encoding="utf-8").read()
    expected = open(os.path.join(GOLDEN_DIR, "generation_template.ast.txt"), encoding="utf-8").read()
    assert dump_ast(parse_template(src)) + "\n" == expected


@pytest.mark.parametrize("src", [
    "{% generation %}{{ messages[0]['content'] }}{% endgeneration %}",
    "{% for m in messages %}{% generation %}{{ m.content }}{% endgeneration %}{% endfor %}",
    "{% generation %}hello{% endgeneration %}",
])
def test_generation_tag_parses(src):
    parse_template(src)  # must not raise (Phase 1 would have raised ParseError)


def test_unclosed_generation_raises_parse_error():
    with pytest.raises(ParseError):
        parse_template("{% generation %}{{ x }}")  # no {% endgeneration %}


def test_sink_inside_generation_block_is_reachable():
    """The passthrough must keep the inner nodes so a sink inside the block is still analyzed --
    otherwise the tag would be an analysis blind spot a payload could hide behind."""
    mal = ("{% generation %}"
           "{{ cycler.__init__.__globals__['__builtins__']['__import__']('os')"
           ".system('GLYPHHOUND_GENERATION_MARKER') }}"
           "{% endgeneration %}")
    findings = analyze_template(mal)
    reach = {f.rule_id for f in findings if f.reachable}
    assert "GH-S001" in reach and "GH-S002" in reach


def test_benign_generation_template_is_clean():
    benign = ("{% for m in messages %}{{ m.role }}: "
              "{% generation %}{{ m.content }}{% endgeneration %}\n{% endfor %}")
    assert analyze_template(benign) == []
