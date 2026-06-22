"""Offline, deterministic tests for the Stage-3 analyzer (Phase 2 — sink baseline).

Fixture-driven (the project conventions): a CVE-2024-34359 MARKER template that *must*
flag, and the real benign corpus that must stay clean (Rule 9 — false positives
measured on real templates). The analyzer only parses + walks the AST; it never
renders a template, so reading the malicious fixtures here cannot execute anything.

Phase 2 is the STRING/structural baseline: it flags the presence of §4 sink patterns
by inspecting AST *identifier* nodes (Name / Getattr.attr / Getitem key / Filter).
Reachability/taint is Phase 3 and is deliberately out of scope here.
"""

from __future__ import annotations

import json
import os

import pytest

from glyphhound.acquire import ChatTemplate, RawTemplate, read_gguf_template
from glyphhound.analyze import Finding, analyze_ast, analyze_raw, analyze_template
from glyphhound.parse import parse_template
from synthetic import build_gguf

ROOT = os.path.dirname(os.path.dirname(__file__))
BENIGN_DIR = os.path.join(ROOT, "fixtures", "benign")
MALICIOUS_DIR = os.path.join(ROOT, "fixtures", "malicious")


def _corpus_files() -> list[str]:
    provenance = json.load(open(os.path.join(BENIGN_DIR, "PROVENANCE.json"), encoding="utf-8"))
    return [entry["file"] for entry in provenance]


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


# --- the malicious MARKER fixtures MUST flag ------------------------------------

def test_cve_2024_34359_marker_fixture_is_flagged():
    src = _read(os.path.join(MALICIOUS_DIR, "cve_2024_34359_marker.jinja"))
    findings = analyze_template(src)
    assert findings, "the CVE-2024-34359 marker fixture must produce findings"
    rule_ids = {f.rule_id for f in findings}
    # The dunder attribute chain and the os.system code-exec name are both caught.
    assert "GH-S001" in rule_ids  # __init__/__globals__/__builtins__/__import__
    assert "GH-S002" in rule_ids  # system
    assert any(f.severity == "critical" for f in findings)


def test_attr_filter_pivot_fixture_is_flagged():
    src = _read(os.path.join(MALICIOUS_DIR, "attr_filter_pivot_marker.jinja"))
    findings = analyze_template(src)
    assert findings, "the |attr() pivot fixture must produce findings"
    # __class__/__base__/__subclasses__ reached through the |attr filter -> dunder rule.
    assert "GH-S001" in {f.rule_id for f in findings}


# --- the benign corpus must stay clean (Rule 9 false-positive gate) -------------

def test_corpus_has_at_least_ten_templates():
    assert len(_corpus_files()) >= 10


@pytest.mark.parametrize("fname", _corpus_files())
def test_real_benign_template_has_no_findings(fname):
    src = _read(os.path.join(BENIGN_DIR, fname))
    findings = analyze_template(src)
    assert findings == [], f"benign template {fname} was wrongly flagged: {findings}"


def test_benign_lookalikes_are_not_flagged():
    # Near-miss benign constructs that a naive text scanner would trip on:
    #  - 'system' as a role *string literal* (not os.system)
    #  - subscript keys like ['role'] / ['content'] (not ['__class__'])
    #  - ordinary attribute access (.content, loop.first)
    benign = (
        "{% for m in messages %}"
        "{% if m['role'] == 'system' %}{{ m.content }}{% endif %}"
        "{% if loop.first %}{{ m.role }}{% endif %}"
        "{% endfor %}"
    )
    assert analyze_template(benign) == []


def test_variable_merely_named_like_a_keyword_is_not_flagged():
    # A variable named `class` (a Phase-3 false-positive concern) must not flag at the
    # string baseline either: it is a Name, not a dangerous-dunder attribute access.
    assert analyze_template("{% set class = 'x' %}{{ class }}") == []


# --- per-rule unit coverage (each maps to one §4 catalog entry) -----------------

def test_flags_dunder_attribute_access():
    findings = analyze_template("{{ x.__class__ }}")
    assert [f.rule_id for f in findings] == ["GH-S001"]
    assert findings[0].sink_kind == "dunder-attribute"
    assert findings[0].severity == "critical"


def test_flags_dunder_via_subscript():
    findings = analyze_template("{{ x['__globals__'] }}")
    assert any(f.rule_id == "GH-S001" for f in findings)


def test_flags_dunder_via_attr_filter():
    findings = analyze_template("{{ x|attr('__class__') }}")
    assert any(f.rule_id == "GH-S001" for f in findings)


def test_flags_code_exec_name():
    findings = analyze_template("{{ os.system('x') }}")
    rule_ids = {f.rule_id for f in findings}
    assert "GH-S002" in rule_ids
    assert any(f.sink_kind == "code-exec-name" for f in findings)


def test_flags_generic_attr_filter_pivot():
    # |attr with a non-dunder argument is still the dot-access dodge (§4 pivot).
    findings = analyze_template("{{ x|attr('foo') }}")
    assert [f.rule_id for f in findings] == ["GH-S003"]
    assert findings[0].sink_kind == "attr-filter"


def test_flags_reflection_builtin():
    findings = analyze_template("{{ getattr(x, 'y') }}")
    assert any(f.rule_id == "GH-S004" for f in findings)


def test_finding_carries_source_line_and_evidence():
    findings = analyze_template("\n\n{{ x.__globals__ }}")
    assert findings[0].source_line == 3
    assert "__globals__" in findings[0].evidence


# --- determinism (Rule 7) -------------------------------------------------------

def test_findings_are_deterministic():
    src = _read(os.path.join(MALICIOUS_DIR, "cve_2024_34359_marker.jinja"))
    assert analyze_template(src) == analyze_template(src)


def test_analyze_ast_matches_analyze_template():
    src = "{{ x.__class__ }}"
    assert analyze_ast(parse_template(src)) == analyze_template(src)


# --- §7: scan ALL templates, tag each finding by its template name ---------------

def test_analyze_raw_tags_findings_by_template_name():
    raw = RawTemplate(
        source_ref="synthetic",
        templates=(
            ChatTemplate(None, "{% for m in messages %}{{ m.role }}: {{ m.content }}{% endfor %}"),
            ChatTemplate("evil", "{{ cycler.__init__.__globals__ }}"),
        ),
        bytes_fetched=1,
        total_size=1000,
    )
    findings = analyze_raw(raw)
    assert findings, "the named malicious template must be flagged"
    # Every finding is attributed to the NAMED template; the benign default has none.
    assert {f.template_name for f in findings} == {"evil"}


def test_named_template_attack_is_caught_end_to_end(tmp_path):
    # The §7 payoff: a model whose DEFAULT template is benign but a NAMED template
    # carries the sink. The named one must not hide from the analyzer. MARKER only.
    benign_default = "{% for m in messages %}{{ m.role }}: {{ m.content }}\n{% endfor %}"
    malicious_named = "{{ self.__init__.__globals__.__builtins__ }}"
    payload = build_gguf(
        benign_default,
        named_templates={"tokenizer.chat_template.tool_use": malicious_named},
    )
    path = tmp_path / "hidden_sink.gguf"
    path.write_bytes(payload)

    raw = read_gguf_template(str(path))
    findings = analyze_raw(raw)

    assert findings, "a sink hidden in a named template must still be flagged"
    assert {f.template_name for f in findings} == {"tool_use"}
    # And the default template, scanned too, is clean.
    assert analyze_template(raw.default_template.text, template_name=None) == []


def test_finding_is_frozen_and_hashable():
    f = Finding(rule_id="GH-S001", severity="critical", sink_kind="dunder-attribute",
                template_name=None, source_line=1, evidence="x.__class__")
    with pytest.raises(Exception):
        f.rule_id = "changed"  # frozen dataclass


# --- Phase 3: taint / reachability ----------------------------------------------
# A sink is reachable only when a dangerous expression actually BUILDS TOWARD it:
# an attribute/subscript/|attr chain that climbs from a real base object (any Name,
# incl. the Jinja gadgets, or a literal) through a dunder / onto a code-exec name /
# via a reflection call. Phase 3 only ANNOTATES findings (sets `reachable`); it never
# changes the Phase-2 finding set, so the Rule-9 0/11 FP gate holds by construction.

REACHABLE_FIXTURE = os.path.join(MALICIOUS_DIR, "reachable_sink_marker.jinja")


def _reachable(findings):
    return [f for f in findings if f.reachable]


def test_reachable_sink_marker_fixture_is_reachable():
    findings = analyze_template(_read(REACHABLE_FIXTURE))
    assert findings, "the reachable-sink fixture must produce findings"
    reach = _reachable(findings)
    assert reach, "the reachable-sink fixture must have reachable=True findings"
    reachable_rules = {f.rule_id for f in reach}
    # the dunder pivot and the os.system code-exec name are the reachable sinks
    assert "GH-S001" in reachable_rules
    assert "GH-S002" in reachable_rules


def test_cve_2024_34359_fixture_is_now_reachable():
    findings = analyze_template(_read(os.path.join(MALICIOUS_DIR, "cve_2024_34359_marker.jinja")))
    assert any(f.reachable and f.rule_id == "GH-S001" for f in findings)
    assert any(f.reachable and f.rule_id == "GH-S002" for f in findings)


def test_attr_filter_pivot_fixture_is_now_reachable():
    findings = analyze_template(_read(os.path.join(MALICIOUS_DIR, "attr_filter_pivot_marker.jinja")))
    assert _reachable(findings), "the |attr() dunder pivot chain must be reachable"
    # every dunder reached through the |attr pivot is reachable
    assert all(f.reachable for f in findings if f.rule_id == "GH-S001")


def test_gadget_rooted_dunder_chain_is_reachable():
    # cycler is a taint SOURCE; pivoting through it into dunders makes the chain reach.
    findings = analyze_template("{{ cycler.__init__.__globals__ }}")
    assert findings
    assert all(f.reachable for f in findings)  # both __init__ and __globals__


def test_bare_gadget_presence_is_not_reachable():
    # Gadgets are dangerous only when pivoted THROUGH into a dunder. Bare presence is
    # not even a sink -> no findings -> nothing reachable.
    assert analyze_template("{{ namespace(x=1) }}") == []
    assert analyze_template("{{ cycler('a', 'b') }}") == []


def test_keyword_named_variable_is_not_reachable():
    # The FP-killer: a variable merely NAMED `class` (not `__class__`) builds toward
    # nothing -> not a sink, not reachable.
    findings = analyze_template("{% set class = 'x' %}{{ class }}")
    assert findings == []
    assert _reachable(findings) == []


def test_benign_lookalikes_are_not_reachable():
    # role string 'system' (a Const), ['role'] subscript, .content / loop.first.
    benign = (
        "{% for m in messages %}"
        "{% if m['role'] == 'system' %}{{ m.content }}{% endif %}"
        "{% if loop.first %}{{ m.role }}{% endif %}"
        "{% endfor %}"
    )
    findings = analyze_template(benign)
    assert findings == []


def test_generic_attr_filter_pivot_is_not_reachable():
    # |attr('foo') reaches a benign-named attribute: a pivot, but it builds toward no sink.
    findings = analyze_template("{{ x|attr('foo') }}")
    assert [f.rule_id for f in findings] == ["GH-S003"]
    assert findings[0].reachable is False


def test_direct_code_exec_call_is_reachable():
    # eval(x): a code-exec name invoked directly is reachable.
    findings = analyze_template("{{ eval(x) }}")
    assert any(f.rule_id == "GH-S002" and f.reachable for f in findings)


def test_code_exec_attribute_chain_is_reachable():
    # os.system('x'): `.system` reached via access on the `os` base.
    findings = analyze_template("{{ os.system('x') }}")
    assert any(f.rule_id == "GH-S002" and f.reachable for f in findings)


def test_bare_code_exec_name_is_not_reachable():
    # A variable merely named `system`, neither called nor accessed-through, builds
    # toward nothing -> flagged (presence) but not reachable.
    findings = analyze_template("{{ system }}")
    assert [f.rule_id for f in findings] == ["GH-S002"]
    assert findings[0].reachable is False


def test_reflection_call_is_reachable():
    # getattr(...) is the reflection dodge; the call itself is reachable, independent
    # of the (uninspected) argument string.
    findings = analyze_template("{{ getattr(x, 'y') }}")
    assert any(f.rule_id == "GH-S004" and f.reachable for f in findings)


def test_raw_walker_does_not_fold_obfuscated_getattr():
    # The RAW walker (analyze_ast) sees getattr(x, '__cl'+'ass__') only as a GH-S004
    # reflection call -- it never folds the string. De-obfuscation is a SEPARATE Phase-4
    # layer that analyze_template runs (parse -> normalize -> analyze_ast); the folded
    # GH-S001 upgrade is asserted in the Phase-4 section below.
    findings = analyze_ast(parse_template("{{ getattr(x, '__cl' + 'ass__') }}"))
    assert any(f.rule_id == "GH-S004" and f.reachable for f in findings)
    assert all(f.rule_id != "GH-S001" for f in findings), "raw walker does not fold"


def test_reachability_is_deterministic():
    src = _read(REACHABLE_FIXTURE)
    assert analyze_template(src) == analyze_template(src)


# --- Phase 4: de-obfuscation pre-pass -------------------------------------------
# A separate normalization layer folds obfuscation BEFORE analysis: constant string
# concatenation ('a'+'b' / 'a'~'b', recursive) and getattr/setattr with a constant-
# after-fold *dangerous* name. analyze_template runs the full pipeline (parse ->
# normalize -> analyze_ast); the existing Const-only sink walk then fires unchanged on
# the normalized tree. analyze_ast is the raw walker and never folds.

DEOBFUSCATED_FIXTURE = os.path.join(MALICIOUS_DIR, "deobfuscated_sink_marker.jinja")


def test_deobfuscated_sink_marker_fixture_is_reachable_after_folding():
    src = _read(DEOBFUSCATED_FIXTURE)
    # Premise: invisible to the raw walker -- every dangerous identifier is a string concat.
    assert analyze_ast(parse_template(src)) == [], "fixture must be clean WITHOUT folding"
    # After folding: the dunder chain (GH-S001) and the `system` code-exec name (GH-S002)
    # are reachable.
    reach = _reachable(analyze_template(src))
    assert reach, "the de-obfuscated chain must be reachable after folding"
    rules = {f.rule_id for f in reach}
    assert "GH-S001" in rules and "GH-S002" in rules


def test_obfuscated_subscript_dunder_is_folded():
    # x['__cl'+'ass__'] -> x['__class__'] -> GH-S001 reachable.
    findings = analyze_template("{{ x['__cl' + 'ass__'] }}")
    assert any(f.rule_id == "GH-S001" and f.reachable for f in findings)


def test_obfuscated_attr_filter_dunder_is_folded():
    # ()|attr('__cl'+'ass__') -> ()|attr('__class__') -> GH-S001 reachable.
    findings = analyze_template("{{ ()|attr('__cl' + 'ass__') }}")
    assert any(f.rule_id == "GH-S001" and f.reachable for f in findings)


def test_obfuscated_getattr_is_upgraded_to_dunder_finding():
    # getattr(x, '__cl'+'ass__') resolves to x.__class__: GH-S001 reachable, and the now-
    # redundant GH-S004 reflection finding is REPLACED (decision: upgrade high -> critical).
    findings = analyze_template("{{ getattr(x, '__cl' + 'ass__') }}")
    assert any(f.rule_id == "GH-S001" and f.reachable for f in findings)
    assert all(f.rule_id != "GH-S004" for f in findings), "dangerous getattr is upgraded, not duplicated"


def test_tilde_concat_is_folded():
    # Jinja's ~ string-concat operator (PRD §2: |attr('__cl'~'ass__')) folds too.
    findings = analyze_template("{{ x['__cl' ~ 'ass__'] }}")
    assert any(f.rule_id == "GH-S001" and f.reachable for f in findings)


def test_recursive_concat_is_folded():
    # 'a'+'b'+'c' chains fold fully.
    findings = analyze_template("{{ x['__cl' + 'as' + 's__'] }}")
    assert any(f.rule_id == "GH-S001" and f.reachable for f in findings)


def test_setattr_to_dunder_is_upgraded_and_preserves_value():
    # setattr(x, '__cl'+'ass__', y.__globals__): the dunder target -> GH-S001, AND the
    # assigned value's own sink (y.__globals__) is not lost by the rewrite.
    findings = analyze_template("{{ setattr(x, '__cl' + 'ass__', y.__globals__) }}")
    assert [f.rule_id for f in findings].count("GH-S001") >= 2  # x.__class__ AND y.__globals__
    assert all(f.reachable for f in findings if f.rule_id == "GH-S001")


def test_benign_string_concat_does_not_flag():
    # A role string built as 'rol'+'e' folds to 'role' -- benign, no finding.
    assert analyze_template("{{ 'rol' + 'e' }}") == []
    assert analyze_template("{% set r = 'rol' + 'e' %}{{ r }}") == []


def test_benign_getattr_with_constant_arg_stays_reflection_only():
    # getattr with a benign (constant) name is NOT resolved/upgraded -- it stays GH-S004,
    # so the deliberate reflection-anomaly signal is preserved (no regression).
    findings = analyze_template("{{ getattr(x, 'rol' + 'e') }}")
    assert [f.rule_id for f in findings] == ["GH-S004"]
    assert findings[0].reachable is True


def test_normalize_records_applied_deobfuscations():
    from glyphhound.parse import normalize
    norm = normalize(parse_template("{{ x['__cl' + 'ass__'] }}"),
                     dangerous_names=frozenset({"__class__"}))
    assert norm.deobfuscations_applied, "a fold must be recorded for evidence"


def test_deobfuscation_is_deterministic():
    src = _read(DEOBFUSCATED_FIXTURE)
    assert analyze_template(src) == analyze_template(src)
