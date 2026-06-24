"""Phase 15 -- detection hardening: a code-exec NAME as a constant subscript key is benign
mapping indexing, not a sink.

The wider-corpus FP audit (scripts/wider_fp_audit.py) surfaced two real benign templates
(LGAI-EXAONE/EXAONE-4.0-32B, K-EXAONE-236B-A23B) that index a role-name dict --
``role_indicators['system']`` -- and were wrongly flagged GH-S002 because ``'system'`` is a
code-exec name AND appeared as a constant subscript key. ``system`` is dangerous as an
*attribute* (``os.system``) or a *called name* (``system(x)``), never as a *string key*
indexing a mapping. So a code-exec name as a constant subscript key on an untainted base is
not a sink; DUNDER subscript keys (the ``x['__globals__']`` dict-escape form) and code-exec
attributes/calls remain sinks. The fix is monotonic (only removes such findings), so it cannot
introduce a new false positive and every real escape still gates via a dunder/attr/call.
"""

from __future__ import annotations

from glyphhound.analyze import analyze_template
from glyphhound.report import make_report


def _gates(tpl: str) -> bool:
    return make_report(analyze_template(tpl)).exit_code != 0


def _rule_ids(tpl: str) -> set[str]:
    return {f.rule_id for f in analyze_template(tpl)}


# --- the false positives the wider audit found (must be CLEAN) -----------------

def test_codeexec_name_as_subscript_key_is_not_a_sink():
    # role_indicators['system'] -- indexing a benign dict by the role-name string.
    findings = analyze_template("{{ role_indicators['system'] }}")
    assert findings == [], findings
    assert not _gates("{{ role_indicators['system'] }}")


def test_exaone_role_indicator_pattern_is_clean():
    # The exact shape from LGAI-EXAONE (a {role: marker} dict indexed by role name).
    tpl = (
        "{%- set role_indicators = {'system': '<|system|>\\n', "
        "'user': '<|user|>\\n', 'assistant': '<|assistant|>\\n'} %}"
        "{%- for msg in messages %}"
        "{%- if msg.role == 'system' %}{{- role_indicators['system'] }}{{- msg.content }}"
        "{%- endif %}{%- endfor %}"
    )
    assert analyze_template(tpl) == []
    assert not _gates(tpl)


def test_other_codeexec_names_as_subscript_keys_are_clean():
    for name in ("open", "globals", "locals", "vars", "eval", "exec", "compile", "os"):
        tpl = "{{ cfg[%r] }}" % name
        assert analyze_template(tpl) == [], (name, analyze_template(tpl))


def test_reflection_name_as_subscript_key_is_clean():
    assert analyze_template("{{ cfg['getattr'] }}") == []


# --- detection that MUST be preserved (no regression) --------------------------

def test_codeexec_name_as_attribute_still_flags():
    # os.system -- 'system' as an ATTRIBUTE remains a reachable GH-S002.
    findings = analyze_template("{{ os.system('x') }}")
    assert any(f.rule_id == "GH-S002" and f.reachable for f in findings)
    assert _gates("{{ os.system('x') }}")


def test_codeexec_name_called_directly_still_flags():
    findings = analyze_template("{{ system('x') }}")
    assert any(f.rule_id == "GH-S002" and f.reachable for f in findings)
    assert _gates("{{ system('x') }}")


def test_dunder_subscript_key_still_flags():
    # x['__globals__'] -- a DUNDER subscript key (the dict-escape form) stays GH-S001.
    findings = analyze_template("{{ obj['__globals__'] }}")
    assert any(f.rule_id == "GH-S001" and f.reachable for f in findings)
    assert _gates("{{ obj['__globals__'] }}")


def test_gadget_chain_with_codeexec_subscript_still_gates():
    # The real escape reaches code-exec through a tainted base + an attribute, so dropping
    # the standalone code-exec-subscript-key finding does not lose the gate.
    tpl = "{{ cycler.__init__.__globals__['os'].system('x') }}"
    assert _gates(tpl)
    assert "GH-S001" in _rule_ids(tpl)


def test_subscript_codeexec_on_tainted_base_still_gates():
    # __builtins__['eval'] reached via a dunder: gates via the dunder keys, even though the
    # standalone code-exec subscript key is no longer independently flagged.
    tpl = "{{ cycler.__init__.__globals__['__builtins__']['eval']('x') }}"
    assert _gates(tpl)
