"""Stage 3 data model and sink catalog (ARCHITECTURE.md §4 and §5).

Phase 2 is the **string/structural baseline**: it flags the *presence* of §4 sink
patterns by inspecting AST identifier nodes (a Name, a Getattr's ``attr``, a constant
subscript key, an ``|attr`` filter argument) — never the contents of string literals,
so the role string ``'system'`` is not confused with the ``os.system`` sink.

Reachability/taint (Phase 3) and de-obfuscation (Phase 4) are deliberately out of
scope here, so a Phase-2 :class:`Finding` leaves ``reachable`` unset (``None``) —
"presence detected, reachability not yet analyzed" — the same way ``confirmed`` stays
``None`` until the Phase-6 sandbox runs.
"""

from __future__ import annotations

from dataclasses import dataclass

# Severity levels. Plain strings (not an enum) so findings serialize cleanly to
# JSON / SARIF in Phase 5 without extra machinery.
CRITICAL = "critical"
HIGH = "high"

# --- §4 Sink Catalog -----------------------------------------------------------
# Attribute/subscript names that climb Python's object model toward a sandbox escape.
# None of these appear AS IDENTIFIERS in a legitimate message-formatting template
# (measured: zero identifier occurrences across the real benign corpus — the analyzer
# matches AST identifiers, never string contents, so the literal "open" inside a
# tool-schema string in a benign template is ignored).
#
# Curated from public SSTI / Python sandbox-escape research (cite, don't weaponize;
# exercised by MARKER fixtures only):
#   - PayloadsAllTheThings — Server Side Template Injection (Jinja2): the
#     __class__/__mro__/__subclasses__/__globals__/__builtins__ gadget chain.
#   - PortSwigger Web Security Academy — Server-side template injection.
#   - Prior art: github.com/huggingface/gguf-jinja-analysis (the same vuln class).
#   - CPython data model: pickle protocol (__reduce__/__reduce_ex__/__getstate__/
#     __setstate__), function internals (__code__/__closure__/__func__/__self__),
#     attribute interception (__getattribute__/__call__), the import system
#     (__loader__/__spec__) and functools.wraps (__wrapped__).
# GH-S001 (a dunder reach) maps to CWE-94 (code injection); see RULE_CATALOG below.
DANGEROUS_DUNDERS = frozenset({
    # object-model climb (Phase 2 baseline)
    "__class__", "__base__", "__bases__", "__mro__", "__subclasses__",
    "__globals__", "__builtins__", "__init__", "__import__", "__dict__",
    # attribute interception / callable (Phase 12)
    "__getattribute__", "__call__",
    # pickle-protocol / serialization RCE (Phase 12)
    "__reduce__", "__reduce_ex__", "__getstate__", "__setstate__",
    # function internals -> __globals__ (Phase 12)
    "__code__", "__closure__", "__func__", "__self__",
    # import machinery / decorator unwrap (Phase 12)
    "__loader__", "__spec__", "__wrapped__",
})

# Identifiers that denote code execution or a dangerous capability directly. Same
# identifier-only discipline and sources as DANGEROUS_DUNDERS above. GH-S002 -> CWE-94.
CODE_EXEC_NAMES = frozenset({
    # direct execution / process (Phase 2 baseline)
    "eval", "exec", "__import__", "os", "subprocess", "popen", "system",
    # code generation / dynamic import / (de)serialization gateways (Phase 12)
    "compile", "importlib", "builtins", "marshal", "pickle",
    # namespace / scope introspection -> reaches builtins (Phase 12)
    "globals", "locals", "vars",
    # filesystem / process / debugger capability (Phase 12)
    "open", "pty", "breakpoint",
})

# Reflection builtins used to reach attributes dynamically (a dodge for the above).
REFLECTION_BUILTINS = frozenset({"getattr", "setattr"})

# Jinja gadget objects (cycler / joiner / namespace / lipsum / self) are intentionally
# NOT flagged on bare presence in this string baseline. They are dual-use — namespace
# in particular is ubiquitous in real tool-calling templates — and are only dangerous
# when an attribute chain pivots *through* them into the dunders above, which GH-S001
# already catches. Treating a gadget as a taint *source* is Phase 3, where the
# "builds toward it" reachability that makes them safe-to-flag lives.

# --- CWE classification (Phase 12) ---------------------------------------------
# Two CWEs span the catalog: the dunder reach and the code-exec names ARE the
# code-injection mechanism (CWE-94), while the |attr filter and getattr/setattr
# reflection are the template-engine-specific evasion special-elements (CWE-1336,
# server-side template injection — the vuln class itself). The id is surfaced per rule
# in JSON + SARIF so a finding is standards-mapped, not just GlyphHound-specific.
CWE_CODE_INJECTION = "CWE-94"        # Improper Control of Generation of Code ('Code Injection')
CWE_TEMPLATE_INJECTION = "CWE-1336"  # Improper Neutralization of Special Elements in a Template Engine

# Each catalog entry is one rule_id with a severity + short rationale + CWE id, so every
# finding is explainable and standards-mapped (ARCHITECTURE.md §4).
RULE_CATALOG: dict[str, tuple[str, str, str, str]] = {
    "GH-S001": ("dunder-attribute", CRITICAL,
                "attribute/subscript/|attr access to a Python dunder used for sandbox escape",
                CWE_CODE_INJECTION),
    "GH-S002": ("code-exec-name", CRITICAL,
                "reference to a code-execution or dangerous-capability name "
                "(eval/exec/compile/os/subprocess/importlib/pickle/open/...)",
                CWE_CODE_INJECTION),
    "GH-S003": ("attr-filter", HIGH,
                "use of the |attr() filter to dodge dot-access detection (§4 pivot)",
                CWE_TEMPLATE_INJECTION),
    "GH-S004": ("reflection-call", HIGH,
                "use of getattr/setattr reflection to reach attributes dynamically",
                CWE_TEMPLATE_INJECTION),
}


def cwe_for(rule_id: str) -> str:
    """The CWE id mapped to ``rule_id`` (e.g. ``'CWE-94'``); raises KeyError if unknown."""
    return RULE_CATALOG[rule_id][3]


@dataclass(frozen=True)
class Finding:
    """One detected sink (ARCHITECTURE.md §5), tagged with its source template (§7).

    ``template_name`` is the name of the chat template the sink was found in
    (``None`` for the default ``tokenizer.chat_template``), so a sink hidden in a
    named variant is attributable. ``reachable`` and ``confirmed`` stay ``None`` in
    Phase 2 — they are set by the taint (Phase 3) and sandbox (Phase 6) stages.
    """

    rule_id: str
    severity: str
    sink_kind: str
    template_name: str | None
    source_line: int
    evidence: str
    ast_span: str = ""
    reachable: bool | None = None
    confirmed: bool | None = None
