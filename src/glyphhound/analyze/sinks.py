"""Stage 3 (Analyzer) — sink detection, string/structural baseline (Phase 2).

Walk the Jinja2 AST produced by Stage 2 and flag the §4 sink catalog. This is the
*string baseline*: it matches on the AST's **identifier** nodes — a ``Name``, a
``Getattr``'s attribute, a constant subscript key, an ``|attr`` filter argument —
and never on the contents of string literals (``Const`` nodes). That distinction is
the whole reason the role string ``'system'`` in a benign template is not confused
with the ``os.system`` sink: one is a ``Const`` (ignored), the other an identifier.

De-obfuscation (Phase 4) is a separate Stage-2 pre-pass (:mod:`..parse.deobfuscate`)
that :func:`analyze_template` runs *before* this walk; the walk itself is unchanged and
still inspects only identifier nodes (never ``Const`` contents), so it fires naturally on
the folded tree. Reachability (Phase 3) is layered on without changing the finding set:
this stage still *matches* the §4 sink patterns, and :mod:`.taint` decides which are
actually reached by a dangerous chain — each finding's ``reachable`` flag is set from
:func:`~.taint.compute_reachable`.

The walk is a single deterministic pre-order pass (``find_all`` over the tree), so
the same template always yields the same findings in the same order (Rule 7).
"""

from __future__ import annotations

from jinja2 import nodes

from ..acquire import RawTemplate
from ..parse import normalize, parse_template
from .models import (
    CODE_EXEC_NAMES,
    CRITICAL,
    DANGEROUS_DUNDERS,
    HIGH,
    REFLECTION_BUILTINS,
    Finding,
)
from .taint import compute_reachable


def analyze_raw(raw: RawTemplate) -> list[Finding]:
    """Analyze **every** template in a :class:`RawTemplate` (default + named).

    Scanning all templates and tagging each finding with its template name is the
    security payoff of the multi-template acquirer (ARCHITECTURE.md §7): a sink hidden
    in a ``tokenizer.chat_template.<name>`` variant cannot escape the analyzer just
    because the default template is benign.
    """
    findings: list[Finding] = []
    for template in raw.templates:
        findings.extend(analyze_template(template.text, template_name=template.name))
    return findings


def analyze_template(template_string: str, *, template_name: str | None = None) -> list[Finding]:
    """Parse, de-obfuscate, then analyze a template string and return its sink findings.

    The full Stage-2 -> Stage-3 pipeline: ``parse_template`` -> :func:`~..parse.normalize`
    (Phase 4 fold) -> :func:`analyze_ast`. Folding the obfuscation first is what lets the
    identifier-only walk catch ``'__cl' + 'ass__'`` payloads a string-matcher misses.
    Raises ParseError on malformed input — Stage 2's error type, so callers catch one thing.
    """
    normalized = normalize(parse_template(template_string),
                           dangerous_names=DANGEROUS_DUNDERS | CODE_EXEC_NAMES)
    return analyze_ast(normalized.ast, template_name=template_name)


def analyze_ast(ast: nodes.Node, *, template_name: str | None = None) -> list[Finding]:
    """Walk a parsed AST and return findings for the §4 sink catalog.

    Reachability (Phase 3) is computed once for the whole AST by :mod:`.taint`, and each
    finding is annotated with whether its node is reached by a dangerous chain.
    """
    reachable_ids = compute_reachable(ast)
    findings: list[Finding] = []
    for node in ast.find_all(nodes.Node):
        _inspect(node, template_name, reachable_ids, findings)
    return findings


def _inspect(node: nodes.Node, template_name: str | None, reachable_ids: set[int],
             out: list[Finding]) -> None:
    """Dispatch one node to its sink check. Each node is exactly one of these kinds,
    so there is no double counting within a single node."""
    if isinstance(node, nodes.Filter) and node.name == "attr":
        _inspect_attr_filter(node, template_name, reachable_ids, out)
    elif isinstance(node, nodes.Getattr):
        _emit_if_dangerous(node.attr, f".{node.attr}", node, template_name, reachable_ids, out)
    elif isinstance(node, nodes.Getitem):
        key = _const_str(node.arg)
        # A DUNDER subscript key is always a sink — the dict-escape form x['__globals__'] /
        # x['__class__']. A code-exec NAME (or reflection builtin) as a subscript key is a sink
        # only when the base is a dangerous (tainted) namespace — __builtins__['eval'] — NOT
        # benign mapping indexing (role_indicators['system']). Taint already encodes "base is
        # tainted" as reachability (a code-exec subscript key is reachable only then), so gate
        # the non-dunder case on it; code-exec names remain unconditional sinks as attributes
        # (os.system) and called names (system(x)). (Phase 15 — wider-FP-audit narrowing.)
        if key is not None and (key in DANGEROUS_DUNDERS or id(node) in reachable_ids):
            _emit_if_dangerous(key, f"[{key!r}]", node, template_name, reachable_ids, out)
    elif isinstance(node, nodes.Name):
        _emit_if_dangerous(node.name, node.name, node, template_name, reachable_ids, out)


def _inspect_attr_filter(node: nodes.Filter, template_name: str | None,
                         reachable_ids: set[int], out: list[Finding]) -> None:
    """The ``|attr('...')`` filter (ARCHITECTURE.md §4 pivot).

    If the argument is a constant naming a dunder / code-exec identifier, report the
    specific sink (GH-S001/S002). Otherwise the bare use of the filter — including a
    *computed* argument — is itself the dot-access dodge, reported as GH-S003. The name may
    be positional (``|attr('__class__')``) or a keyword (``|attr(name='__class__')``).
    """
    arg = node.args[0] if node.args else _attr_filter_name(node)
    key = _const_str(arg)
    if key is not None:
        hit = _classify(key)
        if hit is not None:
            rule_id, severity, sink_kind = hit
            out.append(_make(rule_id, severity, sink_kind, f"|attr({key!r})", node,
                             template_name, reachable_ids))
            return
    out.append(_make("GH-S003", HIGH, "attr-filter", f"|attr({key!r})" if key else "|attr(...)",
                     node, template_name, reachable_ids))


def _attr_filter_name(node: nodes.Filter) -> nodes.Node | None:
    """The ``name=`` keyword argument of an ``|attr(...)`` filter, else None (Phase 10 —
    the pivot name can hide in a keyword argument just as in a ``getattr`` call)."""
    return next((kw.value for kw in node.kwargs if kw.key == "name"), None)


def _emit_if_dangerous(name: str, evidence: str, node: nodes.Node,
                       template_name: str | None, reachable_ids: set[int],
                       out: list[Finding]) -> None:
    hit = _classify(name)
    if hit is not None:
        rule_id, severity, sink_kind = hit
        out.append(_make(rule_id, severity, sink_kind, evidence, node, template_name, reachable_ids))


def _classify(name: str) -> tuple[str, str, str] | None:
    """Map an identifier to its (rule_id, severity, sink_kind), or None if benign.

    Dunders are checked first so ``__import__`` (which is both a dunder and a code-exec
    name) classifies deterministically as GH-S001.
    """
    if name in DANGEROUS_DUNDERS:
        return ("GH-S001", CRITICAL, "dunder-attribute")
    if name in CODE_EXEC_NAMES:
        return ("GH-S002", CRITICAL, "code-exec-name")
    if name in REFLECTION_BUILTINS:
        return ("GH-S004", HIGH, "reflection-call")
    return None


def _const_str(node: object) -> str | None:
    """The value of a constant string node, else None.

    Only *constant* keys/args are inspected — a computed one (``'__cl' + 'ass__'``)
    is a ``Add`` node, not a ``Const``, and is left for the Phase-4 de-obfuscator.
    """
    if isinstance(node, nodes.Const) and isinstance(node.value, str):
        return node.value
    return None


def _make(rule_id: str, severity: str, sink_kind: str, evidence: str,
          node: nodes.Node, template_name: str | None, reachable_ids: set[int]) -> Finding:
    lineno = getattr(node, "lineno", 0) or 0
    return Finding(
        rule_id=rule_id,
        severity=severity,
        sink_kind=sink_kind,
        template_name=template_name,
        source_line=lineno,
        evidence=evidence,
        ast_span=f"{type(node).__name__}@line{lineno}",
        reachable=id(node) in reachable_ids,
    )
