"""Stage 3 (Analyzer) — taint / reachability layer (Phase 3).

Phase 2 flags the *presence* of a §4 sink (a dunder access, a code-exec name, a
reflection call, an ``|attr`` pivot). Phase 3 decides whether that sink is actually
**reachable**: it counts only when a dangerous expression *builds toward* it — an
attribute / subscript / ``|attr`` chain that climbs from a real **base object** (any
``Name``, including the dual-use Jinja gadgets ``cycler``/``joiner``/``namespace``/
``lipsum``/``self``, or a literal like ``()``) **through** a ``DANGEROUS_DUNDER``, onto
a ``CODE_EXEC_NAME`` reached by access or call, or as a ``getattr``/``setattr``
reflection call (ARCHITECTURE.md §3).

This is the false-positive killer: a template that merely *names* a variable ``class``
(a ``Name``, not a ``__class__`` access) or uses the role string ``'system'`` (a
``Const``, never inspected) builds toward nothing and stays unreachable.

The layer never changes the Phase-2 finding set: :func:`compute_reachable` returns the
identities of the sink nodes that are reachable, and the sink walk annotates each
:class:`~.models.Finding` from it. So the 0/11 false-positive gate is preserved
by construction — the benign corpus yields zero findings, hence zero reachable findings.

Scope boundary: :func:`_const_str` matches only ``Const`` — a computed key such as
``'__cl' + 'ass__'`` is an ``Add`` node, left unfolded for the Phase-4 de-obfuscator,
so taint only flows from its base (it is not reclassified as a dunder here).
"""

from __future__ import annotations

from jinja2 import nodes

from .models import CODE_EXEC_NAMES, DANGEROUS_DUNDERS, REFLECTION_BUILTINS

# An access chain is a nest of these node types linked by ``.node`` (the spine).
_CHAIN_NODES = (nodes.Getattr, nodes.Getitem, nodes.Filter, nodes.Call)


def compute_reachable(ast: nodes.Node) -> set[int]:
    """Return the ``id()``s of the sink nodes in ``ast`` that are reachable.

    A single deterministic pass: ``find_all`` yields chain nodes outermost-first, so a
    chain is walked once from its outermost node down to its base, and inner spine nodes
    are then skipped. ``id()`` is used only for in-pass membership — the resulting
    per-finding booleans depend solely on AST structure, so the analysis is
    deterministic.
    """
    reachable: set[int] = set()
    seen: set[int] = set()
    for node in ast.find_all(nodes.Node):
        if isinstance(node, _CHAIN_NODES) and id(node) not in seen:
            _resolve(node, reachable, seen)
    return reachable


def _resolve(node: nodes.Node, reachable: set[int], seen: set[int]) -> bool:
    """Walk one expression down its chain spine; return whether its value is *tainted*
    (a reference obtained by climbing into Python internals / code execution).

    Records every spine node in ``seen`` and every reachable sink node's id in
    ``reachable``. Non-spine sub-expressions (call args, subscript keys) are left for
    the outer pass to pick up as independent chains.
    """
    if isinstance(node, nodes.Getattr):
        seen.add(id(node))
        base_tainted = _resolve(node.node, reachable, seen)
        return _step(node, node.attr, base_tainted, reachable)

    if isinstance(node, nodes.Getitem):
        seen.add(id(node))
        base_tainted = _resolve(node.node, reachable, seen)
        key = _const_str(node.arg)
        if key is not None:
            return _step(node, key, base_tainted, reachable, subscript=True)
        # Computed key (e.g. x['__cl'+'ass__']): not folded here (Phase 4) — taint only
        # flows from the base.
        return base_tainted

    if isinstance(node, nodes.Filter) and node.name == "attr":
        seen.add(id(node))
        base_tainted = _resolve(node.node, reachable, seen)
        arg = node.args[0] if node.args else next(
            (kw.value for kw in node.kwargs if kw.key == "name"), None)
        key = _const_str(arg)
        if key is not None:
            return _step(node, key, base_tainted, reachable)
        # Generic |attr(...) with a computed arg: a pivot that reaches no known sink by
        # itself; reachable only if it sits on an already-tainted base.
        if base_tainted:
            reachable.add(id(node))
        return base_tainted

    if isinstance(node, nodes.Filter):  # any other filter: taint flows through it
        seen.add(id(node))
        return _resolve(node.node, reachable, seen)

    if isinstance(node, nodes.Call):
        seen.add(id(node))
        func_tainted = _resolve(node.node, reachable, seen)
        # A bare code-exec / reflection name being CALLED is itself reachable:
        #   eval(x) / system(x) -> code execution;  getattr(x, ...) -> reflection dodge.
        if isinstance(node.node, nodes.Name) and (
            node.node.name in CODE_EXEC_NAMES or node.node.name in REFLECTION_BUILTINS
        ):
            reachable.add(id(node.node))
            return True
        # Calling a tainted callable returns a tainted value (e.g. __import__('os')).
        return func_tainted

    # A base object (Name / literal): a taint *source* candidate, not tainted by itself —
    # the climb only becomes dangerous at a dunder / code-exec step above it.
    return False


def _step(node: nodes.Node, name: str, base_tainted: bool, reachable: set[int],
          *, subscript: bool = False) -> bool:
    """One access step (attr / subscript key / ``|attr`` key). Mark the node reachable
    if it reaches a dunder or code-exec name, or sits on an already-tainted base; return
    whether the resulting value is tainted.

    ``subscript=True`` (a constant subscript string key) counts only a DUNDER as dangerous —
    the dict-escape form ``x['__globals__']``. A code-exec NAME as a subscript key is benign
    mapping indexing (``role_indicators['system']``), so it is not a sink on its own; code-exec
    names stay sinks as attributes (``os.system``) and called names (Phase 15 — wider-FP-audit
    narrowing). An already-tainted base still carries through, so ``__globals__['os']`` etc.
    stay reachable."""
    dangerous = name in DANGEROUS_DUNDERS or (not subscript and name in CODE_EXEC_NAMES)
    if dangerous or base_tainted:
        reachable.add(id(node))
        return True
    return False


def _const_str(node: object) -> str | None:
    """The value of a constant string node, else None — ``Const`` only (a computed key
    is left for Phase 4; never inspect string *contents* beyond the exact identifier)."""
    if isinstance(node, nodes.Const) and isinstance(node.value, str):
        return node.value
    return None
