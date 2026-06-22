"""Stage 2 (De-obfuscator) — fold obfuscation before analysis (Phase 4).

This is the *de-obfuscation* half of Stage 2 (ARCHITECTURE.md §"Stage 2"; PRD §7.2). It
is GlyphHound's whole differentiator (PRD §4): a string-matcher sees ``'__cl' + 'ass__'``
and misses it, so we fold the concatenation back to ``'__class__'`` **before** the Stage-3
sink/taint walk runs. The walk's existing ``Const``-only handling then fires unchanged —
no change to :mod:`..analyze.sinks` or :mod:`..analyze.taint` is needed.

Three folds, all **static** (we never evaluate or render the template — Rule 4/Rule 6;
the constant string operations below are computed only over string *literals* at analysis
time, the same class of work as the concatenation fold):

* **Constant string concatenation.** ``Add`` (the ``+`` operator) and ``Concat`` (the
  Jinja ``~`` operator, PRD §2) over string ``Const`` operands collapse to a single
  ``Const``. Recursive, so ``'a' + 'b' + 'c'`` folds fully. Only string constants fold —
  a non-constant or non-string operand is left untouched (``1 + 2``, ``'a' + x``).
* **Constant string builders (Phase 10).** The same collapse for the other ways an
  identifier can be assembled from literals: ``'{}'.format('__class__')`` (``str.format``
  with constant args), a constant slice/index ``'__class__X'[:9]``, and the ``|join`` /
  ``|replace`` filters over constant operands. Each folds to a single ``Const`` **only**
  when every operand is constant; a folded value over ``_MAX_FOLDED_LEN`` chars (never an
  identifier) is rejected so a pathological format width cannot blow up.
* **Constant string transforms (Phase 16).** The pure, side-effect-free identifier
  transforms an evader uses to hide a name behind a non-matching literal: the case folds
  ``|lower``/``|upper``/``|title``/``|capitalize``/``|swapcase``, whitespace ``|trim``/
  ``|strip``, and ``|reverse`` (``'__CLASS__'|lower`` -> ``'__class__'``), plus negative /
  reverse *slices* (``'__ssalc__'[::-1]`` -> ``'__class__'``; a ``-1`` step is a ``Neg`` over
  a ``Const``, which :func:`_const_int_bound` now unwraps). Each is computed over the string
  *literal* only, so nothing dynamic is ever evaluated (Rule 4/6). Together these extend the
  fold to a single, general principle: *any* expression built entirely from string ``Const``s
  through this whitelist of pure ops is reduced to its constant value before the walk.
* **Constant string repetition + printf + cast (Phase 19).** The remaining trivial,
  *identifier-hiding* builders an adversarial hunt found slipping past — and which a
  string-matcher misses too: string repetition ``'_' * 2`` (the ``Mul`` operator), printf via
  the ``%`` operator (``'%sinit%s' % ('__', '__')``) and the ``|format`` filter
  (``'%sinit%s'|format('__', '__')``), and the ``|string`` cast that an evader wraps around a
  foldable expression to break the fold (``('__in' + 'it__')|string``). Each folds over string
  ``Const`` operands only; ``Mul`` is bounded by ``_MAX_FOLDED_LEN`` *before* it computes and a
  printf width ``>= _MAX_FOLDED_LEN`` (and an arg-supplied ``%*s`` width) is rejected, so a
  pathological ``'x' * 10**9`` / ``'%999999s'`` / ``'%*s' % (10**9, 'x')`` cannot allocate a
  giant transient at analysis time (Rule 7). NOT folded here (a known residual, future work):
  pure-constant **container selection** — list/tuple/dict index, ``|first``/``|last`` —
  (``['__init__'][0]``) and ``namespace(c=...).c`` attribute propagation. A *bare-literal*
  container form leaves the identifier visible to a string-matcher, but a *split* one
  (``['__in' + 'it__'][0]``) still hides it, so this stays a genuine (if contrived) residual
  bypass to fold later, not a string-matcher-visible gap. The fully dynamic / runtime-built
  name remains the permanent static ceiling (the gated ``--confirm`` sandbox is the backstop).
* **Reflection resolution.** ``getattr(obj, '<name>')`` / ``setattr(obj, '<name>', value)``
  where ``<name>`` is a constant (after the folds above) **and** names a dangerous
  identifier resolves to the equivalent attribute access ``obj.<name>``, so it classifies
  as the precise dunder/code-exec sink (GH-S001/GH-S002) instead of a generic reflection
  call. The name may be passed positionally or as a keyword (``getattr(obj, name='...')``,
  Phase 10). A benign or non-constant name is left as a reflection call (GH-S004 unchanged),
  so the deliberate reflection-anomaly signal is preserved.

On top of the folds, a **constant-propagation** pass (Phase 13) substitutes ``{% set %}``
variables bound to a constant string into their loads — so a dangerous identifier carried in
a variable (``{% set c = '__class__' %}{{ x[c] }}``) is exposed to the same ``Const``-only walk.
It runs *between* two folds (fold -> propagate -> fold) so a value built by concatenation folds
first and a substitution that re-creates a concatenation folds after. It is conservative
(a name is propagated only when every binding of it is the same constant ``{% set %}``) and
constant-only — never evaluated or rendered (Rule 4/6). See :func:`_propagate_constants`.

The "is this name dangerous?" catalog is **passed in** (``dangerous_names``) rather than
imported, so this Stage-2 module has no dependency on Stage-3 — it stays a pure leaf and
there is no parse <-> analyze import cycle. The caller (``analyze.sinks.analyze_template``)
supplies ``DANGEROUS_DUNDERS | CODE_EXEC_NAMES``.

Determinism (Rule 7): a single post-order rewrite of a *copy* of the AST; same template ->
same normalized tree. The original AST is never mutated, so the Phase-1 golden (dumped from
``parse_template``) is unaffected.
"""

from __future__ import annotations

import copy
import re
import string
from dataclasses import dataclass

from jinja2 import nodes


@dataclass(frozen=True)
class NormalizedAST:
    """A de-obfuscated AST plus the list of folds applied (ARCHITECTURE.md §5).

    ``deobfuscations_applied`` is an audit trail of the rewrites — evidence that the tool
    actually folded something, for reporting (Phase 5) and debugging.
    """

    ast: nodes.Node
    deobfuscations_applied: tuple[str, ...] = ()


def normalize(ast: nodes.Node, *, dangerous_names: frozenset[str]) -> NormalizedAST:
    """Fold obfuscation in a parsed AST and return a :class:`NormalizedAST`.

    Rewrites a deep copy, so the input AST is left untouched. ``dangerous_names`` is the
    set of identifiers worth resolving a ``getattr``/``setattr`` into (the Stage-3 dunder +
    code-exec catalog), injected by the caller to keep this module free of a Stage-3 import.

    Three deterministic stages over the copy (Phase 13): **fold -> propagate -> fold**. The
    first fold turns each ``{% set %}`` value that is built from literals into a ``Const``;
    :func:`_propagate_constants` then substitutes those constant-bound variables into their
    loads, so a dangerous identifier held in a variable (``{% set c = '__class__' %}{{ x[c] }}``)
    becomes visible to the unchanged ``Const``-only walk; the second fold collapses any
    concatenation the substitution newly exposes (``x[a + b]`` once ``a``/``b`` are consts).
    """
    applied: list[str] = []
    tree = _transform(copy.deepcopy(ast), dangerous_names, applied)
    tree = _propagate_constants(tree, applied)
    tree = _transform(tree, dangerous_names, applied)
    return NormalizedAST(tree, tuple(applied))


def _propagate_constants(root: nodes.Node, applied: list[str]) -> nodes.Node:
    """Phase 13: substitute ``{% set %}`` variables bound to a constant string into their
    loads, so a variable-held dangerous identifier becomes visible to the Stage-3 walk.

    Conservative + deterministic. A name is propagated **only** when every one of its
    store/param occurrences is a simple ``{% set name = <const string> %}`` carrying the
    *same* value — so a loop variable, a macro/``with`` parameter, a ``{% set %}…{% endset %}``
    block, a tuple-unpack target, or any re-binding to a non-constant (or a different
    constant) drops the name entirely. Constant-only: no expression is evaluated and nothing
    is rendered (Rule 4/6). Loads are replaced by a ``Const``; the ``{% set %}`` statement is
    left in place (harmless — a ``Const`` value is never an identifier the walk inspects).
    """
    env = _constant_set_env(root)
    if env:
        _substitute_loads(root, env, applied)
    return root


def _constant_set_env(root: nodes.Node) -> dict[str, str]:
    """The name -> constant-string map safe to propagate (see :func:`_propagate_constants`).

    A name qualifies iff (a) it has at least one ``Assign(Name, Const-string)`` binding, (b)
    all such bindings share one value, and (c) **every** store/param occurrence of the name
    is one of those constant assigns — i.e. it is never bound any other way. Counting total
    store/param occurrences against the constant-assign count makes the check cover loop
    targets, parameters, blocks and re-bindings without enumerating each construct.
    """
    const_values: dict[str, set[str]] = {}   # name -> distinct constant string values
    const_assigns: dict[str, int] = {}        # name -> count of `set name = <const str>`
    store_count: dict[str, int] = {}          # name -> total store/param occurrences

    for name_node in root.find_all(nodes.Name):
        if name_node.ctx in ("store", "param"):
            store_count[name_node.name] = store_count.get(name_node.name, 0) + 1

    for assign in root.find_all(nodes.Assign):
        target = assign.target
        if (isinstance(target, nodes.Name)
                and isinstance(assign.node, nodes.Const) and isinstance(assign.node.value, str)):
            const_values.setdefault(target.name, set()).add(assign.node.value)
            const_assigns[target.name] = const_assigns.get(target.name, 0) + 1

    return {
        name: next(iter(values))
        for name, values in const_values.items()
        if len(values) == 1 and store_count.get(name, 0) == const_assigns[name]
    }


def _substitute_loads(node: nodes.Node, env: dict[str, str], applied: list[str]) -> nodes.Node:
    """Replace every *load* of a name in ``env`` with its ``Const``, recursively. Mirrors
    :func:`_transform`'s field walk; only ``ctx == "load"`` names are touched, so a ``set``
    target (``ctx == "store"``) is never rewritten."""
    for field in node.fields:
        value = getattr(node, field)
        if isinstance(value, nodes.Node):
            setattr(node, field, _substitute_node(value, env, applied))
        elif isinstance(value, (list, tuple)):
            rewritten = [
                _substitute_node(v, env, applied) if isinstance(v, nodes.Node) else v
                for v in value
            ]
            setattr(node, field, type(value)(rewritten))
    return node


def _substitute_node(node: nodes.Node, env: dict[str, str], applied: list[str]) -> nodes.Node:
    if isinstance(node, nodes.Name) and node.ctx == "load" and node.name in env:
        applied.append(f"const-propagate {node.name} -> {env[node.name]!r}")
        return nodes.Const(env[node.name], lineno=getattr(node, "lineno", 0))
    return _substitute_loads(node, env, applied)


def _transform(node: nodes.Node, dangerous_names: frozenset[str], applied: list[str]) -> nodes.Node:
    """Post-order rewrite: normalize every child first, then the node itself.

    Folding children first means a ``getattr`` argument or a subscript key that is itself a
    concatenation is already a ``Const`` by the time we inspect this node.
    """
    for field in node.fields:
        value = getattr(node, field)
        if isinstance(value, nodes.Node):
            setattr(node, field, _transform(value, dangerous_names, applied))
        elif isinstance(value, (list, tuple)):
            rewritten = [
                _transform(v, dangerous_names, applied) if isinstance(v, nodes.Node) else v
                for v in value
            ]
            setattr(node, field, type(value)(rewritten))

    folded = _fold_string_concat(node, applied)
    if folded is not None:
        return folded
    built = _fold_const_string_op(node, applied)
    if built is not None:
        return built
    resolved = _resolve_reflection(node, dangerous_names, applied)
    if resolved is not None:
        return resolved
    return node


def _fold_string_concat(node: nodes.Node, applied: list[str]) -> nodes.Const | None:
    """Collapse an ``Add``/``Concat`` of string constants into one ``Const``, else None.

    Children are already folded (post-order), so a fully-constant concatenation has all
    operands as string ``Const`` nodes here. Anything else (a number, a variable) yields
    None and is left as-is — we never fold non-string or non-constant operations.
    """
    if isinstance(node, nodes.Add):
        parts: list[nodes.Node] = [node.left, node.right]
    elif isinstance(node, nodes.Concat):
        parts = list(node.nodes)
    else:
        return None

    pieces: list[str] = []
    for part in parts:
        if isinstance(part, nodes.Const) and isinstance(part.value, str):
            pieces.append(part.value)
        else:
            return None

    value = "".join(pieces)
    applied.append(f"string-concat -> {value!r}")
    return nodes.Const(value, lineno=getattr(node, "lineno", 0))


# A folded constant longer than this is never a hidden identifier; rejecting it bounds
# analysis-time work against a pathological `'{:>9999999}'.format('x')` (Rule 7).
_MAX_FOLDED_LEN = 4096


def _make_const(node: nodes.Node, value: object, note: str, applied: list[str]) -> nodes.Const | None:
    """Wrap a computed value as a ``Const`` (lineno preserved) — only if it is a string of
    plausible identifier length. Non-string or over-long results are left unfolded."""
    if not isinstance(value, str) or len(value) > _MAX_FOLDED_LEN:
        return None
    applied.append(note)
    return nodes.Const(value, lineno=getattr(node, "lineno", 0))


def _const_values(parts: list) -> list | None:
    """The constant values of ``parts``, or None if any element is not a ``Const``."""
    out = []
    for p in parts:
        if isinstance(p, nodes.Const):
            out.append(p.value)
        else:
            return None
    return out


def _const_int_bound(node: object) -> tuple[bool, int | None]:
    """(ok, value) for a constant int slice bound or ``None``; (False, None) otherwise.

    A negative bound is written ``Neg(Const(int))`` in the AST (``-1`` is unary-minus over a
    literal, not a negative ``Const``), so unwrap one ``Neg`` — this is what lets a reverse
    slice ``'__ssalc__'[::-1]`` fold to ``'__class__'`` (Phase 16). ``bool`` is excluded —
    ``True``/``False`` are ints in Python but never a real index.
    """
    if node is None:
        return True, None
    if isinstance(node, nodes.Const) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return True, node.value
    if (isinstance(node, nodes.Neg) and isinstance(node.node, nodes.Const)
            and isinstance(node.node.value, int) and not isinstance(node.node.value, bool)):
        return True, -node.node.value
    return False, None


def _format_has_only_simple_fields(fmt: str) -> bool:
    """True only if every ``str.format`` field is a plain substitution — no attribute (``.``)
    or item (``[``) access, and no nested field in the format spec.

    This is a safety gate (Rule 4/6): ``'{0.__class__.__init__.__globals__}'.format(x)`` would
    make ``str.format`` *traverse attributes* at analysis time. We only ever want to fold the
    identifier-assembly forms an evader actually uses (``'{}{}'.format('__cl', 'ass__')``), so a
    format string that reaches into an object is left unfolded rather than evaluated.
    """
    try:
        fields = list(string.Formatter().parse(fmt))
    except ValueError:
        return False
    for _literal, field_name, spec, _conv in fields:
        if field_name and ("." in field_name or "[" in field_name):
            return False
        if spec and "{" in spec:  # a nested field in the spec could hide attribute access
            return False
    return True


def _fold_const_string_op(node: nodes.Node, applied: list[str]) -> nodes.Const | None:
    """Fold a constant string *builder* — ``str.format`` / slice / index / ``|join`` /
    ``|replace`` — to one ``Const``, else None.

    Children are already folded (post-order), so an operand that was itself a concatenation
    is already a ``Const`` here. Every operand must be constant: we compute the result over
    string literals only and never evaluate a dynamic expression or render anything
    (Rule 4/6). Each builder is the way a string-matcher-evading template assembles an
    identifier without writing it literally.
    """
    # 'str' * n  (repetition) — bounded before it computes (Phase 19)
    if isinstance(node, nodes.Mul):
        return _fold_string_mul(node, applied)

    # 'fmt' % args  (printf via the % operator, Phase 19)
    if isinstance(node, nodes.Mod):
        return _fold_string_mod(node, applied)

    # 'fmt'.format(*const_args, **const_kwargs)
    if (isinstance(node, nodes.Call) and isinstance(node.node, nodes.Getattr)
            and node.node.attr == "format"
            and isinstance(node.node.node, nodes.Const)
            and isinstance(node.node.node.value, str)):
        if node.dyn_args is not None or node.dyn_kwargs is not None:
            return None
        if not _format_has_only_simple_fields(node.node.node.value):
            return None  # a field like {0.__class__} would access attributes — never do that
        args = _const_values(node.args)
        if args is None:
            return None
        kwargs: dict[str, object] = {}
        for kw in node.kwargs:
            if not isinstance(kw.value, nodes.Const):
                return None
            kwargs[kw.key] = kw.value.value
        try:
            value = node.node.node.value.format(*args, **kwargs)
        except (IndexError, KeyError, ValueError):
            return None
        return _make_const(node, value, f"str.format -> {value!r}", applied)

    # 'const'[i]  or  'const'[a:b:c]
    if (isinstance(node, nodes.Getitem) and isinstance(node.node, nodes.Const)
            and isinstance(node.node.value, str)):
        s = node.node.value
        arg = node.arg
        if isinstance(arg, nodes.Const) and isinstance(arg.value, int) and not isinstance(arg.value, bool):
            try:
                value = s[arg.value]
            except IndexError:
                return None
            return _make_const(node, value, f"const-index -> {value!r}", applied)
        if isinstance(arg, nodes.Slice):
            ok_a, start = _const_int_bound(arg.start)
            ok_b, stop = _const_int_bound(arg.stop)
            ok_c, step = _const_int_bound(arg.step)
            if ok_a and ok_b and ok_c:
                try:
                    value = s[start:stop:step]
                except ValueError:
                    return None  # e.g. a zero step `'x'[::0]` — never a real identifier build
                return _make_const(node, value, f"const-slice -> {value!r}", applied)
        return None

    if isinstance(node, nodes.Filter):
        if node.name == "join":
            return _fold_join(node, applied)
        if node.name == "replace":
            return _fold_replace(node, applied)
        if node.name == "format":
            return _fold_format_filter(node, applied)
        return _fold_string_transform(node, applied)
    return None


def _fold_string_mul(node: nodes.Mul, applied: list[str]) -> nodes.Const | None:
    """``'_' * 2`` (string repetition, either operand order) over constants -> ``Const``.

    The multiplier * length is checked against ``_MAX_FOLDED_LEN`` BEFORE computing, so a
    pathological ``'x' * 10**9`` is rejected without allocating a giant transient string
    (Rule 7) — never an identifier anyway. A non-positive count yields ``''`` (harmless)."""
    for s_node, n_node in ((node.left, node.right), (node.right, node.left)):
        if (isinstance(s_node, nodes.Const) and isinstance(s_node.value, str)
                and isinstance(n_node, nodes.Const) and isinstance(n_node.value, int)
                and not isinstance(n_node.value, bool)):
            n = n_node.value
            if n > 0 and n * len(s_node.value) > _MAX_FOLDED_LEN:
                return None
            value = s_node.value * n
            return _make_const(node, value, f"str-mul -> {value!r}", applied)
    return None


def _fold_string_mod(node: nodes.Mod, applied: list[str]) -> nodes.Const | None:
    """``'fmt' % args`` printf over constants -> ``Const``. The right operand is a single
    ``Const`` (``'__%s__' % 'init'``) or a ``Tuple`` of ``Const``s (``'%s%s' % ('a','b')``);
    a ``List`` is NOT unpacked (Python ``%`` does not), so it is left unfolded."""
    if not (isinstance(node.left, nodes.Const) and isinstance(node.left.value, str)):
        return None
    right = node.right
    if isinstance(right, nodes.Tuple):
        vals = _const_values(right.items)
        if vals is None:
            return None
        args: object = tuple(vals)
    elif isinstance(right, nodes.Const):
        args = right.value
    else:
        return None
    return _apply_printf(node, node.left.value, args, "str-mod", applied)


def _fold_format_filter(node: nodes.Filter, applied: list[str]) -> nodes.Const | None:
    """The Jinja ``|format`` filter == printf: ``'%s%s'|format('a','b')`` -> ``'%s%s' % ('a','b')``.
    Folds only when the format string and every argument are constants (Rule 4/6)."""
    if node.dyn_args is not None or node.dyn_kwargs is not None or node.kwargs:
        return None
    if not (isinstance(node.node, nodes.Const) and isinstance(node.node.value, str)):
        return None
    args = _const_values(node.args)
    if args is None:
        return None
    return _apply_printf(node, node.node.value, tuple(args), "format-filter", applied)


def _apply_printf(node: nodes.Node, fmt: str, args: object, note: str,
                  applied: list[str]) -> nodes.Const | None:
    """Compute ``fmt % args`` over constants, guarding width and exceptions. Two width guards
    BEFORE the format runs so a pathological width never allocates a giant transient (Rule 7):
    (1) an arg-supplied width/precision (``%*s`` / ``%.*f`` — the width comes from an argument,
    not the format string, so a digit scan cannot bound it) is refused outright; a dynamic
    width is never part of a hidden identifier, so this costs no detection. (2) any literal
    width/precision ``>= _MAX_FOLDED_LEN`` is rejected. A type/format mismatch leaves it
    unfolded."""
    if re.search(r"%[-+ #0]*(?:\*|\d*\.\*)", fmt):
        return None  # arg-supplied (`*`) width/precision — unbounded by the format string
    for m in re.finditer(r"%[-+ #0]*(\d+)?(?:\.(\d+))?", fmt):
        for digits in m.groups():
            if digits is not None and int(digits) >= _MAX_FOLDED_LEN:
                return None
    try:
        value = fmt % args
    except (TypeError, ValueError, KeyError):
        return None
    return _make_const(node, value, f"{note} -> {value!r}", applied)


def _fold_join(node: nodes.Filter, applied: list[str]) -> nodes.Const | None:
    """``['__cl', 'ass__']|join`` / ``[...]|join('sep')`` over constant strings -> ``Const``."""
    if node.dyn_args is not None or node.dyn_kwargs is not None:
        return None
    if not isinstance(node.node, (nodes.List, nodes.Tuple)):
        return None
    items = _const_values(node.node.items)
    if items is None or not all(isinstance(i, str) for i in items):
        return None
    sep = ""
    if node.args:
        if not (isinstance(node.args[0], nodes.Const) and isinstance(node.args[0].value, str)):
            return None
        sep = node.args[0].value
    for kw in node.kwargs:
        if kw.key == "attribute":
            return None  # joining an object's attribute is not a constant build
        if kw.key == "d":
            if not (isinstance(kw.value, nodes.Const) and isinstance(kw.value.value, str)):
                return None
            sep = kw.value.value
    return _make_const(node, sep.join(items), f"join -> {sep.join(items)!r}", applied)


def _fold_replace(node: nodes.Filter, applied: list[str]) -> nodes.Const | None:
    """``'__ZZ__'|replace('ZZ', 'class')`` over constant strings -> ``Const``."""
    if node.dyn_args is not None or node.dyn_kwargs is not None:
        return None
    if not (isinstance(node.node, nodes.Const) and isinstance(node.node.value, str)):
        return None
    params = ("old", "new", "count")
    vals: dict[str, object] = {}
    for i, a in enumerate(node.args):
        if i >= len(params) or not isinstance(a, nodes.Const):
            return None
        vals[params[i]] = a.value
    for kw in node.kwargs:
        if kw.key not in params or not isinstance(kw.value, nodes.Const):
            return None
        vals[kw.key] = kw.value.value
    old, new = vals.get("old"), vals.get("new")
    if not (isinstance(old, str) and isinstance(new, str)):
        return None
    count = vals.get("count")
    if count is None:
        value = node.node.value.replace(old, new)
    elif isinstance(count, int) and not isinstance(count, bool):
        value = node.node.value.replace(old, new, count)
    else:
        return None
    return _make_const(node, value, f"replace -> {value!r}", applied)


# Pure, side-effect-free string-transform filters (Phase 16): name -> the function over the
# string literal. These are the identifier transforms an evader uses to hide a dunder/code-exec
# name behind a non-matching literal — case folds, whitespace strip, and reverse. `trim`/`strip`
# strip whitespace (the no-argument form); `reverse` of a string is `s[::-1]` (matches Jinja's
# `do_reverse`). Folding fires only when the operand is a `Const` string, so nothing dynamic is
# ever evaluated (Rule 4/6). Closes the `''['__CLASS__'|lower]` case-fold bypass.
_STRING_TRANSFORM_FILTERS = {
    "lower": str.lower,
    "upper": str.upper,
    "title": str.title,
    "capitalize": str.capitalize,
    "swapcase": str.swapcase,
    "trim": str.strip,
    "strip": str.strip,
    "reverse": lambda s: s[::-1],
    "string": str,   # Phase 19: the |string cast (identity on a str) — an evader wraps it
}                    # around a foldable expression to break the fold; folding it re-exposes the name.


def _fold_string_transform(node: nodes.Filter, applied: list[str]) -> nodes.Const | None:
    """Fold a pure string-transform filter (``|lower``/``|upper``/…/``|reverse``) over a
    constant string to one ``Const``, else None (Phase 16).

    Children are already folded (post-order), so an operand that was itself assembled from
    literals is already a ``Const`` here — and chained transforms (``'X'|upper|lower``) fold
    bottom-up. Only the no-argument forms fold: a transform carrying an argument (or any
    keyword/splat) is left as a filter for taint to handle, mirroring the project's rule that
    only *pure-constant* builds are normalized and dynamic ones are not. Computes over the
    string literal only — nothing is evaluated or rendered (Rule 4/6).
    """
    fn = _STRING_TRANSFORM_FILTERS.get(node.name)
    if fn is None:
        return None
    if node.args or node.kwargs or node.dyn_args is not None or node.dyn_kwargs is not None:
        return None
    if not (isinstance(node.node, nodes.Const) and isinstance(node.node.value, str)):
        return None
    value = fn(node.node.value)
    return _make_const(node, value, f"{node.name} -> {value!r}", applied)


def _resolve_reflection(node: nodes.Node, dangerous_names: frozenset[str],
                        applied: list[str]) -> nodes.Node | None:
    """Resolve ``getattr``/``setattr`` with a constant *dangerous* name into attribute
    access, else None.

    ``getattr(obj, '__class__')`` -> ``obj.__class__`` (a ``Getattr``) so it classifies as
    the dunder sink. ``setattr(obj, '__class__', value)`` keeps the assigned ``value`` as a
    sub-node (wrapped on the resolved access) so a sink hidden inside it is not lost. A
    benign or non-constant name is left untouched (stays a GH-S004 reflection call).
    """
    if not (isinstance(node, nodes.Call) and isinstance(node.node, nodes.Name)):
        return None
    func = node.node.name
    if func not in ("getattr", "setattr"):
        return None
    if node.dyn_args is not None or node.dyn_kwargs is not None:
        return None  # *args/**kwargs may hide the name — leave it as a reflection call
    obj = _call_arg(node, 0, "object")
    name = _call_arg(node, 1, "name")
    if obj is None or name is None:
        return None
    if not (isinstance(name, nodes.Const) and isinstance(name.value, str)):
        return None
    if name.value not in dangerous_names:
        return None

    lineno = getattr(node, "lineno", 0)
    access = nodes.Getattr(obj, name.value, "load", lineno=lineno)
    value = _call_arg(node, 2, "value")
    if func == "setattr" and value is not None:
        applied.append(f"setattr -> .{name.value}")
        # Retain the assigned value as an argument so its own subtree is still analyzed.
        return nodes.Call(access, [value], [], None, None, lineno=lineno)
    applied.append(f"getattr -> .{name.value}")
    return access


def _call_arg(node: nodes.Call, index: int, key: str) -> nodes.Node | None:
    """The positional argument at ``index``, else the keyword argument named ``key``, else
    None — so ``getattr(obj, '__class__')`` and ``getattr(obj, name='__class__')`` resolve
    the same (Phase 10: the dunder name can hide in a keyword argument)."""
    if len(node.args) > index:
        return node.args[index]
    for kw in node.kwargs:
        if kw.key == key:
            return kw.value
    return None
