"""Stage 2 (Parser) -- turn a chat-template string into a Jinja2 AST.

This is the *parse* half of Stage 2 (ARCHITECTURE.md section "Stage 2"); the de-obfuscation
pre-pass is Phase 4. We parse with ``jinja2.Environment().parse()`` -- pure syntax
analysis, no rendering -- so reading a hostile template here cannot execute it.

Two deliberate choices, both for security coverage rather than convenience:

* **The ``do``, ``loopcontrols`` and ``generation`` extensions are enabled.** Real chat
  templates use ``{% do ... %}`` and ``{% break %}``/``{% continue %}``, and HuggingFace
  templates use ``{% generation %}...{% endgeneration %}`` (assistant-mask markers); without
  these extensions Jinja raises ``TemplateSyntaxError`` and we would fail to analyze the very
  ``{% do evil() %}`` form that can hold a sink -- or skip a whole template for an unknown tag.
  Parsing them faithfully is the point of an AST-based scanner. ``generation`` is a local
  passthrough (:class:`GenerationExtension`) that preserves the block's inner nodes.
* **A plain (non-sandboxed) Environment is used.** Sandboxing only restricts
  attribute access at *render* time; it has no effect on parsing, and we never
  render here. The plain environment is the simplest thing that yields the AST.

The AST node API is pinned via ``jinja2==3.1.6`` (pyproject) so ``node.fields``
ordering -- which :func:`dump_ast` relies on for determinism -- cannot drift.
"""

from __future__ import annotations

import jinja2
from jinja2 import nodes
from jinja2.ext import Extension


class GenerationExtension(Extension):
    """Parse HuggingFace's ``{% generation %}...{% endgeneration %}`` block as a passthrough.

    transformers wraps the *assistant-generated* span of a chat template in this tag so it can
    build a token mask at render time; without the matching extension Jinja raises a
    ``TemplateSyntaxError`` and the whole template is unparseable (5 real templates were
    build-skipped from the FP corpus for exactly this). We don't need the mask -- we need the
    **inner nodes preserved** so the Stage-3 sink/taint walk still sees anything inside the
    block -- so a minimal passthrough that returns the block body is enough, and avoids taking on
    a transformers dependency. Parsing only (we never render), so this executes no template code.
    """

    tags = {"generation"}

    def parse(self, parser):
        next(parser.stream)  # consume the 'generation' tag keyword
        # Parse the body up to {% endgeneration %} and emit it inline (passthrough): the inner
        # nodes stay in the AST so a sink hidden inside a generation block is still analyzed.
        return parser.parse_statements(("name:endgeneration",), drop_needle=True)


# Extensions enabled for parsing -- see module docstring for the security rationale.
PARSE_EXTENSIONS = ("jinja2.ext.do", "jinja2.ext.loopcontrols", GenerationExtension)

# Deep-nest DoS guard (Phase 20). The Stage-2 de-obfuscator and the Stage-3 walk recurse per
# AST level, so a pathologically nested hostile template (e.g. thousands of chained `+`) would
# raise an uncaught RecursionError mid-analysis. Reject such a template cleanly at the parse
# gateway instead. Calibrated from real data: the deepest benign corpus template nests 29
# levels and the analyzer starts overflowing around ~220 -- so 100 is ~3x any real template and
# ~2x below the overflow. A normal chat template is nowhere near this.
_MAX_AST_DEPTH = 100


class ParseError(Exception):
    """A template string could not be parsed into a Jinja2 AST.

    Wraps Jinja2's :class:`~jinja2.TemplateSyntaxError` so callers can catch a
    GlyphHound-owned type, the way Stage 1 exposes ``AcquireError``.
    """


def make_parse_environment() -> jinja2.Environment:
    """The Environment used for parsing -- deterministic, render-free, no autoescape.

    Exposed so later stages parse templates exactly the same way (same extensions,
    so the same AST) instead of re-deriving the configuration.
    """
    return jinja2.Environment(extensions=PARSE_EXTENSIONS, autoescape=False)


def parse_template(template_string: str) -> nodes.Template:
    """Parse a chat-template string into a Jinja2 AST (a :class:`nodes.Template`).

    Raises :class:`ParseError` on malformed templates -- never a raw
    ``TemplateSyntaxError`` -- so a caller's ``except ParseError`` is enough.
    """
    env = make_parse_environment()
    try:
        ast = env.parse(template_string)
    except jinja2.TemplateSyntaxError as exc:
        where = f" at line {exc.lineno}" if exc.lineno else ""
        raise ParseError(f"template did not parse{where}: {exc.message}") from exc
    except RecursionError as exc:  # extreme nesting overflows Jinja's own recursive parser
        raise ParseError("template is too deeply nested to parse") from exc
    if _ast_too_deep(ast, _MAX_AST_DEPTH):
        raise ParseError(
            f"template AST nests deeper than {_MAX_AST_DEPTH} levels; refusing to analyze "
            "(deep-nest denial-of-service guard, Phase 20)"
        )
    return ast


def _ast_too_deep(root: nodes.Node, limit: int) -> bool:
    """Whether the AST nests deeper than ``limit`` levels. Iterative (its own traversal never
    recurses), so the depth check itself cannot overflow on a hostile template."""
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return True
        for field in node.fields:
            value = getattr(node, field)
            if isinstance(value, nodes.Node):
                stack.append((value, depth + 1))
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, nodes.Node):
                        stack.append((item, depth + 1))
    return False


def dump_ast(node: nodes.Node) -> str:
    """Render an AST as a deterministic, indented, line-number-free tree.

    Walks only ``node.fields`` (the structural children) and never ``node.attributes``
    (``lineno``/``environment``), so the same template always produces the same dump --
    suitable as a golden value for the Phase 1 verification check.
    """
    lines: list[str] = []
    _dump_node(node, 0, lines)
    return "\n".join(lines)


def _dump_node(node: nodes.Node, depth: int, lines: list[str]) -> None:
    pad = "  " * depth
    lines.append(f"{pad}{type(node).__name__}")
    for field in node.fields:
        _dump_field(field, getattr(node, field), depth + 1, lines)


def _dump_field(label: str, value: object, depth: int, lines: list[str]) -> None:
    pad = "  " * depth
    if isinstance(value, nodes.Node):
        lines.append(f"{pad}{label}:")
        _dump_node(value, depth + 1, lines)
    elif isinstance(value, (list, tuple)):
        if not value:
            lines.append(f"{pad}{label}: []")
            return
        lines.append(f"{pad}{label}:")
        for item in value:
            if isinstance(item, nodes.Node):
                _dump_node(item, depth + 1, lines)
            else:
                lines.append(f"{'  ' * (depth + 1)}{item!r}")
    else:
        # Scalars only here (str / int / float / bool / None); their repr is stable.
        lines.append(f"{pad}{label}: {value!r}")
