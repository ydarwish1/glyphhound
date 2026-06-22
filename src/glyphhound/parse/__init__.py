"""Stage 2 — Parser + de-obfuscator.

Phase 1 implements the parser (a template string -> a Jinja2 AST) and Phase 4 the
de-obfuscation pre-pass (folding obfuscation in that AST before analysis); see
ARCHITECTURE.md §"Stage 2". ``parse_template`` stays a pure parse so the Phase-1 golden is
stable; ``normalize`` is the separate fold step the analyzer runs next.
"""

from .deobfuscate import NormalizedAST, normalize
from .jinja_ast import (
    PARSE_EXTENSIONS,
    ParseError,
    dump_ast,
    make_parse_environment,
    parse_template,
)

__all__ = [
    "ParseError",
    "parse_template",
    "dump_ast",
    "make_parse_environment",
    "PARSE_EXTENSIONS",
    "normalize",
    "NormalizedAST",
]
