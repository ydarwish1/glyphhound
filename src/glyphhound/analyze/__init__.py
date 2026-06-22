"""Stage 3 — Analyzer: sink catalog + taint/reachability.

Phase 2 implements the **string/structural baseline**: walk the Jinja2 AST and flag
the §4 sink catalog by inspecting identifier nodes (see ARCHITECTURE.md §"Stage 3").
Taint/reachability is Phase 3 and de-obfuscation is Phase 4.
"""

from .models import (
    CODE_EXEC_NAMES,
    DANGEROUS_DUNDERS,
    REFLECTION_BUILTINS,
    RULE_CATALOG,
    Finding,
)
from .sinks import analyze_ast, analyze_raw, analyze_template

__all__ = [
    "Finding",
    "analyze_template",
    "analyze_ast",
    "analyze_raw",
    "RULE_CATALOG",
    "DANGEROUS_DUNDERS",
    "CODE_EXEC_NAMES",
    "REFLECTION_BUILTINS",
]
