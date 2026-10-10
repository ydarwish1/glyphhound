"""Stage 5 -- Reporter: human / JSON / SARIF 2.1.0 / Markdown + CI exit codes (Phase 5).

Turns the analyzer's ``Finding[]`` into consumable output with a CI-gating exit code
(ARCHITECTURE.md section 3 Stage 5, section 5 data model). This is a pure formatting
layer: it consumes findings and **never parses, renders, or executes a template** --
rendering is the dangerous act reserved for the Phase-6 sandbox.
"""

from .human import display_text, render_human, render_human_targets
from .json_report import render_json, render_json_targets
from .markdown import md_code, render_markdown, render_markdown_targets
from .models import (
    DEFAULT_SEVERITY_THRESHOLD,
    Report,
    ReportSummary,
    TargetResult,
    gates_ci,
    make_report,
    targets_exit_code,
)
from .sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    SEVERITY_TO_SARIF_LEVEL,
    render_sarif,
    render_sarif_targets,
)

__all__ = [
    "Report",
    "ReportSummary",
    "TargetResult",
    "make_report",
    "gates_ci",
    "targets_exit_code",
    "DEFAULT_SEVERITY_THRESHOLD",
    "display_text",
    "render_human",
    "render_human_targets",
    "render_json",
    "render_json_targets",
    "md_code",
    "render_markdown",
    "render_markdown_targets",
    "render_sarif",
    "render_sarif_targets",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "SEVERITY_TO_SARIF_LEVEL",
]
