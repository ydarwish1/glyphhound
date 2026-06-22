"""Stage 5 — Reporter: human / JSON / SARIF 2.1.0 + CI exit codes (Phase 5).

Turns the analyzer's ``Finding[]`` into consumable output with a CI-gating exit code
(ARCHITECTURE.md §3 Stage 5, §5 data model). This is a pure formatting
layer: it consumes findings and **never parses, renders, or executes a template** —
rendering is the dangerous act reserved for the Phase-6 sandbox.
"""

from .human import render_human
from .json_report import render_json
from .models import (
    DEFAULT_SEVERITY_THRESHOLD,
    Report,
    ReportSummary,
    gates_ci,
    make_report,
)
from .sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    SEVERITY_TO_SARIF_LEVEL,
    render_sarif,
)

__all__ = [
    "Report",
    "ReportSummary",
    "make_report",
    "gates_ci",
    "DEFAULT_SEVERITY_THRESHOLD",
    "render_human",
    "render_json",
    "render_sarif",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "SEVERITY_TO_SARIF_LEVEL",
]
