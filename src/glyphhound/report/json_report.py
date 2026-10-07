"""Stage 5 -- machine-readable JSON renderer.

A flat, round-trippable serialization of a :class:`~.models.Report`
(``Report.to_dict`` -> JSON -> ``Report.from_dict`` yields an equal report). Named
``json_report`` rather than ``json`` so it cannot be confused with the stdlib module it
uses. Deterministic: fixed key order, trailing newline.
"""

from __future__ import annotations

import json

from .models import Report, TargetResult


def render_json(report: Report) -> str:
    """Render a :class:`Report` as deterministic JSON (trailing newline included)."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_json_targets(results: list[TargetResult]) -> str:
    """Render a multi-target scan as a JSON list with one report per target, in the given
    order; a target that could not be scanned carries ``exit_code`` 2 and an ``error``."""
    return json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False) + "\n"
