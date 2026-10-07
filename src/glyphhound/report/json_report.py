"""Stage 5 -- machine-readable JSON renderer.

A flat, round-trippable serialization of a :class:`~.models.Report`
(``Report.to_dict`` -> JSON -> ``Report.from_dict`` yields an equal report). Named
``json_report`` rather than ``json`` so it cannot be confused with the stdlib module it
uses. Deterministic: fixed key order, trailing newline.
"""

from __future__ import annotations

import json

from .models import Report, TargetResult


def dump_json(value) -> str:
    """``value`` as indented JSON with a trailing newline, readable non-ASCII kept as is.

    ``json.dumps`` escapes only C0 controls, so every other non-printable character (a bidi
    override, a C1 control such as CSI, a line separator) that a template name, evidence or
    error message carries is written as a ``\\u`` escape too: it reads back as the same
    value but cannot drive a terminal or a viewer.
    """
    text = json.dumps(value, indent=2, ensure_ascii=False)
    return "".join(ch if ch.isprintable() or ch == "\n" else json.dumps(ch)[1:-1]
                   for ch in text) + "\n"


def render_json(report: Report) -> str:
    """Render a :class:`Report` as deterministic JSON (trailing newline included)."""
    return dump_json(report.to_dict())


def render_json_targets(results: list[TargetResult]) -> str:
    """Render a multi-target scan as a JSON list with one report per target, in the given
    order; a target that could not be scanned carries ``exit_code`` 2 and an ``error``."""
    return dump_json([r.to_dict() for r in results])
