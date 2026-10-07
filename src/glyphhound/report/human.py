"""Stage 5 -- human-readable renderer.

A readable, deterministic summary of a :class:`~.models.Report`: one block per finding
citing its rule id, severity, reachability (reachable vs presence-only), source
template + line, evidence, and the rule rationale -- plus a header and a summary line.
Formats ``Finding[]`` only; never renders a template (the Phase-5 safety boundary).
No timestamps or randomness, so the output is deterministic.
"""

from __future__ import annotations

from ..analyze.models import RULE_CATALOG
from .models import Report, ReportSummary, TargetResult, gates_ci, targets_exit_code

# How a finding's reachability reads in the report.
_REACHABILITY = {True: "reachable", False: "presence-only", None: "unanalyzed"}


def display_text(value: str) -> str:
    """``value`` with every non-printable character written as its Python escape.

    Template names, error messages and target names can carry text taken from a model; an
    ANSI escape (colours, cursor moves, OSC-8 links), a bidi override or a line break in
    them must not restyle, reorder or forge lines of the terminal report.
    """
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
                   for ch in value)


def _template_label(template_name: str | None) -> str:
    return "tokenizer.chat_template" if template_name is None \
        else f"tokenizer.chat_template.{display_text(template_name)}"


def _summary_line(s: ReportSummary) -> str:
    return (f"summary: {s.total} finding(s), {s.reachable} reachable; "
            f"critical={s.critical} high={s.high}; "
            f"{s.gating} gating -> exit {1 if s.gating else 0}")


def render_human(report: Report) -> str:
    """Render a :class:`Report` as human-readable text (trailing newline included)."""
    s = report.summary
    lines = [
        "GlyphHound scan report",
        "======================",
        f"threshold: fail CI on reachable findings of severity >= {s.severity_threshold}",
        f"exit code: {report.exit_code}",
        "",
    ]

    if not report.findings:
        lines.append("findings: 0 (nothing flagged at or above the detection threshold)")
        lines.append("")
        lines.append(_summary_line(s))
        return "\n".join(lines) + "\n"

    lines.append(f"findings ({s.total}):")
    for f in report.findings:
        reachability = _REACHABILITY.get(f.reachable, "unanalyzed")
        gate = "  [GATES CI]" if gates_ci(f, s.severity_threshold) else ""
        lines.append(
            f"  [{f.rule_id}] {f.severity.upper():8s} {reachability:13s} "
            f"{_template_label(f.template_name)}:{f.source_line}{gate}"
        )
        # ASCII separator: GlyphHound's primary console is Windows cp1252, where a
        # unicode em-dash mojibakes. Keep this output clean.
        lines.append(f"      {f.sink_kind}: {display_text(f.evidence)}")
        catalog = RULE_CATALOG.get(f.rule_id)
        if catalog is not None:
            lines.append(f"      reason: {catalog[2]}")
    lines.append("")
    lines.append(_summary_line(s))
    return "\n".join(lines) + "\n"


def _target_block(result: TargetResult) -> str:
    heading = f"=== target: {display_text(result.target)} ==="
    if result.report is not None:
        return f"{heading}\n{render_human(result.report)}"
    return f"{heading}\nerror: {display_text(result.error or '')}\nexit code: 2\n"


def _overall_line(results: list[TargetResult]) -> str:
    gating = sum(1 for r in results if r.exit_code == 1)
    failed = sum(1 for r in results if r.exit_code == 2)
    return (f"overall: {len(results)} target(s), {gating} gating, "
            f"{failed} could not be scanned -> exit {targets_exit_code(results)}\n")


def render_human_targets(results: list[TargetResult]) -> str:
    """Render a multi-target scan: each target's report under its own heading, then an
    overall line with the combined exit code."""
    return "\n".join([*(_target_block(r) for r in results), _overall_line(results)])
