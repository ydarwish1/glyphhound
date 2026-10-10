"""Stage 5 -- Markdown renderer, for a pull request comment.

The same content as the human report (:mod:`.human`), laid out as Markdown. Every value
taken from a template or model -- a target, a template name, evidence, an error message --
is put in an inline code span (:func:`md_code`), so Markdown, HTML, links and @mentions in
it show as plain text. Formats ``Finding[]`` only; never renders a template.
"""

from __future__ import annotations

import re

from ..analyze.models import RULE_CATALOG, Finding
from .human import (
    _REACHABILITY,
    _overall_line,
    _summary_line,
    _template_label,
    display_text,
)
from .models import Report, TargetResult, gates_ci


def md_code(value: str) -> str:
    """``value`` as a Markdown inline code span that shows it as plain text.

    Non-printable characters are escaped first (:func:`display_text`), so a line break
    cannot end the span or the paragraph. The fence is one backtick longer than the longest
    run of backticks in ``value``, so no run inside can close it, and a value that starts or
    ends with a backtick or a space is padded with one space on each side, which Markdown
    strips again. An empty value is shown as a single space.
    """
    text = display_text(value)
    fence = "`" * (max((len(run) for run in re.findall("`+", text)), default=0) + 1)
    if text.strip(" ") and (text[0] in "` " or text[-1] in "` "):
        text = f" {text} "
    return f"{fence}{text or ' '}{fence}"


def _finding_lines(f: Finding, severity_threshold: str) -> list[str]:
    reachability = _REACHABILITY.get(f.reachable, "unanalyzed")
    gate = " **GATES CI**" if gates_ci(f, severity_threshold) else ""
    location = md_code(f"{_template_label(f.template_name)}:{f.source_line}")
    lines = [
        f"- {md_code(f.rule_id)} {f.severity.upper()} {reachability} {location}{gate}",
        f"  - {f.sink_kind}: {md_code(f.evidence)}",
    ]
    catalog = RULE_CATALOG.get(f.rule_id)
    if catalog is not None:
        lines.append(f"  - reason: {catalog[2]}")
    return lines


def _report_markdown(report: Report, heading: str) -> str:
    s = report.summary
    lines = [
        f"{heading} GlyphHound scan report",
        "",
        f"- threshold: fail CI on reachable findings of severity >= {s.severity_threshold}",
        f"- exit code: {report.exit_code}",
        "",
    ]
    if not report.findings:
        lines.append("findings: 0 (nothing flagged at or above the detection threshold)")
    else:
        lines += [f"findings ({s.total}):", ""]
        for f in report.findings:
            lines += _finding_lines(f, s.severity_threshold)
    lines += ["", _summary_line(s)]
    return "\n".join(lines) + "\n"


def render_markdown(report: Report) -> str:
    """Render a :class:`Report` as Markdown (trailing newline included)."""
    return _report_markdown(report, "##")


def _target_block(result: TargetResult) -> str:
    heading = f"## target: {md_code(result.target)}\n\n"
    if result.report is not None:
        return heading + _report_markdown(result.report, "###")
    return f"{heading}- error: {md_code(result.error or '')}\n- exit code: 2\n"


def render_markdown_targets(results: list[TargetResult]) -> str:
    """Render a multi-target scan as Markdown: each target's report under its own heading,
    then the overall line with the combined exit code."""
    return "\n".join([*(_target_block(r) for r in results), _overall_line(results)])
