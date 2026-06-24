"""Stage 5 -- SARIF 2.1.0 renderer (ARCHITECTURE.md section 3 Stage 5).

Each :class:`~.models.Report` finding becomes a SARIF ``result``: ``ruleId`` = the rule
id, ``level`` mapped from severity (critical -> error, high -> warning), a
``physicalLocation`` whose ``artifactLocation.uri`` names the chat template the sink was
found in and whose ``region.startLine`` is the source line, and a ``message`` carrying
the evidence. ``runs[].tool.driver.rules`` is built from the analyzer's ``RULE_CATALOG``.

The output validates against the official OASIS SARIF 2.1.0 schema (vendored at
``schemas/sarif-2.1.0.json`` and checked in the offline test/verify layer). This module
emits with the stdlib ``json`` only -- it never imports ``jsonschema`` (a dev-only dep) --
so the shipped tool stays jinja2-only. It is deterministic: no timestamps, rules in sorted
id order, results in the findings' given order, fixed key order. It formats ``Finding[]``
only and never renders a template.
"""

from __future__ import annotations

import json

from .. import __version__
from ..analyze.models import CRITICAL, HIGH, RULE_CATALOG, cwe_for
from .models import Report, gates_ci

# An informational pointer to the schema the output conforms to (a constant, so it does
# not affect determinism). The vendored copy under schemas/ is what validation uses.
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Severity -> SARIF level. SARIF levels are none/note/warning/error.
SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {CRITICAL: "error", HIGH: "warning"}

# Stable rule order, independent of dict construction order (determinism).
_RULE_IDS = sorted(RULE_CATALOG)
_RULE_INDEX = {rid: i for i, rid in enumerate(_RULE_IDS)}


def _level(severity: str) -> str:
    return SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")


def _cwe_tag(cwe: str) -> str:
    """A CWE id (``'CWE-94'``) as the GitHub code-scanning tag ``external/cwe/cwe-094``
    (the numeric part is zero-padded to at least three digits, matching CodeQL)."""
    number = cwe.split("-")[-1]
    return f"external/cwe/cwe-{number.zfill(3)}"


def _template_uri(template_name: str | None) -> str:
    """The GGUF metadata key the template came from -- the honest 'where' of a finding.

    ``None`` is the default ``tokenizer.chat_template``; a named variant is
    ``tokenizer.chat_template.<name>`` (so a sink hidden in a named template is
    attributable in the SARIF artifact location).
    """
    if template_name is None:
        return "tokenizer.chat_template"
    return f"tokenizer.chat_template.{template_name}"


def _driver_rules() -> list[dict]:
    rules = []
    for rid in _RULE_IDS:
        sink_kind, severity, rationale, cwe = RULE_CATALOG[rid]
        rules.append({
            "id": rid,
            "name": sink_kind,
            "shortDescription": {"text": rationale},
            "defaultConfiguration": {"level": _level(severity)},
            # `tags` carries the CWE in GitHub code-scanning's convention so the security
            # category surfaces in the GitHub UI; `cwe` is the plain id for other consumers.
            "properties": {"severity": severity, "cwe": cwe, "tags": ["security", _cwe_tag(cwe)]},
        })
    return rules


def _result(finding, severity_threshold: str) -> dict:
    physical_location: dict = {"artifactLocation": {"uri": _template_uri(finding.template_name)}}
    # SARIF requires region.startLine >= 1; omit the region rather than emit an invalid 0.
    if finding.source_line and finding.source_line >= 1:
        physical_location["region"] = {"startLine": finding.source_line}

    result: dict = {"ruleId": finding.rule_id}
    idx = _RULE_INDEX.get(finding.rule_id)
    if idx is not None:
        result["ruleIndex"] = idx
    result.update({
        "level": _level(finding.severity),
        "message": {"text": f"{finding.sink_kind}: {finding.evidence}"},
        "locations": [{"physicalLocation": physical_location}],
        "properties": {
            "reachable": finding.reachable,
            "confirmed": finding.confirmed,
            "sinkKind": finding.sink_kind,
            "cwe": cwe_for(finding.rule_id),
            "astSpan": finding.ast_span,
            "gating": gates_ci(finding, severity_threshold),
        },
    })
    return result


def render_sarif(report: Report) -> str:
    """Render a :class:`Report` as a SARIF 2.1.0 document (trailing newline included)."""
    threshold = report.summary.severity_threshold
    doc = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [{
            # informationUri is intentionally omitted -- GlyphHound has no published
            # project URL yet, and inventing one would be a (small) overclaim.
            "tool": {"driver": {
                "name": "GlyphHound",
                "version": __version__,
                "rules": _driver_rules(),
            }},
            "results": [_result(f, threshold) for f in report.findings],
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
