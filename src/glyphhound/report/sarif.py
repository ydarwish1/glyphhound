"""Stage 5 -- SARIF 2.1.0 renderer (ARCHITECTURE.md section 3 Stage 5).

Each :class:`~.models.Report` finding becomes a SARIF ``result``: ``ruleId`` = the rule
id, ``level`` mapped from severity (critical -> error, high -> warning), a
``physicalLocation`` whose ``artifactLocation.uri`` names the chat template the sink was
found in and whose ``region.startLine`` is the source line, and a ``message`` carrying
the evidence. ``runs[].tool.driver.rules`` is built from the analyzer's ``RULE_CATALOG``.
A scan of several targets is still one run: ``artifacts`` lists every target, each result's
``artifactLocation`` points at its target (the template key moves to a logical location),
and a target that could not be scanned is an error notification on the invocation.

The output validates against the official OASIS SARIF 2.1.0 schema (vendored at
``schemas/sarif-2.1.0.json`` and checked in the offline test/verify layer). This module
emits with the stdlib ``json`` only -- it never imports ``jsonschema`` (a dev-only dep) --
so the shipped tool stays jinja2-only. It is deterministic: no timestamps, rules in sorted
id order, results in the findings' given order, fixed key order. It formats ``Finding[]``
only and never renders a template.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from .. import __version__
from ..analyze.models import CRITICAL, HIGH, RULE_CATALOG, cwe_for
from .json_report import dump_json
from .models import Report, TargetResult, gates_ci

# An informational pointer to the schema the output conforms to (a constant, so it does
# not affect determinism). The vendored copy under schemas/ is what validation uses.
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Severity -> SARIF level. SARIF levels are none/note/warning/error.
SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {CRITICAL: "error", HIGH: "warning"}

# Stable rule order, independent of dict construction order (determinism).
_RULE_IDS = sorted(RULE_CATALOG)
_RULE_INDEX = {rid: i for i, rid in enumerate(_RULE_IDS)}

# The RFC 3986 reserved characters plus "%" (an already-encoded URL stays as given): an
# http(s) target keeps these and percent-encodes everything else that is not unreserved.
_URI_SAFE = ":/?#[]@!$&'()*+,;=%"


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


def _with_region(physical_location: dict, finding) -> dict:
    # SARIF requires region.startLine >= 1; omit the region rather than emit an invalid 0.
    if finding.source_line and finding.source_line >= 1:
        physical_location["region"] = {"startLine": finding.source_line}
    return physical_location


def _template_location(finding) -> dict:
    """One target: the artifact is the metadata key the template came from."""
    return {"physicalLocation": _with_region(
        {"artifactLocation": {"uri": _template_uri(finding.template_name)}}, finding)}


def _target_location(finding, artifact_location: dict, template_file: bool) -> dict:
    """Several targets: the artifact is the scanned target, and the metadata key the
    template came from becomes the location's logical location. The template line is a
    line of the artifact only when the target is the raw template file, so only then is it
    the region; it always rides along as the location's ``templateLine`` property."""
    physical_location: dict = {"artifactLocation": dict(artifact_location)}
    if template_file:
        _with_region(physical_location, finding)
    location: dict = {
        "physicalLocation": physical_location,
        "logicalLocations": [{"fullyQualifiedName": _template_uri(finding.template_name)}],
    }
    if finding.source_line and finding.source_line >= 1:
        location["properties"] = {"templateLine": finding.source_line}
    return location


def _result(finding, severity_threshold: str, location: dict) -> dict:
    result: dict = {"ruleId": finding.rule_id}
    idx = _RULE_INDEX.get(finding.rule_id)
    if idx is not None:
        result["ruleIndex"] = idx
    result.update({
        "level": _level(finding.severity),
        "message": {"text": f"{finding.sink_kind}: {finding.evidence}"},
        "locations": [location],
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


def _document(run: dict) -> str:
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
            **run,
        }],
    }
    return dump_json(doc)


def render_sarif(report: Report) -> str:
    """Render a :class:`Report` as a SARIF 2.1.0 document (trailing newline included)."""
    threshold = report.summary.severity_threshold
    return _document({
        "results": [_result(f, threshold, _template_location(f)) for f in report.findings],
    })


def _target_uri(target: str) -> str:
    """A target reference as a SARIF URI reference.

    An http(s) URL keeps its reserved characters and existing escapes; an absolute local
    path becomes a ``file:`` URI; anything else (a relative path, a repo id, an Ollama name,
    ``-``) is a relative reference with every character but ``/`` percent-encoded, so a
    literal ``%``, ``:`` or ``\\`` in it cannot read as an escape, a scheme or a new file.
    """
    if target.startswith(("http://", "https://")):
        return quote(target, safe=_URI_SAFE)
    path = Path(target)
    if path.is_absolute():
        return path.as_uri()
    return quote(path.as_posix(), safe="/")


def render_sarif_targets(results: list[TargetResult]) -> str:
    """Render a multi-target scan as one SARIF 2.1.0 run listing every target in
    ``artifacts``. Each result points at its target's artifact; a target that could not be
    scanned becomes an error notification, and the invocation is then unsuccessful."""
    artifacts: list[dict] = []
    index_by_uri: dict[str, int] = {}
    sarif_results: list[dict] = []
    notifications: list[dict] = []
    for target in results:
        uri = _target_uri(target.target)
        if uri not in index_by_uri:  # SARIF artifacts must be unique
            index_by_uri[uri] = len(artifacts)
            artifacts.append({"location": {"uri": uri}})
        artifact_location = {"uri": uri, "index": index_by_uri[uri]}
        if target.report is None:
            notifications.append({
                "level": "error",
                "message": {"text": target.error or ""},
                "locations": [{"physicalLocation": {"artifactLocation": artifact_location}}],
            })
            continue
        threshold = target.report.summary.severity_threshold
        for f in target.report.findings:
            location = _target_location(f, artifact_location, target.template_file)
            sarif_results.append(_result(f, threshold, location))
    return _document({
        "artifacts": artifacts,
        "invocations": [{
            "executionSuccessful": not notifications,
            "toolExecutionNotifications": notifications,
        }],
        "results": sarif_results,
    })
