"""Stage 5 — Report data model + CI exit-code policy (ARCHITECTURE.md §5).

The reporter is a pure formatting layer: it consumes the ``Finding[]`` produced by
Stage 3 and never parses, renders, or executes a template (rendering is the dangerous
act reserved for the Phase-6 sandbox). :func:`make_report` computes the summary and the
exit code; the human / JSON / SARIF renderers (sibling modules) turn a :class:`Report`
into bytes.

**Exit-code policy.** A finding fails CI only when it is *reachable* (Phase-3 taint
proved a dangerous chain builds toward it) **and** its severity is at or above a
configurable threshold (default :data:`DEFAULT_SEVERITY_THRESHOLD` = ``high``).
Presence-only findings — a variable merely named ``system``, a generic ``|attr('foo')``
pivot — are still reported (annotate, never filter) but must not break a build, or we
would reintroduce the false positives reachability was built to remove. ``reachable is True`` (not truthy) keeps ``None`` ("not analyzed") from gating.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .. import __version__
from ..analyze.models import CRITICAL, HIGH, Finding, cwe_for

# Severity ranking for the gate. Higher = more severe. The catalog (analyze/models.py)
# has only CRITICAL and HIGH; an unknown severity ranks 0 (never gates on its own).
_SEVERITY_RANK: dict[str, int] = {HIGH: 1, CRITICAL: 2}

# Default CI gate: fail on reachable findings of severity >= HIGH. Chosen (not CRITICAL)
# because a *reachable* reflection/|attr pivot (the HIGH rules) is a genuine dodge worth
# failing on, and the real benign corpus yields zero reachable findings of any severity
# (measured 0/11) — so HIGH stays clean while being strict.
DEFAULT_SEVERITY_THRESHOLD = HIGH

# The Finding fields the JSON report serializes / round-trips.
_FINDING_FIELDS = (
    "rule_id", "severity", "sink_kind", "template_name", "source_line",
    "evidence", "ast_span", "reachable", "confirmed",
)


def _rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, 0)


def gates_ci(finding: Finding, severity_threshold: str) -> bool:
    """Whether ``finding`` drives a non-zero exit code under ``severity_threshold``."""
    return finding.reachable is True and _rank(finding.severity) >= _rank(severity_threshold)


def _finding_to_dict(f: Finding) -> dict:
    d = {k: getattr(f, k) for k in _FINDING_FIELDS}
    # CWE is a property of the rule (analyze/models.RULE_CATALOG), derived here rather than
    # stored on the Finding. It rides along in the JSON as an informational field; the
    # round-trip is lossless because _finding_from_dict ignores unknown keys and Finding has
    # no cwe attribute, so from_dict(to_dict(r)) == r still holds (Phase 12).
    d["cwe"] = cwe_for(f.rule_id)
    return d


def _finding_from_dict(d: dict) -> Finding:
    return Finding(**{k: d[k] for k in _FINDING_FIELDS if k in d})


@dataclass(frozen=True)
class ReportSummary:
    """Counts that explain a :class:`Report` at a glance (ARCHITECTURE.md §5)."""

    total: int
    critical: int
    high: int
    reachable: int
    gating: int
    severity_threshold: str

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "critical": self.critical,
            "high": self.high,
            "reachable": self.reachable,
            "gating": self.gating,
            "severity_threshold": self.severity_threshold,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ReportSummary":
        return cls(
            total=d["total"], critical=d["critical"], high=d["high"],
            reachable=d["reachable"], gating=d["gating"],
            severity_threshold=d["severity_threshold"],
        )


@dataclass(frozen=True)
class Report:
    """The output of Stage 5: ``{findings, summary, exit_code}`` (ARCHITECTURE.md §5)."""

    findings: tuple[Finding, ...]
    summary: ReportSummary
    exit_code: int

    def to_dict(self) -> dict:
        return {
            "tool": "glyphhound",
            "version": __version__,
            "exit_code": self.exit_code,
            "summary": self.summary.to_dict(),
            "findings": [_finding_to_dict(f) for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Report":
        return cls(
            findings=tuple(_finding_from_dict(fd) for fd in d["findings"]),
            summary=ReportSummary.from_dict(d["summary"]),
            exit_code=d["exit_code"],
        )


def make_report(findings: Iterable[Finding], *,
                severity_threshold: str = DEFAULT_SEVERITY_THRESHOLD) -> Report:
    """Build a :class:`Report` from ``Finding[]`` and apply the CI exit-code policy.

    Findings are kept in their given (deterministic, AST-walk) order — the reporter
    never re-sorts them — so the same ``Finding[]`` always yields byte-identical output.
    """
    findings = tuple(findings)
    gating = sum(1 for f in findings if gates_ci(f, severity_threshold))
    summary = ReportSummary(
        total=len(findings),
        critical=sum(1 for f in findings if f.severity == CRITICAL),
        high=sum(1 for f in findings if f.severity == HIGH),
        reachable=sum(1 for f in findings if f.reachable is True),
        gating=gating,
        severity_threshold=severity_threshold,
    )
    return Report(findings=findings, summary=summary, exit_code=1 if gating else 0)
