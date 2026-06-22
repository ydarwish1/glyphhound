"""Offline tests for the Phase-7 benign FP corpus + measured false-positive rate.

The vendored corpus (``corpus/templates/*.jinja`` + ``corpus/PROVENANCE.json``) is the
>=100-template, SHA-pinned, deduped set the analyzer's false-positive rate is measured on.
These tests run fully offline: they only *parse* each real template
(``analyze_template`` — parse -> de-obfuscate -> walk), never *render* one, so reading the
corpus cannot execute anything, and they load no weights (the build did the range-fetch).

A template is a FALSE POSITIVE iff its report GATES CI (``make_report(...).exit_code != 0``,
i.e. a finding with ``reachable is True`` at severity >= threshold) — the same gate the CLI
uses. The corpus is benign by construction, so the measured gating FP rate is expected to be
0%; this test locks that in and would catch a regression that re-introduces false positives.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from glyphhound.analyze import analyze_template
from glyphhound.report import make_report

ROOT = os.path.dirname(os.path.dirname(__file__))
CORPUS_DIR = os.path.join(ROOT, "corpus")
TEMPLATES_DIR = os.path.join(CORPUS_DIR, "templates")
PROVENANCE_PATH = os.path.join(CORPUS_DIR, "PROVENANCE.json")

MIN_REQUIRED = 100
NO_WEIGHTS_THRESHOLD = 0.10  # matches RawTemplate.assert_no_weights_loaded default


def _provenance() -> list[dict]:
    if not os.path.exists(PROVENANCE_PATH):
        return []
    with open(PROVENANCE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_corpus_has_at_least_100_templates():
    assert len(_provenance()) >= MIN_REQUIRED


def test_corpus_templates_are_all_distinct():
    prov = _provenance()
    digests = [p["template_sha256"] for p in prov]
    assert len(set(digests)) == len(digests) >= MIN_REQUIRED


@pytest.mark.parametrize("entry", _provenance(), ids=lambda e: e["model"])
def test_vendored_bytes_match_the_pin(entry):
    # Reproducibility: the committed file's bytes hash to the recorded pin.
    path = os.path.join(TEMPLATES_DIR, entry["file"])
    digest = hashlib.sha256(_read(path).encode("utf-8")).hexdigest()
    assert digest == entry["template_sha256"]


@pytest.mark.parametrize("entry", _provenance(), ids=lambda e: e["model"])
def test_no_weights_were_loaded(entry):
    # Only the metadata header was read, never the weights.
    assert entry["bytes_fetched"] < entry["total_size"]
    assert entry["bytes_fetched"] / entry["total_size"] < NO_WEIGHTS_THRESHOLD


@pytest.mark.parametrize("entry", _provenance(), ids=lambda e: e["model"])
def test_real_template_is_not_a_false_positive(entry):
    # The benign-corpus gate: a benign real template must NOT gate CI (no reachable sink).
    path = os.path.join(TEMPLATES_DIR, entry["file"])
    report = make_report(analyze_template(_read(path)))
    gating = [f for f in report.findings if f.reachable is True]
    assert report.exit_code == 0, f"{entry['model']} wrongly gated CI: {gating}"


def test_measured_gating_fp_rate_is_zero():
    prov = _provenance()
    assert len(prov) >= MIN_REQUIRED
    fp = 0
    for p in prov:
        report = make_report(analyze_template(_read(os.path.join(TEMPLATES_DIR, p["file"]))))
        if report.exit_code != 0:
            fp += 1
    assert fp == 0, f"{fp}/{len(prov)} real templates were false positives"
