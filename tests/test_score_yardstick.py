"""Offline tests for Phase 17 step 5 -- the public-yardstick scorer (scripts/score_yardstick.py).

Confirms the gate helper, and that GlyphHound scores the SHIPPED labeled benchmark payloads
correctly (every malicious caught, 0 benign false positives). The corpus scorer's logic is
checked on a tiny synthetic dir to stay fast (the real 120-template measurement is verify_phase7).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import score_yardstick  # noqa: E402

MARKER = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
BENIGN = "{% for m in messages %}{{ m.role }}: {{ m.content }}{% endfor %}"


def test_gates_helper():
    assert score_yardstick.gates(MARKER) is True
    assert score_yardstick.gates(BENIGN) is False


def test_shipped_payloads_all_scored_correctly():
    s = score_yardstick.score_payloads(score_yardstick.MANIFEST, score_yardstick.PAYLOADS_DIR)
    assert s["malicious_total"] >= 9
    assert s["malicious_caught"] == s["malicious_total"]      # GlyphHound catches every one
    assert s["benign_false_positives"] == 0                   # and FPs none of the controls
    assert all(r["correct"] for r in s["rows"])


def test_score_corpus_counts_false_positives(tmp_path):
    (tmp_path / "benign.jinja").write_text(BENIGN, encoding="utf-8")
    (tmp_path / "evil.jinja").write_text(MARKER, encoding="utf-8")
    s = score_yardstick.score_corpus(str(tmp_path))
    assert s["total"] == 2
    assert s["false_positives"] == 1
    assert s["fp_files"] == ["evil.jinja"]
