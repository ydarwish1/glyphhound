# GlyphHound public yardstick — obfuscation benchmark + labeled corpus

**A reproducible, MARKER-only, redistributable evaluation set for chat-template scanners.**
*Status: prepared for release. Not yet published.*

If you build or use a model-file / chat-template scanner, this is a dataset you can run your
tool against to measure two things that matter for load-time RCE (CVE-2024-34359 /
CVE-2026-5760 class):

1. **Obfuscation catch rate** — does it flag code-exec-capable templates when the dangerous
   identifiers are *hidden* (string concat, `str.format`, slice, `|join`, `|replace`, case-fold,
   reverse-slice) and *gated* off a naive render path?
2. **False-positive rate** — does it stay quiet on real, benign chat templates?

## What's in the set

| Part | Location | Labels | Contents |
|------|----------|--------|----------|
| **Obfuscation benchmark** | `benchmark/payloads/` | `MANIFEST.json` (`malicious` true/false per file) | 10 MARKER-only malicious payloads (1 plain control + 9 obfuscated CVE-2024-34359-class gadgets) + 3 benign controls |
| **Labeled-benign corpus** | `corpus/templates/` | `corpus/PROVENANCE.json` (each pinned by HF commit SHA, deduped by sha256) | 120 distinct real Hugging Face chat templates, all benign |

Every malicious payload simulates exploitation with the harmless sentinel
`GLYPHHOUND_BENCH_MARKER` — **no working exploit and no poisoned model is included**, so the set
is safe to commit and redistribute (the project conventions). Scanning it never loads weights and, for
GlyphHound, never renders a template (Rule 6).

## Run it yourself

### A. Score GlyphHound (one command, no incumbent needed)

```bash
.venv/Scripts/python scripts/score_yardstick.py
```

Runs GlyphHound's real CI gate over the labeled payloads + the 120-template corpus and prints a
scorecard. Current measured result (deterministic):

```
malicious payloads caught : 10/10 (100%)
benign controls + corpus  : 123/123 clean (0 false positives)
RESULT: PASS -- all malicious caught, 0 false positives
```

### B. Reproduce the head-to-head vs ModelAudit

See [`README.md`](README.md) for the full methodology and the measured table (**GlyphHound 9/9
vs ModelAudit 3/9** on the obfuscated set, 0/3 benign FP both). Briefly:

```bash
python -m venv .venv-modelaudit
.venv-modelaudit/Scripts/python -m pip install "modelaudit==0.2.47" "jinja2==3.1.6" "gguf==0.19.0"
.venv/Scripts/python scripts/run_benchmark.py     # prints the comparison table
.venv/Scripts/python scripts/verify_phase8.py     # asserts the claim + determinism
```

### C. Score your own scanner

The dataset is tool-agnostic. Point your scanner at the two directories and score against the
labels — no GlyphHound internals required:

- For each file in `benchmark/payloads/*.jinja`, your scanner **should flag** it iff
  `MANIFEST.json` marks it `"malicious": true`.
- For each file in `corpus/templates/*.jinja`, your scanner **should stay clean** (any flag is a
  false positive).
- Report: *malicious caught / total* (catch rate) and *benign flagged / total* (FP rate).

`scripts/score_yardstick.py` is a ~90-line worked example of exactly this loop — copy its
structure and swap in your scanner's verdict function.

## Honest positioning (the project conventions)

This is an **open engineering yardstick**, not a leaderboard or a research claim. ModelAudit is a
capable incumbent, benchmarked here in its strongest configuration; the comparison is fully
reproducible and reported whichever way it comes out. GlyphHound's defensible edge is narrow and
specific: **AST + taint + de-obfuscation catches obfuscated load-time-RCE templates that
string-matching misses**, at a measured-low false-positive rate — nothing larger.
