# Phase 8 — Head-to-head benchmark: GlyphHound vs ModelAudit

This is GlyphHound's single most important credibility artifact: a **reproducible**,
**measured** comparison against the incumbent, [Promptfoo
**ModelAudit**](https://www.promptfoo.dev/docs/model-audit/), on an obfuscated chat-template
payload set. It substantiates the project's one defensible claim and **nothing larger**
(the design docs, the project conventions).

ModelAudit is a capable scanner, not a strawman. To avoid under-powering it (Rule 3) this
benchmark runs it in its **strongest configuration** — `modelaudit==0.2.47` **with `jinja2`
and `gguf` installed**, which activates its optional *dynamic* `SandboxedEnvironment` render
test on top of its regex SSTI patterns and its static AST probe. (A plain `pip install
modelaudit` installs neither, leaving it regex-only and even weaker — so this comparison is
conservative.)

## The measured result

Each row is one MARKER-only payload wrapped into a minimal GGUF and scanned by **both** tools
(same artifact). `FLAG` = flagged; `miss` = not flagged.

| # | Payload | Obfuscation | GlyphHound | ModelAudit | ModelAudit mechanism |
|---|---------|-------------|:----------:|:----------:|----------------------|
| 1 | plain dunder chain (**control**) | none | FLAG | FLAG | regex (literal tokens) |
| 2 | `\|attr()` filter, concat dunders | `\|attr('__cl'~'ass__')` | FLAG | FLAG | regex (`\|attr(` token) |
| 3 | `getattr()` reflection, concat dunder | `getattr(x,'__in'+'it__')` | FLAG | FLAG | regex (`getattr(` token) |
| 4 | concat chain **gated in message loop** | concat, off render path | FLAG | **miss** | — |
| 5 | concat chain **gated behind role check** | concat, off render path | FLAG | **miss** | — |
| 6 | `~`-concat chain **gated behind `if messages`** | `~`-concat, off render path | FLAG | **miss** | — |
| 7 | `str.format()`-built dunders, gated | `'{}{}'.format('__in','it__')` | FLAG | FLAG | regex (`obfuscation` pattern flags the `.format` construction) |
| 8 | slice-built dunders, gated | `('__in'+'it__#')[:8]` | FLAG | **miss** | — |
| 9 | `\|join`-built dunders, gated | `['__in','it__']\|join` | FLAG | **miss** | — |
| 10 | `\|replace`-built dunders, gated | `'__QQQQ__'\|replace('QQQQ','init')` | FLAG | **miss** | — |
| 11 | benign chat template (**control**) | none | ok-clean | ok-clean | clean |
| 12 | benign string concat (**control**) | `'rol'+'e'`→`'role'` | ok-clean | ok-clean | clean |
| 13 | benign gated template (**control**) | none (guard, no sink) | ok-clean | ok-clean | clean |

**Headline (the design docs — obfuscation catch rate, over the 9 obfuscated payloads, rows 2–10):**

| | GlyphHound | ModelAudit (strongest config) |
|---|:---:|:---:|
| Obfuscated malicious caught | **9/9 (100%)** | 3/9 (33%) |
| All malicious caught (incl. plain control) | 10/10 (100%) | 4/10 (40%) |
| False positives on benign controls | 0/3 | 0/3 |

Phase 10 widened the obfuscated set from 5 to 9 by adding the `str.format` / slice / `|join` /
`|replace` constant-builder families. GlyphHound catches all 9; the GlyphHound-only edge grew
from **3** payloads (the concat-gated chains) to **6** (those plus slice / `|join` / `|replace`),
dropping ModelAudit's obfuscated catch rate from 40% to 33%.

**Re-confirmed at Phase 15 (2026-06-22)** against the current analyzer — the catalog has since
grown to **23 dunders / 18 code-exec names** (Phase 12) and gained constant-propagation
(Phase 13) and the HF-canonical-source scan (Phase 14). `verify_phase8.py` re-measures the
table live: every verdict above is unchanged (the benchmark payloads don't exercise the
newly-added names, so the rates hold), and the analyzer was not tuned to the benchmark
(`git diff src/` carries no Phase-15 change — `src/` is byte-identical to the tagged
`phase-14`). The expanded catalog is instead audited for false positives on a *wider* benign
sample — see the Phase-15 wider-FP audit (`study/wider_fp_audit.json`).

## What this shows, honestly

**Where ModelAudit also catches (rows 1–3, 7), reported honestly (Rule 3):** the **plain** chain
(row 1) and the `|attr`/`getattr` forms (rows 2–3) keep a literal trigger token (`|attr(`,
`getattr(`) that ModelAudit's **regex** matches even though the dunder *names* are concatenated;
and the **`str.format` family** (row 7) trips a *separate* ModelAudit heuristic — its generic
`obfuscation` `pattern_type` flags the `.format()` construction itself (it ships such a rule for
`str.format`, but none for slice / `|join` / `|replace`). That only tells ModelAudit "this looks
obfuscated"; GlyphHound resolves the construction to the actual `__init__…__import__` sink and
reports the precise rule + line. GlyphHound matches every one of these. ModelAudit is not a
strawman.

**The edge — what GlyphHound catches that even the strongest ModelAudit misses (rows 4–6, 8–10):**
the three string-concat chains placed **off ModelAudit's render path**, plus the **slice**,
**`|join`**, and **`|replace`** constant-builder families added in Phase 10. Two independent
limitations of ModelAudit combine here, and GlyphHound's static analysis is subject to neither:

1. **No de-obfuscation.** ModelAudit's regex patterns and its *static* AST probe both inspect
   only **literal/`Const`** identifiers (it walks `Getitem` keys but checks
   `isinstance(arg, Const)` — verified in its source), so a name assembled at run time by `+`/`~`
   concatenation, a slice (`('__in'+'it__#')[:8]`), `|join` (`['__in','it__']|join`), or `|replace`
   is invisible to both. GlyphHound's Stage-2 de-obfuscator folds each of these constant builders
   → the literal identifier **before** the walk (it does not, however, see a *whole* token left in
   the text — which is why the literal `str.format` argument case is one ModelAudit's regex still
   catches).
2. **Single-path dynamic render.** ModelAudit's optional sandbox test renders **one** path with
   `messages=[]` and a 0.5 s budget. A payload that fires only with real message data — inside
   the message loop (rows 4, 8–10), for a specific role (row 5), or when any message is present
   (row 6) — is **never executed**, so the render reports "safe". This is the *normal* operating
   condition of a chat template, so gating the payload there is realistic, not contrived.
   GlyphHound's static **reachability** flags the dunder chain wherever it sits in the AST,
   independent of any single render.

Each limitation alone is survivable for ModelAudit (a *literal* gated chain is caught by the
regex on the raw text; a *top-level* concat chain is caught by the render). It is the
**combination** — a non-literal construction (concat / slice / `|join` / `|replace`) **and**
off-render-path placement — that defeats it, and that GlyphHound catches every time.

**Measured caveat — ModelAudit's dynamic render is non-deterministic.** A *top-level* concat
chain (no gating) is caught **only** by ModelAudit's dynamic render, whose multiprocessing
worker is timing-dependent: across repeated runs we measured its verdict on the same artifact
flip between `FLAG` and `miss` (the render worker sometimes does not fire within its budget, and
the static fallback is concat-blind). A scanner's verdict that changes between identical runs is
itself a contrast with GlyphHound's deterministic static analysis (the project conventions). Because
the asserted table must be byte-identical across runs, such render-only payloads are
deliberately **excluded** from it; every payload above has a deterministic verdict for both
tools.

## How to reproduce

ModelAudit lives in a **separate** virtualenv so its ~80-package dependency tree never perturbs
GlyphHound's pinned/locked environment (determinism, the project conventions):

```bash
# one-time setup of the incumbent in its STRONGEST config (pinned)
python -m venv .venv-modelaudit
.venv-modelaudit/Scripts/python -m pip install "modelaudit==0.2.47" "jinja2==3.1.6" "gguf==0.19.0"

# run the benchmark (prints the table above) and the phase gate
.venv/Scripts/python scripts/run_benchmark.py
.venv/Scripts/python scripts/verify_phase8.py     # asserts the claim + determinism; exit 0 = PASS
```

`scripts/run_benchmark.py` exits non-zero **only** on a harness failure (ModelAudit missing, a
scan error). The comparison itself is informational — the table is the deliverable, reported
whichever way it comes out (Rule 3). The `.gguf` artifacts are built at run time from the
committed `payloads/*.jinja` and deleted afterwards (they are gitignored; never committed).

## Methodology (what makes this fair and deterministic)

- **Same artifact.** Each `payloads/*.jinja` is wrapped into a minimal GGUF via
  `tests/synthetic.build_gguf`. GlyphHound reads the template back out of the `.gguf`
  (`read_gguf_template` → `analyze_raw`); ModelAudit scans the same `.gguf`. Byte-identical input.
- **GlyphHound "catch" =** the scan report gates CI: ≥1 **reachable** finding at severity ≥ high
  (`make_report(...).exit_code != 0`) — exactly the exit code a user's `glyphhound scan` returns.
- **ModelAudit "catch" =** its own chat-template SSTI detector fires: a `jinja2_template_check`
  issue carrying a `details.pattern_type` (a regex match **or** a `sandbox_violation` from the
  dynamic render). We key on that specific detector (not merely a non-zero exit) so the
  comparison is like-for-like and never credits ModelAudit for an unrelated scanner.
- **Strongest-config / fair invocation (not crippled).** Run via ModelAudit's real packaged CLI
  (`modelaudit scan <file> --format json --no-cache`) with `jinja2`+`gguf` present. The **plain
  control (row 1)** proves basic invocation; the **top-level concat (row 2)**, caught *only* by
  the dynamic render, proves the sandbox test is actually active. `verify_phase8.py` asserts both.
- **Comment-contamination guard.** ModelAudit is a *text* scanner, so a literal sink token in an
  explanatory **comment** would be matched as if it were the payload — falsely crediting it with
  a catch it never earned on the obfuscated code. (We observed exactly this in development.) The
  payload files keep their comments **free of literal sink tokens**; `tests/test_benchmark.py`
  enforces it.
- **Determinism (Rule 7).** Payloads run in manifest order; the table has no timestamps, temp
  paths, or other run-varying data, so the same inputs + pinned versions yield a byte-identical
  table. `verify_phase8.py` checks two independent runs match.
- **MARKER only (Rule 4) / no weights (Rule 6).** Every malicious payload simulates exploitation
  with the harmless sentinel `GLYPHHOUND_BENCH_MARKER`; the synthetic GGUFs carry no tensor data.
  GlyphHound never renders (it parses + walks the AST). ModelAudit's own sandbox render (when it
  runs) is its containment, inside a Jinja `SandboxedEnvironment` that blocks the access — no
  payload ever executes.

`payloads/MANIFEST.json` is the source of truth: per payload it records the label, technique,
CVE provenance, the ModelAudit detection mechanism, and the **measured-then-locked** expected
verdict for each tool (pinned to the recorded versions). `verify_phase8.py` re-measures live and
asserts the live results still match the locked values — so version drift, a config regression
(e.g. `jinja2` missing), or comment contamination is caught, not hidden.

## Provenance

The payloads are MARKER-only simulations of public Jinja2 SSTI / sandbox-escape gadgets of the
**CVE-2024-34359** class (llama-cpp-python load-time RCE,
[advisory GHSA-56xg-wfcc-g829](https://github.com/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829)).
No working exploit and no poisoned model is committed.
