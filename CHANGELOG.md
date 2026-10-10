# Build history

GlyphHound was built in small, verified stages. Each stage was finished, verified
with real output (a flagged fixture, a schema-valid file, a measured rate), and only then was
the next one started. Most have a `scripts/verify_phase*.py` that re-proves them; the rest are
covered by the pytest suite. The stages are listed in order below.

## Stages

**0 -- Acquire.** Extract the chat template from a GGUF file (HTTP range request over the
metadata header) and a local Ollama blob, without reading the weights. Verified on real models;
bytes fetched were far smaller than the file size in every case.

**1 -- Parse.** Template string to a Jinja2 AST, with a deterministic AST dump used as a golden
value. Jinja2 is pinned (`jinja2==3.1.6`) so the AST API cannot drift.

**2 -- Sinks.** Walk the AST and flag known code-execution patterns by inspecting *identifiers*
(never string literal contents), so a role string like `"system"` is ignored while `os.system`
is flagged. Four rules: dunder access, code-exec name, `|attr` pivot, `getattr`/`setattr`
reflection. 0 false positives on the benign fixtures.

**3 -- Taint / reachability.** Flag a sink only when a dangerous expression actually builds
toward it, not when a template merely names a variable. Findings are annotated, not dropped.

**4 -- De-obfuscate.** Fold constant string concatenation and resolve `getattr`/`setattr` with a
constant name before analysis, so an obfuscated identifier is normalized to the form the walk
already matches.

**5 -- Report.** Human, JSON, and SARIF 2.1.0 output (validated against the vendored OASIS
schema), with a configurable severity threshold that drives the CI exit code.

**6 -- Sandbox confirmer (gated, optional).** Render a suspect template in a locked-down child
subprocess to confirm code execution is reachable. Containment is proven by a test that blocks a
real filesystem write outside scratch and a real network connect. Off by default.

**7 -- Benign corpus + false-positive rate.** A vendored corpus of 120 distinct real Hugging
Face chat templates; measured false-positive rate **0.00% (0/120)**.

**8 -- Head-to-head benchmark.** Compare detection against Promptfoo's ModelAudit on the same
artifacts. On the obfuscated set, GlyphHound caught the ones ModelAudit's string matching missed
(both 0 false positives on benign controls).

**9 -- End-to-end CLI scan.** Wire the acquirer into `glyphhound scan <ref>` for local files,
`.gguf` URLs, Hugging Face repos, and Ollama models; scans every template a model carries
(default and named) and tags each finding by template name.

**10 -- Obfuscation coverage.** Fold `str.format` / slice / `|join` / `|replace` constant
builders and resolve keyword-argument names. The measured benchmark lead widened to **9/9 vs
3/9** on the obfuscated set; corpus false positives still 0/120.

**11 -- Parser completeness + documentation accuracy.** Support Hugging Face's
`{% generation %}` tag; correct the docs to match the code exactly.

**12 -- Catalog expansion (CWE-mapped).** Expand the sink catalog from public SSTI research and
attach a CWE id to each rule (surfaced in JSON and SARIF). Re-measured 0/120, presence and
gating.

**13 -- Constant propagation.** Substitute `{% set %}` variables bound to a constant string
before folding, so a dangerous identifier held in a variable is exposed. Conservative;
re-measured 0/120.

**14 -- Scan the canonical source.** Read a repo's canonical chat template directly from
`tokenizer_config.json` / `chat_template.jinja` / safetensors metadata, covering transformers
models that ship no GGUF -- a small metadata read, no weights.

**15 -- Detection hardening.** A wider false-positive audit over 241 additional distinct real
templates surfaced and fixed one real false-positive class (a code-exec name used as a benign
dictionary key); re-measured **0/241**; corpus still 0/120.

**16 -- Close confirmed obfuscation bypasses.** Generalize the de-obfuscator to fold pure
string transforms (case-changing filters, reverse/negative slices). Corpus 0/120, wider 0/241,
benchmark unchanged.

**17 -- Measurement tooling + distribution.** A rate-limit-aware, resumable, parse-only
prevalence-scan script (summaries only, no weights); a ModelAudit-free benchmark scorer; a
`glyphhound` console entry point; and a GitHub Action wrapper that emits SARIF to code scanning.

**18 -- Linux sandbox hardening.** Add Linux kernel/OS backstops to the confirmer's child under
the existing cross-platform audit hook: a seccomp syscall filter, resource limits, and
best-effort privilege-drop, plus OS-enforced symlink/hardlink resolution in the out-of-scratch
write check. A no-op off Linux, so the Windows path is unchanged.

**19 -- Close hidden string-building bypasses.** Extend the de-obfuscator to fold string
repetition (`*`), printf (`%` / `|format`), and the `|string` cast -- forms a string matcher also
misses -- each bounded so a pathological repetition or width cannot exhaust memory at analysis
time. Corpus 0/120, wider 0/241, benchmark unchanged.

**20 -- Polish.** A deep-nest guard (a pathologically nested template is rejected with a clean
error instead of crashing the analyzer), `--file auto` (pick the smallest `.gguf` quant in a
repo), and gated/private-repo support via `HF_TOKEN` with clear errors.

**Hardening (after 20).** Scan failures that used to traceback now return exit 2 (network
errors, missing/unreadable files, directories, bad Ollama JSON, hostile nested GGUF
arrays). `HF_TOKEN` is sent only to Hugging Face hosts and is not forwarded on redirects.
`map` / `selectattr` / `rejectattr` attribute paths are analyzed the same way as `|attr`.
`{% set %}` alias chains propagate. `getattr`'s default argument keeps its subtree.

**Several targets in one scan.** `glyphhound scan A B C` scans each target and reports each
under its own heading; the exit code is 1 if any target gates CI, else 2 if any could not be
scanned, else 0. JSON prints a list with one report per target, and SARIF one run listing every
target as an artifact (a line region only for raw template files). One target is unchanged in
every format. The human report and stderr show non-printable characters in template names,
evidence and error messages as escapes, and JSON and SARIF write them as `\u` escapes. A stdin
template that is not UTF-8 now exits 2 instead of crashing, and a file name that is not UTF-8
is percent-encoded byte by byte in SARIF.

**Scan a local directory.** `glyphhound scan DIR` finds every `*.jinja`, `chat_template.jinja`,
`tokenizer_config.json` and `*.gguf` file under DIR and scans each as a target of its own, as
several targets are. A `tokenizer_config.json` is parsed as a config and every template in its
`chat_template` is scanned. Symlinks out of DIR are not followed but reported. A match that
cannot be read or parsed, or a subdirectory that cannot be listed, is reported and exits 2, and
a directory with no matching file exits 2 saying so; so does a `tokenizer_config.json` with no
template and no `chat_template.jinja` beside it. A template file over 32 MiB now exits 2 instead
of being read whole, and two spellings of one local file are scanned once. A Hub
`tokenizer_config.json` that is not UTF-8 or nests too deeply to parse now exits 2 cleanly too.

**Write the report to a file.** `--output FILE` writes the `--format` report to FILE and still
prints the human report to stdout, so one CI run can upload SARIF and show a readable log. The
exit code is unchanged. FILE that is an existing directory or one of the scanned files exits 2
before anything is scanned; FILE that cannot be written is reported and exits 2 unless a
finding gates (1).

## Standing properties

These held across the phases above and are re-checked on any change:

- **False positives:** 0/120 on the corpus and 0/241 on the wider audit.
- **No weights** are ever read; the acquirer fetches only the metadata via range requests, kept well below the file size by a hard read cap.
- **Deterministic:** dependencies pinned, no randomness in detection, reproducible from a clean
  checkout.
- **MARKER fixtures only:** no working exploit or poisoned model is committed.
