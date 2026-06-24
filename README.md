# GlyphHound

[![CI](https://github.com/ydarwish1/glyphhound/actions/workflows/ci.yml/badge.svg)](https://github.com/ydarwish1/glyphhound/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/glyphhound)](https://pypi.org/project/glyphhound/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

A deterministic scanner that detects code-executing chat templates inside model files
(GGUF / Ollama / Hugging Face), before you load the model.

## The problem

When you download an open-weights LLM, the file ships with a chat template: a small
[Jinja2](https://jinja.palletsprojects.com/) program that formats your messages before the
model sees them. Several runtimes render that template with an unsandboxed Jinja engine, so a
malicious template can run code on your machine the moment the model is loaded, before you type
anything. This is a real, patched bug class:

- [CVE-2024-34359](https://nvd.nist.gov/vuln/detail/CVE-2024-34359) (llama-cpp-python)
- [CVE-2026-5760](https://nvd.nist.gov/vuln/detail/CVE-2026-5760) (SGLang, CVSS 9.8 - RCE via an unsandboxed `jinja2.Environment()` rendering a malicious `tokenizer.chat_template`)

## What GlyphHound does

It reads the chat template out of the model file without downloading the multi-gigabyte
weights, parses it into a syntax tree, traces whether it can reach a code-execution operation,
optionally confirms it in a locked-down sandbox, and reports the result with a CI exit code.

It is a program-analysis tool, not a model: the same input always produces the same finding,
there are no API calls or LLM calls at scan time, and it runs offline.

Pipeline (five stages):

1. Acquire: extract the template via an HTTP range request over the GGUF metadata header, the
   local Ollama blob, or a Hugging Face repo's `tokenizer_config.json` / `chat_template.jinja` /
   safetensors metadata. A hard cap on the bytes read, plus a refusal of any server that ignores
   the range request, keeps the fetch far smaller than the file and never touches the weights.
2. Parse: to a Jinja2 AST (no rendering).
3. De-obfuscate: fold obfuscation back to the identifier it hides, including string
   concatenation, `str.format` / `%` / `|format` printf, slices, `|join` / `|replace`,
   case-changing filters, string repetition, `{% set %}` constant propagation, and
   `getattr` / `|attr` reflection.
4. Analyze: walk the AST for code-execution sinks (dunder chains into the Python object model,
   code-exec names, reflection) and flag one only when a dangerous expression actually reaches
   it (taint / reachability), not when a benign template merely names a variable.
5. Report: human, JSON, and SARIF 2.1.0, with a configurable severity threshold that drives the
   exit code. An optional, off-by-default sandbox stage renders the template in a contained
   subprocess to confirm a finding.

## Example

These examples scan template files from this repository (clone it first), or substitute your own
template file, or scan a model by id with `glyphhound scan owner/name`.

Scanning a malicious template (an obfuscated `__import__` to `os.system` chain). It gates CI
with a non-zero exit code:

```text
$ glyphhound scan fixtures/malicious/cve_2024_34359_marker.jinja
GlyphHound scan report
======================
threshold: fail CI on reachable findings of severity >= high
exit code: 1

findings (5):
  [GH-S002] CRITICAL reachable     tokenizer.chat_template:17  [GATES CI]
      code-exec-name: .system
      reason: reference to a code-execution or dangerous-capability name (eval/exec/compile/os/subprocess/importlib/pickle/open/...)
  [GH-S001] CRITICAL reachable     tokenizer.chat_template:17  [GATES CI]
      dunder-attribute: .__import__
      reason: attribute/subscript/|attr access to a Python dunder used for sandbox escape
  ... (3 more reachable dunder findings: .__builtins__, .__globals__, .__init__)

summary: 5 finding(s), 5 reachable; critical=5 high=0; 5 gating -> exit 1
```

Scanning a real, benign template. It stays quiet and passes:

```text
$ glyphhound scan fixtures/benign/Qwen__Qwen2.5-0.5B-Instruct-GGUF.jinja
GlyphHound scan report
======================
threshold: fail CI on reachable findings of severity >= high
exit code: 0

findings: 0 (nothing flagged at or above the detection threshold)

summary: 0 finding(s), 0 reachable; critical=0 high=0; 0 gating -> exit 0
```

## How it compares

Promptfoo's [ModelAudit](https://www.promptfoo.dev/docs/model-audit/) already ships a
pip-installable, SARIF-emitting chat-template scanner based on string/regex matching.
GlyphHound's contribution is narrow and specific: AST + taint + de-obfuscation catches
obfuscated payloads that string matching misses. That difference is measured, not asserted.
See `benchmark/`:

> On the obfuscated payload set, GlyphHound flags 9 / 9; ModelAudit flags 3 / 9 (in its
> strongest configuration). Both produce 0 false positives on the benign controls.

This is an engineering artifact, not a research claim. It does not catch everything, and it is
not the only tool in this space.

## False-positive rate

A scanner is only as useful as how quiet it stays on safe templates, so this is measured on
real, benign chat templates rather than asserted:

- 0 / 120 on a vendored corpus of distinct real Hugging Face chat templates (`corpus/`).
- 0 / 241 on a separate wider audit of additional real templates (`study/wider_fp_audit.json`).

These are measured rates on those specific sets, not a guarantee that no template will ever be
misflagged. Both are reproducible offline with `scripts/verify_phase7.py`.

## Independent validation

Beyond its own fixtures, GlyphHound has been checked against real, third-party attack payloads
and real production chat templates:

- 23 / 23 real Jinja2 remote-code-execution payloads detected (100% recall). The payloads are
  taken verbatim from two widely used public references: PayloadsAllTheThings and HackTricks.
- 0 / 16 false positives on chat templates pulled live from popular public Hugging Face models
  (100% precision on that set).

These public payloads are largely unobfuscated, where string-matching scanners also do well;
GlyphHound's specific advantage on obfuscated payloads is the separate measurement in
`benchmark/`. The full method, the exact payloads, the model list, and the limitations are in
`VALIDATION.md`.

Reproduce it yourself. The script lives in this repository, so run it from a checkout (static
analysis only, nothing is rendered or executed):

```bash
git clone https://github.com/ydarwish1/glyphhound
cd glyphhound
pip install -e .
python scripts/verify_real_payloads.py
```

## Install

```bash
pip install glyphhound
```

Or from source (for development, the test suite, or the reproduction scripts):

```bash
git clone https://github.com/ydarwish1/glyphhound
cd glyphhound
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

The runtime dependency is jinja2 only; pytest and jsonschema are dev-only.

## Usage

```bash
# Scan a local GGUF, a .gguf URL, a Hugging Face repo, or an Ollama model:
python -m glyphhound scan path/to/model.gguf
python -m glyphhound scan owner/name                      # canonical HF template (no weights)
python -m glyphhound scan owner/name --file auto          # smallest .gguf quant in the repo
python -m glyphhound scan owner/name --file model.Q4.gguf
python -m glyphhound scan ollama-model-name
python -m glyphhound scan template.jinja                  # a local template file
cat template.jinja | python -m glyphhound scan -          # stdin
```

Options:

```
--format human|json|sarif      output format (default: human)
--threshold critical|high      minimum severity that gates CI (default: high)
--confirm                      render in the locked-down sandbox to confirm a finding
--revision <sha>               pin a Hugging Face commit for reproducibility
```

Set `HF_TOKEN` for gated/private repos and higher Hub rate limits.

Exit codes (for CI): 0 = clean, 1 = a reachable finding gates the build, 2 = the scan could
not run.

## Testing and verification

```bash
pip install -e ".[dev]"
python -m pytest                       # offline test suite
python scripts/verify_phase2.py        # per-stage verification scripts (verify_phase*.py)
```

The `verify_phase*.py` scripts re-prove each stage with real output: a flagged fixture, a
schema-valid SARIF file, the measured false-positive rate, the head-to-head benchmark, and the
sandbox containment proof. A few require network (`verify_phase0/9/14`) or a separate ModelAudit
environment (`verify_phase8`); the rest are offline.

## Safety

- MARKER payloads only. Test fixtures simulate the attack chain, but the "payload" is a harmless
  sentinel; there is no working exploit or poisoned model in this repository.
- Never loads weights. The acquirer fetches only the metadata that holds the template.
- The sandbox contains, or stays off. The optional `--confirm` stage renders a template only
  inside a locked-down subprocess (a `sys.addaudithook` policy that blocks network, process
  spawn, `ctypes`, and out-of-scratch / symlink / hardlink writes; on Linux it adds a seccomp
  syscall filter, resource limits, and privilege-drop). It does not block host-file reads or
  deletions; blocking network egress is what prevents a read-then-exfiltrate. Containment is
  tested. It is a best-effort sandbox, not a formally verified jail. See `ARCHITECTURE.md`.

## Documents

- `ARCHITECTURE.md`: the five-stage pipeline, with the exact input/output of each stage.
- `CHANGELOG.md`: the full build history, stage by stage.
- `benchmark/`: the head-to-head methodology, payloads, and the reproducible yardstick
  (`benchmark/RELEASE.md`).
- `study/wider_fp_audit.json`: the wider false-positive audit behind the 0/241 figure.
- `action/`: the GitHub Action wrapper that runs a scan in CI and uploads SARIF to code scanning.
- `SECURITY.md`: how to report a vulnerability. `CONTRIBUTING.md`: how to build and test.

## License

Apache-2.0. See `LICENSE`. Third-party attribution (Jinja2, the vendored SARIF schema, and the
benign template corpus) is in `NOTICE`.
