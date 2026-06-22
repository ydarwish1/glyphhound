# GlyphHound

A deterministic scanner that detects code-executing chat templates inside model files
(GGUF / Ollama / Hugging Face), before you load the model.

## The problem

When you download an open-weights LLM, the file ships with a chat template: a small
[Jinja2](https://jinja.palletsprojects.com/) program that formats your messages before the
model sees them. Several runtimes render that template with an unsandboxed Jinja engine, so a
malicious template can run code on your machine the moment the model is loaded, before you type
anything. This is a real, patched bug class:

- CVE-2024-34359 (llama-cpp-python)
- CVE-2026-5760 (SGLang, CVSS 9.8)

## What GlyphHound does

It reads the chat template out of the model file without downloading the multi-gigabyte
weights, parses it into a syntax tree, traces whether it can reach a code-execution operation,
optionally confirms it in a locked-down sandbox, and reports the result with a CI exit code.

It is a program-analysis tool, not a model: the same input always produces the same finding,
there are no API calls or LLM calls at scan time, and it runs offline.

Pipeline (five stages):

1. Acquire: extract the template via an HTTP range request over the GGUF metadata header, the
   local Ollama blob, or a Hugging Face repo's `tokenizer_config.json` / `chat_template.jinja` /
   safetensors metadata. Asserts that bytes fetched is far smaller than the file size.
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

A scanner that flags everything is useless, so the false-positive rate is measured on real,
benign templates:

- 0 / 120 on a vendored corpus of distinct real Hugging Face chat templates (`corpus/`).
- 0 / 241 on a separate wider audit of additional real templates (`study/wider_fp_audit.json`).

## Install

```bash
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
  syscall filter, resource limits, and privilege-drop). Containment is tested. It is a
  best-effort sandbox, not a formally verified jail. See `ARCHITECTURE.md`.

## Documents

- `ARCHITECTURE.md`: the five-stage pipeline, with the exact input/output of each stage.
- `CHANGELOG.md`: the full build history, stage by stage.
- `benchmark/`: the head-to-head methodology and payloads.

## License

Apache-2.0. See `LICENSE`.
