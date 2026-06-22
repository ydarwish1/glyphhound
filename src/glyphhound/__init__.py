"""GlyphHound — deterministic scanner for code-executing chat templates in model files.

A chat template is a Jinja2 program embedded in a model file (GGUF / Ollama / Hugging
Face). Some runtimes render it with an unsandboxed engine, so a malicious template can
execute code the moment the model is loaded (CVE-2024-34359, CVE-2026-5760). GlyphHound
extracts the template *without downloading the weights*, parses it to an AST, folds away
obfuscation, taint-traces whether it can reach a code-execution sink, optionally confirms
the finding in a locked-down sandbox, and reports it (human / JSON / SARIF) with a CI exit
code. Deterministic, offline, no runtime AI.

The pipeline (see ARCHITECTURE.md): Acquire -> Parse -> De-obfuscate -> Analyze
(sinks + taint/reachability) -> Report, plus an optional, off-by-default sandbox confirmer.
"""

__version__ = "0.1.0"
