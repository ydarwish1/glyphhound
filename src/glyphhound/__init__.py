"""GlyphHound — deterministic scanner for code-executing chat templates in model files.

A chat template is a Jinja2 program embedded in a model file (GGUF / Ollama). Some
runtimes render it with an unsandboxed engine, so a malicious template can execute
code the moment the model is loaded (CVE-2024-34359, CVE-2026-5760). GlyphHound
extracts the template *without downloading the weights*, parses it, folds away
obfuscation, taint-traces whether it can reach a code-execution sink, optionally
confirms in a locked-down sandbox, and reports it. Deterministic, no runtime AI.

See ARCHITECTURE.md for the 5-stage pipeline. This package currently implements
Stage 1 (Acquirer); later stages are stubs pending their phases.
"""

__version__ = "0.0.0"
