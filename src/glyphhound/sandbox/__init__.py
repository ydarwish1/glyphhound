"""Stage 4 — Sandbox Confirmer (gated, Phase 6).

Optionally CONFIRMS a static finding by rendering the suspect template with a MARKER
substitution inside a locked-down subprocess — no network, no process spawn, no filesystem
write outside a temp scratch dir — and checking whether code execution was actually reached
(ARCHITECTURE.md §3 Stage 4). It is OFF by default and never runs in the static
pipeline; the render happens ONLY in the contained child process (:mod:`._child`), never
here in the main process.

Importing this package pulls in no Jinja2 (the renderer lives only in the child), so the
dangerous rendering capability cannot leak into the host process. No model weights are ever
loaded; MARKER payloads only.
"""

from .confirmer import (
    DEFAULT_TIMEOUT,
    MARKER,
    ConfirmResult,
    confirm_findings,
    confirm_template,
    is_supported,
)

__all__ = [
    "confirm_template",
    "confirm_findings",
    "is_supported",
    "ConfirmResult",
    "MARKER",
    "DEFAULT_TIMEOUT",
]
