"""Phase 6 — the contained CHILD that renders a template (the one dangerous act).

Run as ``python -m glyphhound.sandbox._child``. It reads a JSON job from stdin, builds a
**plain (non-sandboxed) Jinja2 Environment** — deliberately, to mirror the vulnerable
runtime so an SSTI escape actually fires — installs the audit-hook containment policy,
renders the template with a MARKER context, and writes a JSON result to stdout.

This is the ONLY place in GlyphHound that a template is rendered, and it only ever runs in
this isolated child process (spawned by the parent confirmer) — never in the main process.
It never loads model weights. Containment — no network, no process
spawn, no out-of-scratch write — is enforced by :func:`..policy.make_audit_hook`; the
parent observes the sentinel file to decide whether code execution was actually reached.
"""

from __future__ import annotations

import json
import sys


def _build_context(job: dict) -> dict:
    """The MARKER render context. Common chat-template variables are given benign defaults
    so a real template renders to completion (and writes no sentinel) instead of erroring on
    an undefined name; the marker/probe variables point the payloads at controlled targets."""
    return {
        "messages": [{"role": "user", "content": "hi"}],
        "sentinel": job["sentinel"],          # in-scratch path the marker payload writes
        "outside": job["outside"],            # out-of-scratch path the fs probe targets
        "probe_host": job["probe_host"],
        "probe_port": job["probe_port"],
        "bos_token": "",
        "eos_token": "",
        "add_generation_prompt": False,
    }


def main() -> int:
    job = json.loads(sys.stdin.read())
    blocked: list[str] = []
    result = {"rendered_ok": False, "error": None, "blocked": blocked}
    try:
        import jinja2

        from glyphhound.sandbox.harden import apply_linux_hardening
        from glyphhound.sandbox.policy import make_audit_hook

        env = jinja2.Environment(
            extensions=("jinja2.ext.do", "jinja2.ext.loopcontrols"),
            autoescape=False,
            undefined=jinja2.ChainableUndefined,
        )
        template = env.from_string(job["template"])   # compile only — runs no template code
        context = _build_context(job)

        # Phase 18 — Linux defence-in-depth (rlimits + privilege drop + seccomp backstop)
        # applied just before arming the audit hook: it runs AFTER imports (seccomp would
        # otherwise block import-time syscalls / ctypes its own loader needs) and UNDER the
        # cross-platform hook. A no-op off Linux, so the Windows path is byte-identical.
        result["hardening"] = apply_linux_hardening(job["scratch"])

        # Arm containment RIGHT before the render: interpreter/import setup above is
        # unaudited; the hook constrains only the dangerous render step below.
        sys.addaudithook(make_audit_hook(job["scratch"], blocked))
        template.render(context)                       # the contained dangerous act
        result["rendered_ok"] = True
    except Exception as exc:  # includes ContainmentViolation raised by the policy
        result["error"] = f"{type(exc).__name__}: {exc}"

    sys.stdout.write(json.dumps(result, ensure_ascii=True))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
