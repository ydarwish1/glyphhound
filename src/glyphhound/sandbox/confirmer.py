"""Phase 6 -- Stage-4 Sandbox Confirmer (gated): the parent side.

Renders a suspect template in a locked-down child process (:mod:`._child`) with a MARKER
substitution and reports whether code execution was actually reached. The render itself
NEVER happens here -- only in the contained subprocess. The confirmer is OFF by default;
callers opt in (``scan_template_string(..., confirm=True)`` / the CLI ``--confirm`` flag).

A confirmed result is a deterministic function of an OBSERVABLE side effect -- a sentinel
file appearing in a temp scratch dir -- not of timing: render errors, blocked syscalls and
timeouts all map to ``confirmed=False`` (never an exception, never a wrong True). So the
subprocess/timeout nondeterminism is isolated from the static pipeline, which keeps
producing byte-identical reports with the sandbox off.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass

from ..analyze.models import Finding

# The harmless sentinel the marker payload writes; observing it == code execution reached.
MARKER = "GLYPHHOUND_MARKER"
SENTINEL_NAME = "GLYPHHOUND_SENTINEL"
OUTSIDE_NAME = "GLYPHHOUND_OUTSIDE"   # sibling of scratch, NOT inside it -> writes must block
DEFAULT_TIMEOUT = 10.0                # wall-clock seconds for a single contained render
_PROBE_HOST = "192.0.2.1"             # RFC 5737 TEST-NET-1, unroutable by design
_PROBE_PORT = 9                       # discard


@dataclass(frozen=True)
class ConfirmResult:
    """Outcome of one contained render (ARCHITECTURE.md section 3 Stage 4)."""

    confirmed: bool                      # the MARKER sentinel was observed -> code exec reached
    ran: bool                            # the contained render actually executed
    blocked_events: tuple                # syscall attempts the sandbox denied (evidence)
    error: str | None                    # the child's render exception, if any
    timed_out: bool
    pid: int | None
    returncode: int | None
    out_of_scratch_write_occurred: bool  # True only if containment FAILED (a write escaped)
    workdir: str | None
    cleaned_up: bool


def is_supported() -> bool:
    """Whether a contained render can run here (audit hooks + a child Python executable)."""
    return bool(getattr(sys, "addaudithook", None)) and bool(sys.executable)


def _child_env() -> dict:
    """A trimmed environment for the child: enough to start Python and import glyphhound,
    without inheriting unrelated process environment into the rendered template."""
    # Locate the import root that holds the `glyphhound` package, robustly for both an
    # editable checkout (.../src) and an installed wheel (.../site-packages).
    import importlib.util
    spec = importlib.util.find_spec("glyphhound")
    if spec is not None and spec.origin:
        import_root = os.path.dirname(os.path.dirname(spec.origin))
    else:  # fallback for unusual layouts
        import_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    keep = ("SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "TEMP", "TMP",
            "COMSPEC", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "LD_LIBRARY_PATH")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env["PYTHONPATH"] = import_root
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def confirm_template(template_string: str, *, template_name: str | None = None,
                     timeout: float = DEFAULT_TIMEOUT) -> ConfirmResult:
    """Render ``template_string`` in the contained subprocess and report the outcome.

    Never raises on a hostile or looping template: every failure mode (unsupported platform,
    spawn failure, render exception, blocked syscall, timeout) maps to ``confirmed=False``.
    """
    if not is_supported():
        return ConfirmResult(False, False, (), "sandbox unsupported on this platform",
                             False, None, None, False, None, True)

    workdir = tempfile.mkdtemp(prefix="glyphhound_sbx_")
    scratch = os.path.join(workdir, "scratch")
    os.mkdir(scratch)
    sentinel = os.path.join(scratch, SENTINEL_NAME)
    outside = os.path.join(workdir, OUTSIDE_NAME)
    job = {
        "template": template_string,
        "scratch": scratch,
        "sentinel": sentinel,
        "outside": outside,
        "probe_host": _PROBE_HOST,
        "probe_port": _PROBE_PORT,
    }

    blocked: tuple = ()
    error: str | None = None
    timed_out = False
    pid: int | None = None
    returncode: int | None = None
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "glyphhound.sandbox._child"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=scratch, env=_child_env(), text=True, encoding="utf-8",
        )
        pid = proc.pid
        try:
            out, _err = proc.communicate(json.dumps(job), timeout=timeout)
            returncode = proc.returncode
            child = _parse_child(out)
            blocked = tuple(child.get("blocked", ()))
            error = child.get("error")
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            timed_out = True
            error = f"timed out after {timeout}s"
    except Exception as exc:  # spawn failure etc. -- degrade, never crash the caller
        error = f"{type(exc).__name__}: {exc}"

    confirmed = (not timed_out) and os.path.isfile(sentinel) and _reads_marker(sentinel)
    out_of_scratch = os.path.exists(outside)

    shutil.rmtree(workdir, ignore_errors=True)
    cleaned_up = not os.path.exists(workdir)

    return ConfirmResult(
        confirmed=bool(confirmed),
        ran=(returncode is not None) or timed_out,
        blocked_events=blocked,
        error=error,
        timed_out=timed_out,
        pid=pid,
        returncode=returncode,
        out_of_scratch_write_occurred=bool(out_of_scratch),
        workdir=workdir,
        cleaned_up=cleaned_up,
    )


def _parse_child(out: str) -> dict:
    try:
        return json.loads(out)
    except (ValueError, TypeError):
        return {}


def _reads_marker(path: str) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read() == MARKER
    except OSError:
        return False


def confirm_findings(template_string: str, findings, *, template_name: str | None = None,
                     timeout: float = DEFAULT_TIMEOUT) -> list[Finding]:
    """Annotate ``findings`` with ``confirmed`` from a single contained render.

    Confirmation is template-scoped in v1: a *reachable* finding becomes ``confirmed=True``
    when the render reached code execution (the MARKER fired) and ``confirmed=False`` when
    the sandbox ran but it did not. Presence-only findings (``reachable`` not True) are left
    untouched (``confirmed`` stays None) -- the sandbox makes no claim about them. If the
    sandbox could not run at all, findings are returned unchanged (``confirmed`` stays None).
    """
    result = confirm_template(template_string, template_name=template_name, timeout=timeout)
    if not result.ran:
        return list(findings)
    out: list[Finding] = []
    for f in findings:
        if f.reachable is True:
            out.append(dataclasses.replace(f, confirmed=result.confirmed))
        else:
            out.append(f)
    return out
