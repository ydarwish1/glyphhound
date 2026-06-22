"""Phase 18 — Linux-only defence-in-depth for the contained child.

Phase 6 contains the one dangerous act (rendering a hostile template) with a cross-platform
``sys.addaudithook`` policy (see :mod:`.policy`). This module adds the kernel-/OS-level
backstops that only exist on Linux, layered UNDER that audit hook inside the child process
(:mod:`._child`):

  * **resource rlimits** (``resource.setrlimit``) — cap CPU, file size, open files and core
    dumps, so an abusive render cannot exhaust the host even if the wall-clock timeout is
    defeated;
  * **best-effort privilege drop** — if the child somehow starts as root, drop to an
    unprivileged uid/gid (a no-op in the normal non-root case, reported honestly);
  * **a seccomp syscall filter** — installed via the system ``libseccomp`` through ``ctypes``
    (no new pip dependency) with a default-ALLOW policy that KILLS the process if it reaches
    the dangerous syscalls the audit hook guards at the Python level (outbound ``connect`` /
    ``sendto`` / ``sendmsg``, process ``execve`` / ``execveat``, and ``ptrace``). This is the
    *kernel* backstop for the case where a payload reaches a syscall WITHOUT going through an
    audited Python call (e.g. via an already-loaded C extension).

Everything here is a NO-OP off Linux, so the Windows / static pipeline is byte-identical
(the project conventions). Nothing here ever raises into the render path: each step degrades to
"not applied" and is recorded as evidence (Rule 5 — ship the containment we can prove; the
audit hook + subprocess boundary remain even if a backstop is unavailable). MARKER-only
context is rendered (Rule 4); no weights are ever loaded (Rule 6).

Honest scope: the seccomp filter is added for the NATIVE (x86_64) ABI — the ABI CPython uses
— and is a *backstop* to the primary, cross-ABI audit hook; it is not a complete syscall
allow-list. ``socket`` creation is deliberately NOT denied so the audit hook can still fire
on the Python-level ``socket.connect`` (producing evidence) before the ``connect`` syscall.
"""

from __future__ import annotations

import sys

# Syscalls the seccomp backstop denies (see module docstring for why ``socket`` itself is
# intentionally absent). Grouped by the escape they close:
#   network egress   : connect (TCP) + sendto/sendmsg/sendmmsg (connectionless UDP, no connect)
#   process exec     : execve/execveat
#   debug            : ptrace
#   filesystem alias : link/linkat/symlink/symlinkat — kernel backstop for the inode-aliasing
#                      escape the audit hook's os.link/os.symlink denial guards at Python level
#   async submission : io_uring_* — submits connect/send/openat/etc. WITHOUT issuing those
#                      syscalls, the canonical way to defeat a connect/send denylist
# Any name unknown on this arch is skipped (resolve returns < 0), never fatal.
_SECCOMP_DENY = (
    "connect", "sendto", "sendmsg", "sendmmsg",
    "execve", "execveat",
    "ptrace",
    "link", "linkat", "symlink", "symlinkat",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
)

# libseccomp action codes (SCMP_ACT_* from <seccomp.h>). KILL_PROCESS terminates the whole
# process with SIGSYS — the strongest containment, and harmless to the render (which never
# issues a denied syscall) because the audit hook intercepts the audited Python calls first.
_SCMP_ACT_ALLOW = 0x7FFF0000
_SCMP_ACT_KILL_PROCESS = 0x80000000

# Safe resource caps for a single contained render. FSIZE stays well above the tiny MARKER
# sentinel so a confirmation still writes it; CPU is a backstop to the wall-clock timeout.
_RLIMIT_CAPS = (
    ("RLIMIT_CORE", 0),                    # no core dumps (no memory-to-disk leak)
    ("RLIMIT_FSIZE", 16 * 1024 * 1024),    # cap file writes at 16 MiB (sentinel is bytes)
    ("RLIMIT_NOFILE", 256),                # cap open file descriptors
    ("RLIMIT_CPU", 30),                    # CPU-seconds backstop to the wall-clock timeout
)


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def apply_rlimits() -> list:
    """Lower resource limits to the safe caps above. Best-effort: a non-root process can only
    lower a hard limit, so a cap that cannot be set is skipped, never fatal. Returns the names
    actually applied (evidence)."""
    applied: list = []
    try:
        import resource
    except Exception:
        return applied
    for name, value in _RLIMIT_CAPS:
        const = getattr(resource, name, None)
        if const is None:
            continue
        try:
            _soft, hard = resource.getrlimit(const)
            new_hard = value if hard == resource.RLIM_INFINITY else min(value, hard)
            resource.setrlimit(const, (min(value, new_hard), new_hard))
            applied.append(name)
        except (ValueError, OSError):
            continue
    return applied


def drop_privileges() -> str:
    """If running as root, drop to an unprivileged uid/gid (an honest no-op otherwise).

    Privilege drop only does anything when the process starts privileged, which a normal CI
    user is not — so this is best-effort by design, reported honestly rather than overclaimed.
    After dropping it verifies root cannot be regained.

    Caveat (safe-direction): if the scanner is run AS ROOT with ``--confirm``, the dropped
    ``nobody`` user may lack access to the interpreter's files or the root-owned scratch dir,
    so a render can fail and a real finding gets a false-NEGATIVE confirmation (never a false
    positive, and never a crash — the confirmer maps every failure to ``confirmed=False``).
    Run the optional confirm stage UNPRIVILEGED (the normal case), where this is a no-op. The
    static pipeline — the actual detector — is unaffected and runs fine as any user.
    """
    try:
        import os
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return "skipped (not root)"
        import pwd
        try:
            nobody = pwd.getpwnam("nobody")
            uid, gid = nobody.pw_uid, nobody.pw_gid
        except KeyError:
            uid = gid = 65534
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        try:
            os.setuid(0)              # must FAIL — a successful re-elevation is a containment hole
            return "FAILED (regained root)"
        except OSError:
            return f"dropped to uid={uid} gid={gid}"
    except Exception as exc:          # never break the render on a privilege-drop hiccup
        return f"error: {type(exc).__name__}"


def install_seccomp_filter() -> str:
    """Install the seccomp backstop via the system libseccomp (ctypes). Returns a status
    string (``loaded: ...`` on success). Default action ALLOW; the syscalls in
    ``_SECCOMP_DENY`` get KILL_PROCESS for the NATIVE (x86_64) ABI only — a backstop, not a
    complete allow-list, and not the cross-ABI guard (the i386/x32 compat ABIs are out of
    scope here; the audit hook is the cross-ABI/Python-level control). Best-effort and never
    raises: if libseccomp is missing or ANY call fails, the reason string is returned and the
    render proceeds under the audit hook + rlimits alone.
    """
    try:
        import ctypes
        import ctypes.util

        name = ctypes.util.find_library("seccomp") or "libseccomp.so.2"
        try:
            lib = ctypes.CDLL(name, use_errno=True)
        except OSError as exc:
            return f"unavailable ({exc})"

        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
        lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]

        raw = lib.seccomp_init(ctypes.c_uint32(_SCMP_ACT_ALLOW))
        if not raw:
            return "seccomp_init failed"
        ctx = ctypes.c_void_p(raw)
        try:
            denied = []
            for sysname in _SECCOMP_DENY:
                nr = lib.seccomp_syscall_resolve_name(sysname.encode("ascii"))
                if nr < 0:
                    continue              # unknown on this arch — skip, not fatal
                rc = lib.seccomp_rule_add(
                    ctx, ctypes.c_uint32(_SCMP_ACT_KILL_PROCESS), ctypes.c_int(nr), ctypes.c_uint(0)
                )
                if rc == 0:
                    denied.append(sysname)
            if not denied:
                return "no rules added"
            # seccomp_load also sets PR_SET_NO_NEW_PRIVS (libseccomp default SCMP_FLTATR_CTL_NNP),
            # so an unprivileged process is allowed to install the filter.
            rc = lib.seccomp_load(ctx)
            if rc != 0:
                return f"seccomp_load failed (rc={rc})"
            return "loaded: " + ",".join(denied)
        finally:
            try:
                lib.seccomp_release(ctx)
            except Exception:
                pass
    except Exception as exc:          # uphold the never-raises contract on any ctypes/ABI hiccup
        return f"unavailable ({type(exc).__name__}: {exc})"


def apply_linux_hardening(scratch_dir: str | None = None) -> dict:
    """Apply all Linux backstops in the child, in order: rlimits -> privilege drop -> seccomp.

    A no-op off Linux (returns ``{"applied": False}``). Never raises — returns a summary dict
    of what was applied so the parent / verifier can surface it as evidence. ``scratch_dir`` is
    accepted for symmetry with the audit-hook policy but is not currently needed here.

    WARNING: the effects are process-global and IRREVERSIBLE — a seccomp filter is inherited
    across fork/exec, and lowered rlimits / a dropped uid cannot be raised again. Call this
    ONLY in the short-lived, throwaway render child (:mod:`._child`), never in a long-lived
    process (a test runner, the CLI host): doing so would silently constrain every later
    subprocess that process spawns.
    """
    if not is_linux():
        return {"platform": sys.platform, "applied": False}
    return {
        "platform": sys.platform,
        "applied": True,
        "rlimits": apply_rlimits(),
        "privilege_drop": drop_privileges(),
        "seccomp": install_seccomp_filter(),
    }
