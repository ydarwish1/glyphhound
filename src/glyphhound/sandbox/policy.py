"""Phase 6 — the audit-hook containment policy (cross-platform).

This is the syscall-level guard that makes rendering a hostile template safe IN THE CHILD
process: a ``sys.addaudithook`` callback that DENIES the operations a load-time RCE would
use — outbound network, process spawn, ``ctypes``, and filesystem writes outside the
sandbox's temp scratch dir — while ALLOWING harmless in-scratch writes (so a MARKER payload
can leave its sentinel). Every denied attempt is recorded as evidence.

The decision logic is a pure function of ``(event, args)`` plus the scratch root, so it is
unit-testable in-process WITHOUT installing the (permanent) hook. The out-of-scratch write
check resolves symlinks via the OS (``realpath``) so a symlink planted inside scratch that
points OUTSIDE cannot be used to escape it, and creating a hardlink / symlink / rename is
DENIED outright (a contained render never needs to alias files) — closing the inode-aliasing
escape a path-based ``realpath`` check alone cannot see, since a hardlink is just a second
name for the same inode (Phase 18). The Linux-only kernel/OS backstops — seccomp, ``resource``
rlimits and privilege-drop — live in :mod:`.harden` and are applied in the child alongside
this hook.
"""

from __future__ import annotations

import os
from typing import Callable

# Audit events that denote a real syscall we must block.
#   network      : socket.connect / DNS lookups
#   process spawn: os.system / subprocess / exec / spawn / startfile / fork
#   ctypes       : a raw-memory escape hatch that could sidestep the hook
_NETWORK_EVENTS = frozenset({"socket.connect", "socket.getaddrinfo", "socket.gethostbyname"})
_SPAWN_EVENTS = frozenset({
    "os.system", "subprocess.Popen", "os.exec", "os.spawn", "os.posix_spawn",
    "os.startfile", "os.fork", "os.forkpty",
})
_CTYPES_EVENTS = frozenset({
    "ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function", "ctypes.cdata",
})
# Filesystem aliasing: a hardlink/symlink/rename can point an in-scratch NAME at an
# out-of-scratch INODE, which the path-based `open` check (even with realpath) cannot see —
# a hardlink carries no symbolic-link signal. A contained render never needs to alias files,
# so creating any of these is denied outright, closing that out-of-scratch-write escape.
_LINK_EVENTS = frozenset({"os.link", "os.symlink", "os.rename"})

# os.open carries its intent in integer flags (the `open` audit event's `mode` is None for
# the os.open path). Any of these means "this open can write".
_WRITE_FLAGS = (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND
                | getattr(os, "O_TRUNC", 0))


class ContainmentViolation(RuntimeError):
    """Raised inside the child to ABORT a denied syscall (an audit hook that raises aborts
    the operation it is auditing)."""


def _is_write(mode, flags) -> bool:
    """Whether an ``open`` audit event represents a write."""
    if isinstance(mode, str):
        return any(c in mode for c in "wax+")
    if isinstance(flags, int):
        return bool(flags & _WRITE_FLAGS)
    return False


def _within(path, root_norm: str, root_real: str) -> bool:
    """Whether ``path`` resolves inside the scratch root, checked TWO ways: string
    normalisation (``..`` collapsed by ``normpath``) AND OS-level symlink resolution
    (``realpath``). A path counts as inside only if BOTH agree, so a symlink planted inside
    scratch that points OUTSIDE is treated as out-of-scratch and its write is blocked
    (Phase 18). For ordinary (non-symlink) paths ``realpath`` == the normalised path, so the
    behaviour is unchanged. The hook's re-entrancy guard keeps ``realpath``'s internal
    ``lstat``/``readlink`` from recursing through nested audit events."""
    try:
        ap = os.path.abspath(os.fspath(path))
    except (TypeError, ValueError):
        return False
    norm = os.path.normpath(ap)
    if not (norm == root_norm or norm.startswith(root_norm + os.sep)):
        return False
    try:
        real = os.path.realpath(ap)
    except OSError:
        return False  # fail closed: an unresolvable path is treated as out-of-scratch
    return real == root_real or real.startswith(root_real + os.sep)


def make_audit_hook(scratch_dir: str, blocked: list) -> Callable[[str, tuple], None]:
    """Build the audit-hook callback for a child whose scratch root is ``scratch_dir``.

    Appends a short description of each denied attempt to ``blocked`` (evidence the parent
    surfaces) and raises :class:`ContainmentViolation` to abort it. A re-entrancy guard keeps
    the hook's own work from recursing if it ever triggers a nested audit event.
    """
    root_norm = os.path.normpath(os.path.abspath(scratch_dir))
    root_real = os.path.realpath(scratch_dir)
    guard = {"busy": False}

    def hook(event: str, args: tuple) -> None:
        if guard["busy"]:
            return
        guard["busy"] = True
        try:
            if event in _NETWORK_EVENTS:
                target = args[1] if len(args) > 1 else args
                blocked.append(f"network-{event}: {target}")
                raise ContainmentViolation(f"network blocked: {event}")
            if event in _SPAWN_EVENTS:
                blocked.append(f"process-spawn: {event}")
                raise ContainmentViolation(f"process spawn blocked: {event}")
            if event in _CTYPES_EVENTS:
                blocked.append(f"ctypes: {event}")
                raise ContainmentViolation(f"ctypes blocked: {event}")
            if event in _LINK_EVENTS:
                paths = args[:2] if len(args) >= 2 else args
                blocked.append(f"fs-link-create: {event}: {paths}")
                raise ContainmentViolation(f"link/rename blocked: {event}")
            if event == "open":
                path = args[0] if args else None
                mode = args[1] if len(args) > 1 else None
                flags = args[2] if len(args) > 2 else None
                if path is not None and _is_write(mode, flags) and not _within(path, root_norm, root_real):
                    blocked.append(f"fs-write-outside-scratch: {path}")
                    raise ContainmentViolation(f"out-of-scratch write blocked: {path}")
        finally:
            guard["busy"] = False

    return hook
