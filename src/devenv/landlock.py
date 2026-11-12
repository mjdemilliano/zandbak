"""Landlock scoping: keep the sandbox away from host abstract sockets.

A sandbox sharing the host network namespace also shares the abstract UNIX
socket namespace. The X11 server listens there (``@/tmp/.X11-unix/X0``) and on
many desktops accepts any process of your uid, so an agent could read
keystrokes, take screenshots or type into host windows.

Landlock ABI 6 (Linux 6.12+) can scope abstract-socket connections and signals
to the sandbox. :func:`restrict_self` runs in the child just before bwrap is
executed, so the restriction covers bwrap and everything it starts.
"""

import ctypes
import os
import stat
import struct
from pathlib import Path

_SYS_CREATE_RULESET = 444
"""``landlock_create_ruleset`` syscall number (identical on all architectures)."""
_SYS_RESTRICT_SELF = 446
"""``landlock_restrict_self`` syscall number."""
_CREATE_RULESET_VERSION = 1
"""Flag asking ``landlock_create_ruleset`` for the ABI version."""
_SCOPE_ABSTRACT_UNIX_SOCKET = 1
"""Deny connecting to abstract sockets created outside the domain."""
_SCOPE_SIGNAL = 2
"""Deny signalling processes outside the domain."""
_PR_SET_NO_NEW_PRIVS = 38
"""``prctl`` option required before an unprivileged process may self-restrict."""
MIN_ABI = 6
"""First Landlock ABI with scoping."""

_libc = ctypes.CDLL(None, use_errno=True)
"""The C library, for ``syscall`` and ``prctl``."""
_libc.syscall.restype = ctypes.c_long


def _syscall(number: int, *args: object) -> int:
    """Call ``syscall(number, *args)`` and return its integer result."""
    return int(_libc.syscall(number, *args))


def _check(ret: int, what: str) -> int:
    """Return ``ret``, or raise OSError with errno if it signals failure."""
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{what}: {os.strerror(err)}")
    return ret


def abi_version() -> int:
    """Return the kernel's Landlock ABI version, or 0 if Landlock is unavailable."""
    return max(0, _syscall(_SYS_CREATE_RULESET, None, 0, _CREATE_RULESET_VERSION))


def usable(bwrap: Path) -> bool:
    """Return whether scoping is available and compatible with ``bwrap``.

    Landlock needs ``no_new_privs``, which would stop a setuid bwrap working.
    """
    try:
        setuid = bool(bwrap.stat().st_mode & stat.S_ISUID)
    except OSError:
        return False
    return not setuid and abi_version() >= MIN_ABI


def restrict_self() -> None:
    """Scope the calling process (and its future children). Raises OSError."""
    _check(int(_libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)), "prctl(PR_SET_NO_NEW_PRIVS)")
    # struct landlock_ruleset_attr { u64 handled_access_fs, handled_access_net, scoped; }
    attr = struct.pack("=QQQ", 0, 0, _SCOPE_ABSTRACT_UNIX_SOCKET | _SCOPE_SIGNAL)
    fd = _check(_syscall(_SYS_CREATE_RULESET, attr, len(attr), 0), "landlock_create_ruleset")
    try:
        _check(_syscall(_SYS_RESTRICT_SELF, fd, 0), "landlock_restrict_self")
    finally:
        os.close(fd)
