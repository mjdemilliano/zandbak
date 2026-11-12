"""Landlock scoping: stop the sandbox from reaching host abstract sockets.

When the sandbox shares the host network namespace it also shares the
abstract UNIX socket namespace. The X11 server listens on one
(@/tmp/.X11-unix/X0) and on many desktops (GNOME/Xwayland with
`SI:localuser`) it accepts any process running as your uid, so a sandboxed
agent could read keystrokes, take screenshots or type into host windows.

Landlock ABI 6 (Linux 6.12+) can scope abstract socket connections and
signals to the sandbox. Applied in the child just before bwrap is exec'd,
the restriction is inherited by everything in the sandbox.
"""

from __future__ import annotations

import ctypes
import os
import struct

_SYS_CREATE_RULESET = 444  # same number on all architectures
_SYS_RESTRICT_SELF = 446
_CREATE_RULESET_VERSION = 1 << 0
_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
_SCOPE_SIGNAL = 1 << 1
_PR_SET_NO_NEW_PRIVS = 38

MIN_ABI = 6

_libc = None


def _syscall(*args) -> int:
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
    _libc.syscall.restype = ctypes.c_long
    return _libc.syscall(*[ctypes.c_long(a) if isinstance(a, int) else a for a in args])


def abi_version() -> int:
    """Landlock ABI version, or 0 if Landlock is unavailable."""
    try:
        ret = _syscall(_SYS_CREATE_RULESET, None, 0, _CREATE_RULESET_VERSION)
    except (OSError, AttributeError):
        return 0
    return ret if ret > 0 else 0


def available() -> bool:
    return abi_version() >= MIN_ABI


def restrict_self() -> None:
    """Apply the scope restriction to the calling process. Raises OSError."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        e = ctypes.get_errno()
        raise OSError(e, "prctl(PR_SET_NO_NEW_PRIVS): " + os.strerror(e))
    # struct landlock_ruleset_attr { u64 handled_access_fs, handled_access_net, scoped; }
    attr = ctypes.create_string_buffer(
        struct.pack("=QQQ", 0, 0, _SCOPE_ABSTRACT_UNIX_SOCKET | _SCOPE_SIGNAL)
    )
    fd = _syscall(_SYS_CREATE_RULESET, attr, 24, 0)
    if fd < 0:
        e = ctypes.get_errno()
        raise OSError(e, "landlock_create_ruleset: " + os.strerror(e))
    try:
        if _syscall(_SYS_RESTRICT_SELF, fd, 0) != 0:
            e = ctypes.get_errno()
            raise OSError(e, "landlock_restrict_self: " + os.strerror(e))
    finally:
        os.close(fd)
