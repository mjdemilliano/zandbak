"""A tiny seccomp-BPF filter that blocks terminal input injection.

Without it, a sandboxed process that shares the controlling terminal can call
ioctl(fd, TIOCSTI, &c) to push characters into the terminal's input queue.
They are read by the *parent* shell once the sandbox exits, so the sandbox
can run arbitrary commands on the host (CVE-2017-5226). TIOCLINUX has a
similar paste-selection primitive on virtual consoles.

bwrap's own answer is --new-session, but that detaches the sandbox from the
terminal's job control (Ctrl-C then kills the whole sandbox instead of the
running command). A filter keeps the terminal behaving normally.

The filter returns EPERM for:
  * ioctl() with a command whose low 32 bits are TIOCSTI or TIOCLINUX
    (the kernel truncates the command to 32 bits, so comparing all 64 would
    be bypassable, see CVE-2019-10063);
  * every x32 syscall on x86_64 (a separate syscall table we don't inspect);
  * every syscall from an architecture we don't know about.
"""

from __future__ import annotations

import platform
import struct
import sys

# BPF opcodes
_LD_W_ABS = 0x20  # BPF_LD | BPF_W | BPF_ABS
_JEQ_K = 0x15  # BPF_JMP | BPF_JEQ | BPF_K
_JGE_K = 0x35  # BPF_JMP | BPF_JGE | BPF_K
_RET_K = 0x06  # BPF_RET | BPF_K

RET_ALLOW = 0x7FFF0000
RET_EPERM = 0x00050000 | 1  # SECCOMP_RET_ERRNO | EPERM

TIOCSTI = 0x5412
TIOCLINUX = 0x541C

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_I386 = 0x40000003
AUDIT_ARCH_AARCH64 = 0xC00000B7
AUDIT_ARCH_ARM = 0x40000028
X32_SYSCALL_BIT = 0x40000000

# Native architecture -> list of (audit arch, ioctl syscall nr, block x32)
# that a process on that kernel can issue syscalls as.
_ARCHES = {
    "x86_64": [
        (AUDIT_ARCH_X86_64, 16, True),
        (AUDIT_ARCH_I386, 54, False),
    ],
    "aarch64": [
        (AUDIT_ARCH_AARCH64, 29, False),
        (AUDIT_ARCH_ARM, 54, False),
    ],
}

# struct seccomp_data offsets
_OFF_NR = 0
_OFF_ARCH = 4
_OFF_ARG1 = 16 + 8  # args[1]
_OFF_ARG1_LO = _OFF_ARG1 + (0 if sys.byteorder == "little" else 4)


def supported(machine: str | None = None) -> bool:
    return (machine or platform.machine()) in _ARCHES


def _assemble(prog: list[tuple]) -> bytes:
    """Assemble (op, k, jt_label, jf_label) / ("label", name) tuples."""
    labels: dict[str, int] = {}
    insns = []
    for item in prog:
        if item[0] == "label":
            labels[item[1]] = len(insns)
        else:
            insns.append(item)
    out = bytearray()
    def rel(i: int, lbl: str | None) -> int:
        if lbl is None:
            return 0
        off = labels[lbl] - (i + 1)
        if not 0 <= off <= 255:
            raise ValueError(f"jump to {lbl} out of range")
        return off

    for i, (op, k, jt, jf) in enumerate(insns):
        out += struct.pack("=HBBI", op, rel(i, jt), rel(i, jf), k)
    return bytes(out)


def build_filter(machine: str | None = None) -> bytes:
    machine = machine or platform.machine()
    if machine not in _ARCHES:
        raise ValueError(f"seccomp filter: unsupported architecture {machine}")
    arches = _ARCHES[machine]
    prog: list[tuple] = [(_LD_W_ABS, _OFF_ARCH, None, None)]
    for idx, (arch, _, _) in enumerate(arches):
        prog.append((_JEQ_K, arch, f"arch{idx}", None))
    prog.append((_RET_K, RET_EPERM, None, None))  # unknown architecture
    for idx, (_, ioctl_nr, block_x32) in enumerate(arches):
        prog.append(("label", f"arch{idx}"))
        prog.append((_LD_W_ABS, _OFF_NR, None, None))
        if block_x32:
            prog.append((_JGE_K, X32_SYSCALL_BIT, "deny", None))
        prog.append((_JEQ_K, ioctl_nr, "check", "allow"))
    prog += [
        ("label", "check"),
        (_LD_W_ABS, _OFF_ARG1_LO, None, None),
        (_JEQ_K, TIOCSTI, "deny", None),
        (_JEQ_K, TIOCLINUX, "deny", "allow"),
        ("label", "allow"),
        (_RET_K, RET_ALLOW, None, None),
        ("label", "deny"),
        (_RET_K, RET_EPERM, None, None),
    ]
    return _assemble(prog)
