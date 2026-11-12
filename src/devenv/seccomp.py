"""A seccomp-BPF filter that blocks terminal input injection.

A process sharing the controlling terminal can call ``ioctl(fd, TIOCSTI, &c)``
to push characters into the terminal's input queue. The *parent* shell reads
them after the sandbox exits, so the sandbox could run commands on the host
(CVE-2017-5226). ``TIOCLINUX`` has a similar paste primitive on virtual
consoles.

bwrap's own fix, ``--new-session``, detaches the sandbox from job control
(Ctrl-C would end the whole sandbox). This filter keeps the terminal normal.

The filter returns ``EPERM`` for:

* ``ioctl`` whose command's *low 32 bits* are TIOCSTI or TIOCLINUX. The kernel
  truncates the command to 32 bits, so a 64-bit comparison is bypassable
  (CVE-2019-10063);
* every x32 syscall on x86_64 (a separate syscall table we don't inspect);
* every syscall from an architecture not listed for this machine.
"""

import struct
import sys
from typing import NamedTuple

_LD_W_ABS = 0x20
"""BPF opcode: load a 32-bit word from ``seccomp_data``."""
_JEQ = 0x15
"""BPF opcode: jump if the accumulator equals ``k``."""
_JGE = 0x35
"""BPF opcode: jump if the accumulator is ``>= k``."""
_RET = 0x06
"""BPF opcode: return ``k``."""

RET_ALLOW = 0x7FFF0000
"""``SECCOMP_RET_ALLOW``."""
RET_EPERM = 0x00050000 | 1
"""``SECCOMP_RET_ERRNO`` with ``EPERM``."""

TIOCSTI = 0x5412
"""ioctl that fakes terminal input."""
TIOCLINUX = 0x541C
"""ioctl multiplexer for virtual consoles, including selection paste."""

AUDIT_ARCH_X86_64 = 0xC000003E
"""Audit architecture value for x86_64 syscalls."""
AUDIT_ARCH_I386 = 0x40000003
"""Audit architecture value for 32-bit x86 syscalls."""
AUDIT_ARCH_AARCH64 = 0xC00000B7
"""Audit architecture value for aarch64 syscalls."""
AUDIT_ARCH_ARM = 0x40000028
"""Audit architecture value for 32-bit ARM syscalls."""
X32_SYSCALL_BIT = 0x40000000
"""Set in the syscall number of x32-ABI syscalls on x86_64."""

_OFF_NR = 0
"""Offset of ``seccomp_data.nr``."""
_OFF_ARCH = 4
"""Offset of ``seccomp_data.arch``."""
_OFF_ARG1_LO = 24 + (0 if sys.byteorder == "little" else 4)
"""Offset of the low 32 bits of ``seccomp_data.args[1]`` (the ioctl command)."""


class _Abi(NamedTuple):
    """One syscall ABI a process on a given kernel can use."""

    audit_arch: int
    """``AUDIT_ARCH_*`` value reported in ``seccomp_data.arch``."""
    ioctl_nr: int
    """Syscall number of ``ioctl`` in this ABI."""
    block_x32: bool
    """Refuse syscall numbers with :data:`X32_SYSCALL_BIT` set."""


_ABIS: dict[str, tuple[_Abi, ...]] = {
    "x86_64": (
        _Abi(AUDIT_ARCH_X86_64, 16, block_x32=True),
        _Abi(AUDIT_ARCH_I386, 54, block_x32=False),
    ),
    "aarch64": (
        _Abi(AUDIT_ARCH_AARCH64, 29, block_x32=False),
        _Abi(AUDIT_ARCH_ARM, 54, block_x32=False),
    ),
}
"""Machine (``platform.machine()``) to the syscall ABIs its kernel accepts."""

type _Insn = tuple[int, int, str | None, str | None]
"""An instruction before assembly: opcode, k, jump-if-true label, jump-if-false label."""
type _Item = _Insn | str
"""A program item: an instruction, or a bare string defining a label at that point."""


def supported(machine: str) -> bool:
    """Return whether a filter can be built for ``machine``."""
    return machine in _ABIS


def _assemble(items: list[_Item]) -> bytes:
    """Resolve labels to relative jumps and encode as ``struct sock_filter``."""
    labels: dict[str, int] = {}
    insns: list[_Insn] = []
    for item in items:
        if isinstance(item, str):
            labels[item] = len(insns)
        else:
            insns.append(item)

    def offset(pc: int, label: str | None) -> int:
        """Jump distance from instruction ``pc`` to ``label`` (0 = next)."""
        if label is None:
            return 0
        off = labels[label] - pc - 1
        if not 0 <= off <= 0xFF:  # noqa: PLR2004 - BPF jump offsets are one byte
            raise ValueError(f"jump to {label} out of range")
        return off

    return b"".join(
        struct.pack("=HBBI", op, offset(pc, jt), offset(pc, jf), k)
        for pc, (op, k, jt, jf) in enumerate(insns)
    )


def build_filter(machine: str) -> bytes:
    """Return the compiled filter for ``machine``, ready for ``bwrap --seccomp``."""
    if not supported(machine):
        raise ValueError(f"no seccomp filter for architecture {machine}")
    abis = _ABIS[machine]
    prog: list[_Item] = [(_LD_W_ABS, _OFF_ARCH, None, None)]
    prog += [(_JEQ, abi.audit_arch, f"abi{i}", None) for i, abi in enumerate(abis)]
    prog.append((_RET, RET_EPERM, None, None))  # unknown architecture
    for i, abi in enumerate(abis):
        prog += [f"abi{i}", (_LD_W_ABS, _OFF_NR, None, None)]
        if abi.block_x32:
            prog.append((_JGE, X32_SYSCALL_BIT, "deny", None))
        prog.append((_JEQ, abi.ioctl_nr, "ioctl", "allow"))
    prog += [
        "ioctl",
        (_LD_W_ABS, _OFF_ARG1_LO, None, None),
        (_JEQ, TIOCSTI, "deny", None),
        (_JEQ, TIOCLINUX, "deny", "allow"),
        "allow",
        (_RET, RET_ALLOW, None, None),
        "deny",
        (_RET, RET_EPERM, None, None),
    ]
    return _assemble(prog)
