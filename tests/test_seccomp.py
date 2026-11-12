"""Check the seccomp program by running it in a small BPF interpreter."""

import struct
import sys

import pytest

from devenv import seccomp as sc


def run_bpf(prog: bytes, nr: int, arch: int, args=(0, 0, 0, 0, 0, 0)) -> int:
    args = tuple(args) + (0,) * (6 - len(args))
    data = struct.pack("=iIQ6Q", nr, arch, 0, *args)
    insns = [struct.unpack("=HBBI", prog[i : i + 8]) for i in range(0, len(prog), 8)]
    acc = 0
    pc = 0
    for _ in range(1000):
        code, jt, jf, k = insns[pc]
        if code == 0x20:
            acc = struct.unpack_from("=I", data, k)[0]
            pc += 1
        elif code == 0x15:
            pc += 1 + (jt if acc == k else jf)
        elif code == 0x35:
            pc += 1 + (jt if acc >= k else jf)
        elif code == 0x06:
            return k
        else:
            raise AssertionError(f"unknown opcode {code:#x}")
    raise AssertionError("no return")


X86 = sc.build_filter("x86_64")
ARM = sc.build_filter("aarch64")


def test_shape():
    assert len(X86) % 8 == 0 and len(X86) // 8 < 64
    assert sc.supported("x86_64") and sc.supported("aarch64")
    assert not sc.supported("riscv64")
    with pytest.raises(ValueError):
        sc.build_filter("riscv64")


@pytest.mark.parametrize("cmd", [sc.TIOCSTI, sc.TIOCLINUX, sc.TIOCSTI | (1 << 32), sc.TIOCSTI | (0xFFFF << 40)])
def test_x86_blocks_injection(cmd):
    assert run_bpf(X86, 16, sc.AUDIT_ARCH_X86_64, (0, cmd)) == sc.RET_EPERM


def test_x86_allows_other_ioctls_and_syscalls():
    assert run_bpf(X86, 16, sc.AUDIT_ARCH_X86_64, (0, 0x5401)) == sc.RET_ALLOW  # TCGETS
    assert run_bpf(X86, 0, sc.AUDIT_ARCH_X86_64, (0, sc.TIOCSTI)) == sc.RET_ALLOW  # read()


def test_x86_compat_paths():
    assert run_bpf(X86, 54, sc.AUDIT_ARCH_I386, (0, sc.TIOCSTI)) == sc.RET_EPERM
    assert run_bpf(X86, 54, sc.AUDIT_ARCH_I386, (0, 0x5401)) == sc.RET_ALLOW
    assert run_bpf(X86, 3, sc.AUDIT_ARCH_I386) == sc.RET_ALLOW
    # every x32 syscall is refused
    assert run_bpf(X86, sc.X32_SYSCALL_BIT | 514, sc.AUDIT_ARCH_X86_64, (0, sc.TIOCSTI)) == sc.RET_EPERM
    assert run_bpf(X86, sc.X32_SYSCALL_BIT | 0, sc.AUDIT_ARCH_X86_64) == sc.RET_EPERM


def test_unknown_arch_denied():
    assert run_bpf(X86, 0, 0x12345678) == sc.RET_EPERM


def test_aarch64():
    assert run_bpf(ARM, 29, sc.AUDIT_ARCH_AARCH64, (0, sc.TIOCSTI)) == sc.RET_EPERM
    assert run_bpf(ARM, 29, sc.AUDIT_ARCH_AARCH64, (0, 0x5401)) == sc.RET_ALLOW
    assert run_bpf(ARM, 54, sc.AUDIT_ARCH_ARM, (0, sc.TIOCLINUX)) == sc.RET_EPERM
    assert run_bpf(ARM, 63, sc.AUDIT_ARCH_AARCH64) == sc.RET_ALLOW


@pytest.mark.skipif(sys.byteorder != "little", reason="interpreter assumes little-endian")
def test_offsets_little_endian():
    assert sc._OFF_ARG1_LO == 24
