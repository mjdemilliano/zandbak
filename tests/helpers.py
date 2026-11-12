"""Shared helpers for building plans in tests."""

from pathlib import Path

from devenv import config, plan


def build(cfg=None, *, home, cwd, command=("bash",), **kw) -> plan.Plan:
    kw.setdefault("environ", {"PATH": "/usr/bin", "TERM": "xterm", "SECRET": "x"})
    kw.setdefault("machine", "x86_64")
    req = plan.Request(
        config=cfg or config.defaults(),
        home=Path(home),
        cwd=Path(cwd),
        command=tuple(command),
        **kw,
    )
    return plan.build(req)


def cfg_with(text: str) -> config.Config:
    return config.parse(text, config.defaults())


def strargs(p: plan.Plan) -> list[str]:
    return [a if isinstance(a, str) else f"<fd{a.index}>" for a in p.argv]


def pairs(args: list[str], flag: str) -> list[tuple[str, str]]:
    """All (a, b) pairs following ``flag``."""
    return [(args[i + 1], args[i + 2]) for i, a in enumerate(args) if a == flag]


def index_of(args: list[str], *seq: str) -> int:
    for i in range(len(args) - len(seq) + 1):
        if tuple(args[i : i + len(seq)]) == seq:
            return i
    raise AssertionError(f"{seq} not in argv")
