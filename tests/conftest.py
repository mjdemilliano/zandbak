
import pytest

from devenv import config, plan


@pytest.fixture
def env(tmp_path):
    """A fake home with a few dotfiles and a project directory."""
    home = tmp_path / "home"
    proj = home / "src" / "proj"
    (home / ".claude").mkdir(parents=True)
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("secret")
    (home / ".claude.json").write_text("{}")
    (home / ".gitconfig").write_text("[user]\nname = t\n")
    (proj / ".git" / "hooks").mkdir(parents=True)
    (proj / ".git" / "config").write_text("[core]\n")
    return home, proj


def build(cfg=None, *, home, cwd, command=("bash",), **kw):
    cfg = cfg or config.defaults()
    kw.setdefault("environ", {"PATH": "/usr/bin", "TERM": "xterm", "SECRET": "x"})
    kw.setdefault("machine", "x86_64")
    return plan.build(cfg, home=str(home), cwd=str(cwd), command=list(command), **kw)


def strargs(p):
    return [a if isinstance(a, str) else f"<fd{a.index}>" for a in p.argv]


def triples(args, flag):
    """All (src, dest) pairs following `flag` in an argv list."""
    return [(args[i + 1], args[i + 2]) for i, a in enumerate(args) if a == flag]


def index_of(args, *seq):
    for i in range(len(args) - len(seq) + 1):
        if tuple(args[i : i + len(seq)]) == seq:
            return i
    raise AssertionError(f"{seq} not in argv")
