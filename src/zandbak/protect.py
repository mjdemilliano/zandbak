"""Protected paths: read-only mounts plus a check after the session.

A protected path lies inside a writable area (the project, or a writable home
directory) and holds something the *host* later runs without the user asking:
git hooks and config, agent hooks and MCP servers, ``.envrc``...

:func:`analyse` walks the path's components from the writable base:

* existing directories on the way are bind-mounted onto themselves ("pinned").
  Mount points cannot be renamed or removed, so the agent cannot swap a parent
  for one it controls;
* the final component, or a non-directory on the way (a worktree's ``.git``
  file), is mounted read-only;
* a symlink is never followed: following an agent-planted link would mount an
  arbitrary host file into the sandbox. It is watched instead;
* a missing component is watched.

After the sandbox exits (the PID namespace guarantees every process in it is
dead), :func:`quarantine` renames watched components that appeared or changed
to ``<name>.zandbak-quarantine-<time>``, so the host never loads them.
"""

import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from zandbak import APP

type Bind = tuple[Path, Path]
"""A bind mount: (host source, sandbox destination)."""


@dataclass(frozen=True, slots=True)
class Identity:
    """What a path is, compared before and after the session to detect changes."""

    dev: int
    """Device number."""
    ino: int
    """Inode number."""
    fmt: int
    """File type bits (``stat.S_IFMT``)."""
    link: str | None
    """Symlink target, or None for other file types."""

    @classmethod
    def of(cls, path: Path) -> Self | None:
        """Return ``path``'s identity without following symlinks, or None if absent."""
        try:
            st = path.lstat()
        except (FileNotFoundError, NotADirectoryError):
            return None
        link = str(path.readlink()) if stat.S_ISLNK(st.st_mode) else None
        return cls(st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), link)


@dataclass(frozen=True, slots=True, kw_only=True)
class Protection:
    """How one protected path is enforced."""

    rel: str
    """The configured path, relative to its base."""
    ro: tuple[Bind, ...] = ()
    """Read-only mounts (at most one)."""
    pins: tuple[Bind, ...] = ()
    """Parent directories bound onto themselves so they cannot be replaced."""
    watch: Path | None = None
    """Host path to compare after the session, if it could not be mounted."""
    before: Identity | None = None
    """Identity of :attr:`watch` at startup (None: it did not exist)."""


def analyse(base: Path, rel: str, dest: Path | None = None) -> Protection:
    """Decide how to protect ``rel`` under host directory ``base``.

    ``base`` appears in the sandbox at ``dest`` (default: the same path).
    """
    dest = dest or base
    pins: list[Bind] = []
    parts = rel.split("/")
    for depth in range(1, len(parts) + 1):
        sub = "/".join(parts[:depth])
        host, inside = base / sub, dest / sub
        ident = Identity.of(host)
        if ident is None or ident.link is not None:
            return Protection(rel=rel, pins=tuple(pins), watch=host, before=ident)
        if depth == len(parts) or ident.fmt != stat.S_IFDIR:
            return Protection(rel=rel, ro=((host, inside),), pins=tuple(pins))
        pins.append((host, inside))
    raise AssertionError("unreachable: rel has at least one component")


def _free_name(path: Path, stamp: str) -> Path:
    """Return an unused quarantine name next to ``path``."""
    candidate = path.with_name(f"{path.name}.{APP}-quarantine-{stamp}")
    n = 1
    while candidate.exists(follow_symlinks=False):
        n += 1
        candidate = path.with_name(f"{path.name}.{APP}-quarantine-{stamp}-{n}")
    return candidate


def quarantine(protections: list[Protection], now: float | None = None) -> list[str]:
    """Rename watched paths that appeared or changed; return messages for the user."""
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
    notes = []
    for watch, before in {p.watch: p.before for p in protections if p.watch}.items():
        after = Identity.of(watch)
        if after is None or after == before:
            continue
        target = _free_name(watch, stamp)
        try:
            watch.rename(target)  # renames a symlink itself, never its target
        except OSError as e:
            notes.append(
                f"DANGER: {watch} was created or changed in the sandbox and could not be "
                f"quarantined ({e.strerror}). Inspect it before running anything there."
            )
        else:
            notes.append(
                f"quarantined {watch} -> {target.name}: created or changed in the sandbox. "
                "Review it before restoring."
            )
    return notes
