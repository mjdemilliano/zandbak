"""Protected paths: read-only mounts plus a post-session check.

A protected path is something inside a writable area (the project, or a
writable home directory) whose contents the *host* later executes without
the user choosing to: git hooks and config, agent hooks/settings, .envrc...

For each protected path we walk its components from the writable base:

* existing directories on the way are bind-mounted onto themselves, which
  makes them mount points. Mount points can't be renamed or removed, so the
  agent can't swap a parent for a directory (or symlink) it controls;
* an existing final component, or an existing non-directory on the way
  (e.g. a worktree's `.git` file), is bind-mounted read-only;
* a symlink anywhere is *not* followed (following an agent-planted link
  would mount an arbitrary host file into the sandbox). It is watched;
* a missing component is watched.

After the sandbox exits (and every process in it is dead, thanks to the PID
namespace), watched components that appeared or changed are renamed to
`<name>.devenv-quarantine-<timestamp>` so the host never loads them.
"""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Identity:
    exists: bool
    dev: int = 0
    ino: int = 0
    fmt: int = 0
    link: str | None = None

    @classmethod
    def of(cls, path: Path) -> "Identity":
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return cls(exists=False)
        except NotADirectoryError:
            return cls(exists=False)
        link = os.readlink(path) if stat.S_ISLNK(st.st_mode) else None
        return cls(True, st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), link)


@dataclass(frozen=True)
class Protection:
    """Result of analysing one protected path."""

    rel: str
    ro_mounts: tuple[tuple[Path, Path], ...] = ()  # --ro-bind src dest
    self_binds: tuple[tuple[Path, Path], ...] = ()  # --bind src dest (pin parents)
    watch: Path | None = None  # component to check after the session
    watch_before: Identity | None = None


def analyse(base: Path, rel: str, dest_base: Path | None = None) -> Protection:
    """Analyse `rel` under host directory `base`, which appears in the
    sandbox at `dest_base` (default: the same path)."""
    dest_base = base if dest_base is None else dest_base
    parts = rel.split("/")
    cur = base
    pins: list[tuple[Path, Path]] = []
    for i, name in enumerate(parts):
        cur = cur / name
        ident = Identity.of(cur)
        last = i == len(parts) - 1
        if not ident.exists or ident.fmt == stat.S_IFLNK:
            return Protection(rel, (), tuple(pins), cur, ident)
        if last or ident.fmt != stat.S_IFDIR:
            # Final component, or a non-directory that the rest of the
            # path can't live under: freeze it.
            return Protection(rel, ((cur, dest_base / "/".join(parts[: i + 1])),), tuple(pins))
        pins.append((cur, dest_base / "/".join(parts[: i + 1])))
    raise AssertionError("unreachable")


def _quarantine_name(path: Path, stamp: str) -> Path:
    cand = path.with_name(f"{path.name}.devenv-quarantine-{stamp}")
    n = 1
    while os.path.lexists(cand):
        n += 1
        cand = path.with_name(f"{path.name}.devenv-quarantine-{stamp}-{n}")
    return cand


def check_after(protections: list[Protection], *, now: float | None = None) -> list[str]:
    """Quarantine watched paths that changed. Returns human-readable notes."""
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
    notes = []
    seen: set[Path] = set()
    for p in protections:
        if p.watch is None or p.watch in seen:
            continue
        seen.add(p.watch)
        after = Identity.of(p.watch)
        if after == p.watch_before or not after.exists:
            continue
        dest = _quarantine_name(p.watch, stamp)
        try:
            os.rename(p.watch, dest)  # renames a symlink itself, never its target
        except OSError as e:
            notes.append(
                f"DANGER: {p.watch} was created or changed in the sandbox and "
                f"could not be quarantined ({e}). Inspect it before running "
                "anything in that directory."
            )
            continue
        notes.append(
            f"quarantined {p.watch} -> {dest.name} (created or changed by the "
            f"sandbox; protected path {p.rel!r}). Review it before restoring."
        )
    return notes
