"""Load and validate the TOML policy file.

The config *is* the security policy, so it is strict: unknown keys, wrong
types and unsafe paths are errors, never silently replaced by defaults.
"""

import functools
import os
import tomllib
from dataclasses import dataclass, field, fields
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any

from devenv import APP, devenvError

type Table = dict[str, Any]
"""A parsed TOML table."""

type Paths = tuple[str, ...]
"""Normalised relative paths (no leading ``/``, no ``..``)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class HomeConfig:
    """Which parts of ``$HOME`` the sandbox sees. Paths are relative to ``$HOME``."""

    ro: Paths = ()
    """Mounted read-only."""
    rw: Paths = ()
    """Mounted read-write; changes persist on the host."""
    ephemeral: Paths = ()
    """Files copied in; the sandbox's changes are discarded at exit."""
    protect: Paths = ()
    """Paths inside ``rw`` entries that are kept read-only or quarantined."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ProjectConfig:
    """Policy for the project directory (where devenv is started)."""

    protect: Paths = ()
    """Paths relative to the project that are kept read-only or quarantined."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Config:
    """The complete, validated configuration."""

    bwrap_path: str = "bwrap"
    """bwrap executable, looked up on ``PATH`` unless absolute."""
    command: tuple[str, ...] = ("bash",)
    """Default command run inside the sandbox."""
    network: bool = True
    """Whether the sandbox shares the host network."""
    bwrap_extra_args: tuple[str, ...] = ()
    """Extra bwrap arguments, applied before devenv's protections."""
    env_allow: tuple[str, ...] = ()
    """Host environment variables copied into the otherwise empty environment."""
    home: HomeConfig = field(default_factory=HomeConfig)
    """The ``[home]`` table."""
    project: ProjectConfig = field(default_factory=ProjectConfig)
    """The ``[project]`` table."""


def default_text() -> str:
    """Return the commented default config shipped with the package."""
    return resources.files(APP).joinpath("defaults.toml").read_text("utf-8")


def default_path() -> Path:
    """Return the user's config path, honouring ``$XDG_CONFIG_HOME``."""
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / APP / "config.toml"


def normalise(path: str, where: str) -> str:
    """Return ``path`` as a clean relative path, or raise devenvError.

    Rejects absolute paths, ``..``, NUL bytes and paths naming the base
    directory itself, so an entry can never point outside its base.
    """
    if not path or "\x00" in path:
        raise devenvError(f"{where}: invalid path {path!r}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or pure == PurePosixPath():
        raise devenvError(f"{where}: {path!r} must be a relative path inside the base directory")
    return pure.as_posix()


def _check_keys(table: Table, cls: type, where: str) -> None:
    """Reject keys in ``table`` that are not fields of dataclass ``cls``."""
    if unknown := table.keys() - {f.name for f in fields(cls)}:
        raise devenvError(f"unknown key {where}{min(unknown)}")


def _table(data: Table, key: str) -> Table:
    """Return sub-table ``key`` of ``data`` (empty if absent)."""
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise devenvError(f"[{key}] must be a table")
    return value


def _get[T: (str, bool)](table: Table, key: str, default: T) -> T:
    """Return scalar ``table[key]`` if present, checking it has ``default``'s type."""
    value = table.get(key, default)
    if type(value) is not type(default):
        raise devenvError(f"{key}: expected {type(default).__name__}")
    return value


def _strings(table: Table, key: str, default: tuple[str, ...], where: str) -> tuple[str, ...]:
    """Return ``table[key]`` as a tuple of strings, or ``default`` if absent."""
    if key not in table:
        return default
    value = table[key]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise devenvError(f"{where}{key}: expected a list of strings")
    return tuple(value)


def _paths(table: Table, key: str, default: Paths, where: str) -> Paths:
    """Like :func:`_strings`, normalising every entry with :func:`normalise`."""
    return tuple(normalise(p, f"{where}{key}") for p in _strings(table, key, default, where))


def _validate(cfg: Config) -> Config:
    """Check rules that span several fields; return ``cfg`` unchanged."""
    if not cfg.command or not cfg.bwrap_path:
        raise devenvError("command and bwrap_path must not be empty")
    for name in cfg.env_allow:
        if not name or "=" in name or "\x00" in name:
            raise devenvError(f"env_allow: invalid variable name {name!r}")
    home = cfg.home
    mounted = [*home.ro, *home.rw, *home.ephemeral]
    if dupes := {p for p in mounted if mounted.count(p) > 1}:
        raise devenvError(f"[home]: listed more than once: {sorted(dupes)}")
    for rw in home.rw:
        for path in mounted:
            if path != rw and PurePosixPath(path).is_relative_to(rw):
                # devenv would follow symlinks the agent can plant inside rw.
                raise devenvError(
                    f"[home]: {path!r} is inside writable {rw!r}; "
                    "use home.protect to keep part of it read-only"
                )
    return cfg


def parse(text: str, base: Config) -> Config:
    """Parse TOML ``text``; keys it sets replace those of ``base``."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise devenvError(f"invalid TOML: {e}") from e
    home_t, project_t = _table(data, "home"), _table(data, "project")
    _check_keys(data, Config, "")
    _check_keys(home_t, HomeConfig, "home.")
    _check_keys(project_t, ProjectConfig, "project.")
    h = base.home
    return _validate(
        Config(
            bwrap_path=_get(data, "bwrap_path", base.bwrap_path),
            command=_strings(data, "command", base.command, ""),
            network=_get(data, "network", base.network),
            bwrap_extra_args=_strings(data, "bwrap_extra_args", base.bwrap_extra_args, ""),
            env_allow=_strings(data, "env_allow", base.env_allow, ""),
            home=HomeConfig(
                ro=_paths(home_t, "ro", h.ro, "home."),
                rw=_paths(home_t, "rw", h.rw, "home."),
                ephemeral=_paths(home_t, "ephemeral", h.ephemeral, "home."),
                protect=_paths(home_t, "protect", h.protect, "home."),
            ),
            project=ProjectConfig(
                protect=_paths(project_t, "protect", base.project.protect, "project."),
            ),
        )
    )


@functools.cache
def defaults() -> Config:
    """Return the built-in default configuration."""
    return parse(default_text(), Config())


def load(path: Path, *, explicit: bool) -> Config:
    """Load ``path`` on top of the defaults.

    A missing file means "use the defaults", unless the user named it
    (``explicit``), in which case it is an error.
    """
    try:
        text = path.read_text("utf-8")
    except FileNotFoundError:
        if explicit:
            raise devenvError(f"{path}: file not found") from None
        return defaults()
    except OSError as e:
        raise devenvError(f"{path}: {e.strerror}") from e
    try:
        return parse(text, defaults())
    except devenvError as e:
        raise devenvError(f"{path}: {e}") from e
