"""Configuration loading and validation."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path, PurePosixPath


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    bwrap_path: str = "bwrap"
    command: tuple[str, ...] = ("bash",)
    network: bool = True
    bwrap_extra_args: tuple[str, ...] = ()
    env_allow: tuple[str, ...] = ()
    home_ro: tuple[str, ...] = ()
    home_rw: tuple[str, ...] = ()
    home_ephemeral: tuple[str, ...] = ()
    home_protect: tuple[str, ...] = ()
    project_protect: tuple[str, ...] = field(default_factory=tuple)


# Schema: top-level key -> (section, attribute, type)
_TOP = {
    "bwrap_path": ("bwrap_path", str),
    "command": ("command", list),
    "network": ("network", bool),
    "bwrap_extra_args": ("bwrap_extra_args", list),
    "env_allow": ("env_allow", list),
}
_HOME = {
    "ro": "home_ro",
    "rw": "home_rw",
    "ephemeral": "home_ephemeral",
    "protect": "home_protect",
}
_PROJECT = {"protect": "project_protect"}


def default_config_text() -> str:
    return resources.files("devenv").joinpath("defaults.toml").read_text("utf-8")


def default_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return Path(base) / "devenv" / "config.toml"


def validate_rel_path(p: str, where: str) -> str:
    """Return a normalised relative path, or raise ConfigError.

    Rejects absolute paths, '..', empty components and anything that would
    resolve to the base directory itself.
    """
    if not isinstance(p, str) or not p:
        raise ConfigError(f"{where}: paths must be non-empty strings")
    if "\x00" in p:
        raise ConfigError(f"{where}: {p!r} contains a NUL byte")
    pp = PurePosixPath(p)
    if pp.is_absolute():
        raise ConfigError(f"{where}: {p!r} must be relative")
    parts = [x for x in pp.parts if x != "."]
    if not parts:
        raise ConfigError(f"{where}: {p!r} refers to the base directory itself")
    if ".." in parts:
        raise ConfigError(f"{where}: {p!r} must not contain '..'")
    return "/".join(parts)


def _str_list(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ConfigError(f"{where}: expected a list of strings")
    return tuple(value)


def _apply(data: dict, values: dict) -> None:
    for key, val in data.items():
        if key == "home":
            if not isinstance(val, dict):
                raise ConfigError("[home] must be a table")
            for k, v in val.items():
                if k not in _HOME:
                    raise ConfigError(f"unknown key home.{k}")
                values[_HOME[k]] = _str_list(v, f"home.{k}")
        elif key == "project":
            if not isinstance(val, dict):
                raise ConfigError("[project] must be a table")
            for k, v in val.items():
                if k not in _PROJECT:
                    raise ConfigError(f"unknown key project.{k}")
                values[_PROJECT[k]] = _str_list(v, f"project.{k}")
        elif key in _TOP:
            attr, typ = _TOP[key]
            if typ is list:
                values[attr] = _str_list(val, key)
            elif not isinstance(val, typ):
                raise ConfigError(f"{key}: expected {typ.__name__}")
            else:
                values[attr] = val
        else:
            # Unknown keys are errors: a typo in a security setting must not
            # silently fall back to something else.
            raise ConfigError(f"unknown key {key}")


def _finalise(values: dict) -> Config:
    for attr in ("home_ro", "home_rw", "home_ephemeral", "home_protect"):
        values[attr] = tuple(
            validate_rel_path(p, attr.replace("_", ".", 1)) for p in values[attr]
        )
    values["project_protect"] = tuple(
        validate_rel_path(p, "project.protect") for p in values["project_protect"]
    )
    if not values["command"]:
        raise ConfigError("command must not be empty")
    if not values["bwrap_path"]:
        raise ConfigError("bwrap_path must not be empty")
    for name in values["env_allow"]:
        if not name or "=" in name or "\x00" in name:
            raise ConfigError(f"env_allow: invalid variable name {name!r}")
    mounted = values["home_ro"] + values["home_rw"] + values["home_ephemeral"]
    dupes = {p for p in mounted if mounted.count(p) > 1}
    if dupes:
        raise ConfigError(f"[home]: listed more than once: {sorted(dupes)}")
    return Config(**values)


def parse(text: str, base: Config | None = None) -> Config:
    """Parse TOML text on top of `base` (defaults if None)."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"invalid TOML: {e}") from e
    values = dict(vars(base)) if base is not None else dict(vars(Config()))
    _apply(data, values)
    return _finalise(values)


def defaults() -> Config:
    return parse(default_config_text(), base=Config())


def load(path: Path | None, *, explicit: bool = False) -> Config:
    """Load the config file at `path` on top of the defaults.

    A missing file is fine unless the user named it explicitly.
    """
    base = defaults()
    if path is None:
        return base
    try:
        text = path.read_text("utf-8")
    except FileNotFoundError:
        if explicit:
            raise ConfigError(f"{path}: file not found") from None
        return base
    except OSError as e:
        raise ConfigError(f"{path}: {e}") from e
    try:
        return parse(text, base=base)
    except ConfigError as e:
        raise ConfigError(f"{path}: {e}") from e
