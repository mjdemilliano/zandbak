"""Turn a :class:`Request` into a bwrap command line (a :class:`Plan`).

This module only reads the filesystem; it never changes it or starts
processes, so it can be tested without bwrap. Mount order matters: later
bwrap mounts cover earlier ones. :func:`build` therefore goes from broad to
specific and ends with the protections, so nothing can cover them.
"""

import os
import platform
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath

from devenv import APP, devenvError, protect, seccomp
from devenv.config import Config, HomeConfig

RC_PATH = f"/tmp/{APP}-rc.sh"  # noqa: S108 - inside the sandbox's private /tmp
"""Where the bash prompt script is written inside the sandbox."""

BASH_RC = "PS1='[\\[\\e[36m\\]🫧\\[\\e[0m\\]] \\w > '\n".encode()
"""Bash startup script giving the sandbox shell a recognisable prompt."""

PRIVATE_DIRS = ("/dev/shm", "/tmp", "/var/tmp", "/run")  # noqa: S108 - fresh, private tmpfs
"""Mounted as empty tmpfs (after ``/dev``), hiding the host's shared memory and sockets."""

HOST_EXEC = frozenset(
    {
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".config/fish",
        ".config/autostart",
        ".config/systemd",
        ".config/environment.d",
        ".local/bin",
        ".local/share/applications",
        ".cargo",
        ".gitconfig",
        ".config/git",
        ".npmrc",
        ".pam_environment",
        ".xprofile",
        ".xinitrc",
        ".ssh",
        ".gnupg",
    }
)
"""Home paths whose writers can make the host run code; writable mounts warn."""

SECRETS = frozenset(
    {
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".netrc",
        ".git-credentials",
        ".config/gh",
        ".password-store",
        ".Xauthority",
        ".pki",
        ".local/share/keyrings",
        ".mozilla",
        ".config/google-chrome",
        ".config/chromium",
        ".vault-token",
        ".pypirc",
    }
)
"""Home paths that usually hold credentials; any mount warns."""


class Access(StrEnum):
    """How a ``[home]`` entry is exposed."""

    RO = "ro"
    """Read-only bind mount."""
    RW = "rw"
    """Read-write bind mount."""
    EPHEMERAL = "ephemeral"
    """Private copy, discarded at exit."""


@dataclass(frozen=True, slots=True)
class FdRef:
    """Placeholder in :attr:`Plan.argv` for a file descriptor opened at launch."""

    index: int
    """Position in :attr:`Plan.fds`."""


type FdSource = bytes | Path
"""Content for a descriptor: bytes (served from a memfd) or a host file (opened read-only)."""

type Arg = str | FdRef
"""One bwrap argument."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Request:
    """Everything :func:`build` needs, gathered by the CLI."""

    config: Config
    """The validated policy."""
    home: Path
    """The user's home directory."""
    cwd: Path
    """Where devenv was started; becomes the project directory."""
    environ: Mapping[str, str]
    """The host environment, filtered through ``env_allow``."""
    command: tuple[str, ...]
    """Program and arguments to run in the sandbox."""
    ro_dirs: tuple[str, ...] = ()
    """``--ro-dir`` arguments as given (relative to ``cwd``)."""
    network: bool = True
    """Share the host network."""
    allow_git_writes: bool = False
    """Skip the project's ``.git`` protections."""
    landlock: bool = False
    """Landlock scoping is usable (see :func:`devenv.landlock.usable`)."""
    machine: str = field(default_factory=platform.machine)
    """CPU architecture, for the seccomp filter."""
    self_paths: tuple[Path, ...] = ()
    """devenv's code, config, Python and bwrap: these must stay out of the agent's reach."""
    interactive: bool = True
    """stdin is a terminal, so run the command under an interactive shell."""


@dataclass(slots=True)
class Plan:
    """The result: bwrap arguments plus what the launcher must prepare and check."""

    argv: list[Arg] = field(default_factory=list)
    """bwrap arguments, excluding the bwrap path."""
    fds: list[FdSource] = field(default_factory=list)
    """Descriptors to open and pass; referenced from :attr:`argv` by :class:`FdRef`."""
    protections: list[protect.Protection] = field(default_factory=list)
    """Protected paths, for the post-session :func:`devenv.protect.quarantine`."""
    warnings: list[str] = field(default_factory=list)
    """Messages to show before starting."""
    landlock: bool = False
    """Apply Landlock scoping when launching."""

    def fd(self, source: FdSource) -> FdRef:
        """Register ``source`` to be opened at launch; return its placeholder."""
        self.fds.append(source)
        return FdRef(len(self.fds) - 1)


def _overlaps(a: str, b: str) -> bool:
    """Return whether relative path ``a`` equals, contains or is inside ``b``."""
    pa, pb = PurePosixPath(a), PurePosixPath(b)
    return pa.is_relative_to(pb) or pb.is_relative_to(pa)


def _in_dot_dir(path: Path, home: Path) -> str | None:
    """Return the ``~/.name`` directory containing ``path``, if any."""
    if path.is_relative_to(home) and path != home:
        top = path.relative_to(home).parts[0]
        return top if top.startswith(".") else None
    return None


def check_project(project: Path, home: Path) -> None:
    """Refuse project directories that would expose home or its dot-directories."""
    if home.is_relative_to(project):
        raise devenvError(
            f"refusing to use {project} as the project directory: it contains your home "
            "directory, which would become writable. Run devenv inside a project folder."
        )
    if top := _in_dot_dir(project, home):
        raise devenvError(
            f"refusing to use {project} as the project directory: it is inside ~/{top}, "
            "and dot-directories are governed by the [home] allowlist."
        )


def resolve_ro_dir(given: str, project: Path, home: Path) -> Path:
    """Resolve a ``--ro-dir`` argument, refusing paths that would weaken the sandbox.

    Relative paths are taken from the (resolved) project directory.
    """
    lexical = Path(os.path.normpath(project / given))  # collapse "..", don't follow links
    try:
        real = lexical.resolve(strict=True)
    except OSError as e:
        raise devenvError(f"--ro-dir {given}: {e.strerror}") from None
    if home.is_relative_to(real):
        raise devenvError(f"--ro-dir {given}: {real} contains your home directory")
    if top := _in_dot_dir(real, home):
        raise devenvError(f"--ro-dir {given}: {real} is inside ~/{top}; use [home] instead")
    if lexical.is_relative_to(project) and not real.is_relative_to(project):
        # Inside the agent-writable project but leading out of it: probably a
        # symlink the agent planted in an earlier session.
        raise devenvError(
            f"--ro-dir {given}: lies inside the project but resolves to {real} "
            "via a symlink; pass the real path if you mean it"
        )
    if real.is_relative_to(project):
        raise devenvError(f"--ro-dir {given}: already visible as part of the project")
    return real


def _namespace_args(*, network: bool) -> list[Arg]:
    """Namespaces and privileges: new everything, no capabilities."""
    return [
        "--unshare-all",
        *(["--share-net"] if network else []),
        "--die-with-parent",
        "--cap-drop",
        "ALL",
    ]


def _env_args(allow: tuple[str, ...], environ: Mapping[str, str], home: Path) -> list[Arg]:
    """Start from an empty environment and copy only allowlisted variables."""
    args: list[Arg] = ["--clearenv"]
    for key in allow:
        if key != "HOME" and key in environ:
            args += ["--setenv", key, environ[key]]
    return [*args, "--setenv", "HOME", str(home), "--setenv", f"{APP.upper()}_SANDBOX", "1"]


def _system_args() -> list[Arg]:
    """Read-only OS, private scratch filesystems, and DNS configuration."""
    args: list[Arg] = ["--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc"]
    for name in ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"):
        path = Path(name)
        if path.is_symlink():
            args += ["--symlink", str(path.readlink()), name]
        elif path.is_dir():
            args += ["--ro-bind", name, name]
    args += ["--ro-bind-try", "/opt", "/opt", "--ro-bind-try", "/sys", "/sys"]
    args += ["--dev", "/dev", "--proc", "/proc"]
    for scratch in PRIVATE_DIRS:
        args += ["--tmpfs", scratch]
    # /etc/resolv.conf often points into /run, which was just hidden.
    resolv = Path("/etc/resolv.conf").resolve()
    if resolv.is_relative_to("/run") and resolv.is_file():
        args += ["--ro-bind", str(resolv), str(resolv)]
    if Path("/run/systemd/resolve").is_dir():
        args += ["--ro-bind", "/run/systemd/resolve", "/run/systemd/resolve"]
    return args


def _home_warnings(rel: str, access: Access) -> list[str]:
    """Warnings for mounting ``~/rel`` with ``access``."""
    notes = []
    if access is Access.RW and any(_overlaps(rel, p) for p in HOST_EXEC):
        notes.append(f"~/{rel} is writable: the agent can plant code your host runs later")
    if any(_overlaps(rel, p) for p in SECRETS):
        notes.append(f"~/{rel} may contain credentials and is visible to the agent")
    return notes


def _mount_home(plan: Plan, cfg: HomeConfig, home: Path) -> dict[str, Access]:
    """Mount an empty home plus the allowlist; return what was mounted, by path."""
    entries = [(rel, Access.RO) for rel in cfg.ro]
    entries += [(rel, Access.RW) for rel in cfg.rw]
    entries += [(rel, Access.EPHEMERAL) for rel in cfg.ephemeral]
    entries.sort(key=lambda e: e[0].count("/"))  # parents before children
    plan.argv += ["--tmpfs", str(home)]
    mounted: dict[str, Access] = {}
    for rel, access in entries:
        host = home / rel
        if not host.exists(follow_symlinks=False):
            continue
        real = host.resolve()
        if home.is_relative_to(real):
            raise devenvError(f"~/{rel} resolves to {real}, which would expose your whole home")
        plan.warnings += _home_warnings(rel, access)
        match access:
            case Access.RO:
                plan.argv += ["--ro-bind", str(real), str(host)]
            case Access.RW:
                plan.argv += ["--bind", str(real), str(host)]
            case Access.EPHEMERAL:
                if not real.is_file():
                    raise devenvError(f"home.ephemeral entry ~/{rel} must be a regular file")
                plan.argv += ["--file", plan.fd(real), str(host)]
        mounted[rel] = access
    return mounted


def _mount_project(plan: Plan, req: Request, project: Path, home: Path) -> None:
    """Mount the project read-write and the ``--ro-dir`` folders read-only.

    ``--ro-dir`` folders containing the project go first, so the project's
    read-write mount lands on top of them.
    """
    ro_dirs = [resolve_ro_dir(d, project, home) for d in req.ro_dirs]
    outer = sorted((d for d in ro_dirs if project.is_relative_to(d)), key=lambda d: len(d.parts))
    for d in outer:
        plan.argv += ["--ro-bind", str(d), str(d)]
    plan.argv += ["--bind", str(project), str(project)]
    for d in ro_dirs:
        if d not in outer:
            plan.argv += ["--ro-bind", str(d), str(d)]


def _check_self(self_paths: tuple[Path, ...], writable: list[Path]) -> None:
    """Refuse to run if the agent could modify devenv itself.

    Otherwise it could disable the protections for the next run. A config
    file that doesn't exist yet counts too: the agent could create it.
    """
    for path in self_paths:
        real = path.resolve()
        for area in writable:
            if real.is_relative_to(area):
                raise devenvError(
                    f"{path} would be writable inside the sandbox (via {area}); the agent "
                    "could disable devenv's protections. Keep devenv, its config, "
                    "Python and bwrap outside writable paths."
                )


def _covering(rel: str, mounted: dict[str, Access]) -> str | None:
    """Return the deepest mounted home entry containing ``rel``, if it is writable."""
    covers = [m for m in mounted if PurePosixPath(rel).is_relative_to(m)]
    best = max(covers, key=len, default=None)
    return best if best is not None and mounted[best] is Access.RW else None


def _protect(
    plan: Plan, req: Request, project: Path, home: Path, mounted: dict[str, Access]
) -> None:
    """Analyse and mount protected paths. Must be the last mounts."""
    for rel in req.config.home.protect:
        top = _covering(rel, mounted)
        if top is None or top == rel:
            continue  # not writable, or a whole entry (make it ro instead)
        base = home / top
        plan.protections.append(
            protect.analyse(base.resolve(), str(PurePosixPath(rel).relative_to(top)), base)
        )
    for rel in req.config.project.protect:
        if not (req.allow_git_writes and PurePosixPath(rel).is_relative_to(".git")):
            plan.protections.append(protect.analyse(project, rel))
    pins = dict.fromkeys(pin for p in plan.protections for pin in p.pins)  # ordered, unique
    for src, dest in pins:
        plan.argv += ["--bind", str(src), str(dest)]
    for src, dest in (ro for p in plan.protections for ro in p.ro):
        plan.argv += ["--ro-bind", str(src), str(dest)]


def _terminal_args(plan: Plan, machine: str) -> list[Arg]:
    """Block terminal injection with seccomp, or fall back to a new session."""
    if seccomp.supported(machine):
        return ["--seccomp", plan.fd(seccomp.build_filter(machine))]
    plan.warnings.append(
        f"no seccomp filter for {machine}; using --new-session (Ctrl-C ends the sandbox)"
    )
    return ["--new-session"]


def _command_args(plan: Plan, command: tuple[str, ...], *, interactive: bool) -> list[Arg]:
    """Arguments that start ``command``, after a ``--`` that ends bwrap's options.

    Commands run under bash (some agents, such as goose, need a parent that
    stays alive) with arguments passed as positional parameters, so the shell
    never re-parses them.
    """
    if command == ("bash",):
        return ["--file", plan.fd(BASH_RC), RC_PATH, "--", "bash", "--rcfile", RC_PATH, "-i"]
    flags = ["-i"] if interactive else []
    return ["--", "bash", *flags, "-c", '"$@"', APP, *command]


def build(req: Request) -> Plan:
    """Build the bwrap command line for ``req``."""
    home, project = req.home.resolve(), req.cwd.resolve()
    check_project(project, home)
    cfg = req.config
    plan = Plan(landlock=req.landlock and req.network)
    plan.argv += _namespace_args(network=req.network)
    plan.argv += _env_args(cfg.env_allow, req.environ, home)
    plan.argv += _system_args()
    mounted = _mount_home(plan, cfg.home, home)
    _mount_project(plan, req, project, home)
    writable = [project, *((home / r).resolve() for r, a in mounted.items() if a is Access.RW)]
    _check_self(req.self_paths, writable)
    plan.argv += cfg.bwrap_extra_args
    _protect(plan, req, project, home, mounted)
    plan.argv += _terminal_args(plan, req.machine)
    if req.network and not req.landlock:
        plan.warnings.append(
            "Landlock ABI 6 (Linux 6.12+) unavailable: the agent can reach host abstract "
            "sockets such as the X11 display. Use --no-network for untrusted work."
        )
    plan.argv += ["--chdir", str(project)]
    plan.argv += _command_args(plan, req.command, interactive=req.interactive)
    return plan
