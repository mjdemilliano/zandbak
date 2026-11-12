"""Turn a Config plus the current situation into a bwrap command line.

Everything here is pure (it only reads the filesystem), so it can be tested
without running bwrap.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from . import protect, seccomp
from .config import Config


class PlanError(Exception):
    pass


@dataclass(frozen=True)
class FdRef:
    """Placeholder for a file descriptor opened at launch time."""

    index: int


@dataclass(frozen=True)
class FdSource:
    data: bytes | None = None  # in-memory content (memfd)
    path: Path | None = None  # host file to open read-only


@dataclass
class Plan:
    argv: list = field(default_factory=list)  # str | FdRef
    fds: list[FdSource] = field(default_factory=list)
    protections: list[protect.Protection] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    landlock: bool = False

    def fd(self, src: FdSource) -> FdRef:
        self.fds.append(src)
        return FdRef(len(self.fds) - 1)


RC_PATH = "/tmp/devenv-rc.sh"
BASH_RC = b"PS1='[\\[\\e[36m\\]\xf0\x9f\xab\xa7\\[\\e[0m\\]] \\w > '\n"

# Paths that let whoever can write them run code on the host or that hold
# credentials. Mounting them gets a warning (they are allowed: the user is
# in charge of the allowlist).
HOST_EXEC = (
    ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc",
    ".zprofile", ".zshenv", ".config/fish", ".config/autostart",
    ".config/systemd", ".config/environment.d", ".local/bin", ".cargo",
    ".gitconfig", ".config/git", ".npmrc", ".pam_environment", ".xprofile",
    ".xinitrc", ".ssh", ".gnupg", ".local/share/applications",
)
SECRETS = (
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".netrc",
    ".git-credentials", ".config/gh", ".password-store", ".Xauthority",
    ".pki", ".local/share/keyrings", ".mozilla", ".config/google-chrome",
    ".config/chromium", ".vault-token", ".pypirc",
)


def _overlaps(a: str, b: str) -> bool:
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def _is_within(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def check_project(project: Path, home: Path) -> None:
    if project == Path("/"):
        raise PlanError("refusing to use / as the project directory")
    if _is_within(home, project):
        raise PlanError(
            f"refusing to use {project} as the project directory: it contains "
            "your home directory, which would expose everything in it read-write. "
            "Run devenv from inside a project folder."
        )
    if _is_within(project, home):
        top = project.relative_to(home).parts[0]
        if top.startswith("."):
            raise PlanError(
                f"refusing to use {project} as the project directory: it is "
                f"inside ~/{top}, and dot-directories are controlled by the "
                "[home] allowlist."
            )


def resolve_ro_dir(given: str, cwd: Path, project: Path, home: Path) -> Path:
    lexical = Path(os.path.normpath(cwd / given))
    try:
        real = Path(os.path.realpath(lexical, strict=True))
    except OSError as e:
        raise PlanError(f"--ro-dir {given}: {e.strerror or e}") from None
    if real == Path("/") or _is_within(home, real):
        raise PlanError(f"--ro-dir {given}: {real} contains your home directory")
    if _is_within(real, home):
        top = real.relative_to(home).parts[0]
        if top.startswith("."):
            raise PlanError(
                f"--ro-dir {given}: {real} is inside ~/{top}; use the [home] "
                "allowlist for dot-directories"
            )
    if _is_within(lexical, project) and not _is_within(real, project):
        # A path inside the (agent-writable) project that leads outside it is
        # probably a symlink the agent planted in an earlier session.
        raise PlanError(
            f"--ro-dir {given}: lies inside the project but resolves to {real} "
            "outside it (via a symlink); pass the real path if you mean it"
        )
    if _is_within(real, project):
        raise PlanError(f"--ro-dir {given}: already visible as part of the project")
    return real


def _system_mounts() -> list[str]:
    args: list[str] = []
    for p in ("/usr", "/etc"):
        args += ["--ro-bind", p, p]
    for p in ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"):
        if os.path.islink(p):
            args += ["--symlink", os.readlink(p), p]
        elif os.path.isdir(p):
            args += ["--ro-bind", p, p]
    for p in ("/opt", "/sys"):
        args += ["--ro-bind-try", p, p]
    args += [
        "--dev", "/dev",
        "--tmpfs", "/dev/shm",  # private: not the host's shared memory
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/var/tmp",
        "--tmpfs", "/run",
    ]
    # DNS: /etc/resolv.conf often points into /run, which we just hid.
    resolv = Path(os.path.realpath("/etc/resolv.conf"))
    if resolv.parts[:2] == ("/", "run") and resolv.is_file():
        args += ["--ro-bind", str(resolv), str(resolv)]
    if os.path.isdir("/run/systemd/resolve"):
        args += ["--ro-bind", "/run/systemd/resolve", "/run/systemd/resolve"]
    return args


def _home_entries(cfg: Config) -> list[tuple[str, str]]:
    """(mode, rel) sorted so parents are mounted before children."""
    entries = (
        [("ro", r) for r in cfg.home_ro]
        + [("rw", r) for r in cfg.home_rw]
        + [("ephemeral", r) for r in cfg.home_ephemeral]
    )
    for mode, rel in entries:
        if mode == "rw":
            continue
        for rw in cfg.home_rw:
            if rel.startswith(rw + "/"):
                # devenv would follow host symlinks the agent can plant there.
                raise PlanError(
                    f"home.{mode} entry {rel!r} is inside writable {rw!r}; "
                    "use home.protect to make part of it read-only"
                )
    for rel in cfg.home_rw:
        for other in cfg.home_rw:
            if rel != other and rel.startswith(other + "/"):
                raise PlanError(f"home.rw entry {rel!r} is already inside {other!r}")
    return sorted(entries, key=lambda e: e[1].count("/"))


def _warn_home(mode: str, rel: str, warnings: list[str]) -> None:
    if mode == "rw" and any(_overlaps(rel, h) for h in HOST_EXEC):
        warnings.append(
            f"~/{rel} is writable: the agent can plant code your host runs later"
        )
    if any(_overlaps(rel, s) for s in SECRETS):
        warnings.append(f"~/{rel} may contain credentials and is visible to the agent")


def _covering_mode(rel: str, mounted: dict[str, str]) -> tuple[str, str] | None:
    best = None
    for m_rel, mode in mounted.items():
        if rel == m_rel or rel.startswith(m_rel + "/"):
            if best is None or len(m_rel) > len(best[0]):
                best = (m_rel, mode)
    return best


def build(
    cfg: Config,
    *,
    home: str,
    cwd: str,
    environ: dict[str, str],
    command: list[str],
    ro_dirs: list[str] = (),
    network: bool | None = None,
    allow_git_writes: bool = False,
    landlock_ok: bool = False,
    machine: str | None = None,
    self_paths: list[str] = (),
    interactive: bool = True,
) -> Plan:
    plan = Plan()
    home_p = Path(os.path.realpath(home))
    cwd_p = Path(os.path.realpath(cwd))
    project = cwd_p
    check_project(project, home_p)
    if network is None:
        network = cfg.network

    a = plan.argv
    a += ["--unshare-all"]
    if network:
        a += ["--share-net"]
    a += ["--die-with-parent", "--cap-drop", "ALL"]

    # Environment: start empty, copy the allowlist.
    a += ["--clearenv"]
    for key in cfg.env_allow:
        if key == "HOME":
            continue
        if key in environ:
            a += ["--setenv", key, environ[key]]
    a += ["--setenv", "HOME", str(home_p), "--setenv", "devenv_SANDBOX", "1"]

    a += _system_mounts()

    # Home: empty tmpfs plus allowlisted entries.
    a += ["--tmpfs", str(home_p)]
    mounted: dict[str, str] = {}
    for mode, rel in _home_entries(cfg):
        host = home_p / rel
        if not os.path.lexists(host):
            continue
        real = Path(os.path.realpath(host))
        if real == Path("/") or _is_within(home_p, real):
            raise PlanError(
                f"home.{mode} entry ~/{rel} resolves to {real}, which would "
                "expose your whole home directory"
            )
        _warn_home(mode, rel, plan.warnings)
        dest = str(home_p / rel)
        if mode == "ro":
            a += ["--ro-bind", str(real), dest]
        elif mode == "rw":
            a += ["--bind", str(real), dest]
        else:
            if not real.is_file():
                raise PlanError(f"home.ephemeral entry ~/{rel} must be a regular file")
            a += ["--file", plan.fd(FdSource(path=real)), dest]
        mounted[rel] = mode

    # Extra read-only directories. Those containing the project go first so
    # the project's read-write mount lands on top of them.
    ro_real = [resolve_ro_dir(d, cwd_p, project, home_p) for d in ro_dirs]
    outer = [d for d in ro_real if _is_within(project, d)]
    others = [d for d in ro_real if d not in outer]
    for d in sorted(outer, key=lambda p: len(p.parts)):
        a += ["--ro-bind", str(d), str(d)]
    a += ["--bind", str(project), str(project)]
    for d in others:
        a += ["--ro-bind", str(d), str(d)]

    # The agent must not be able to change devenv itself (its config, code,
    # interpreter or bwrap), or the next run would be unprotected. A config
    # file that doesn't exist yet counts too: the agent could create it.
    writable = [project] + [
        Path(os.path.realpath(home_p / rel)) for rel, m in mounted.items() if m == "rw"
    ]
    for sp in self_paths:
        real = Path(os.path.realpath(sp))
        for w in writable:
            if _is_within(real, w):
                raise PlanError(
                    f"{sp} would be writable inside the sandbox (via {w}); the "
                    "agent could disable devenv's protections for the next run. "
                    "Keep devenv, its config, Python and bwrap outside writable paths."
                )

    a += list(cfg.bwrap_extra_args)

    # Protections come last so nothing above can cover them.
    for rel in cfg.home_protect:
        cover = _covering_mode(rel, mounted)
        if cover is None or cover[1] != "rw":
            continue  # not mounted, or already read-only / ephemeral
        cover_rel = cover[0]
        rest = rel[len(cover_rel) + 1 :]
        if not rest:
            continue  # protecting a whole rw entry: mount it ro instead
        host_base = Path(os.path.realpath(home_p / cover_rel))
        plan.protections.append(
            protect.analyse(host_base, rest, dest_base=home_p / cover_rel)
        )
    for rel in cfg.project_protect:
        if allow_git_writes and (rel == ".git" or rel.startswith(".git/")):
            continue
        plan.protections.append(protect.analyse(project, rel))
    pinned: set[Path] = set()
    for prot in plan.protections:
        for src, dest in prot.self_binds:
            if dest not in pinned:
                pinned.add(dest)
                a += ["--bind", str(src), str(dest)]
    for prot in plan.protections:
        for src, dest in prot.ro_mounts:
            a += ["--ro-bind", str(src), str(dest)]

    # Terminal injection: seccomp filter, or a new session as a fallback.
    if seccomp.supported(machine):
        a += ["--seccomp", plan.fd(FdSource(data=seccomp.build_filter(machine)))]
    else:
        a += ["--new-session"]
        plan.warnings.append(
            "no seccomp filter for this CPU architecture; using --new-session "
            "(Ctrl-C ends the whole sandbox)"
        )

    plan.landlock = landlock_ok and network
    if network and not landlock_ok:
        plan.warnings.append(
            "Landlock ABI 6 (Linux 6.12+) unavailable: the agent can reach "
            "host abstract sockets such as the X11 display. Use --no-network "
            "for untrusted work."
        )

    a += ["--chdir", str(project)]

    if command == ["bash"]:
        a += ["--file", plan.fd(FdSource(data=BASH_RC)), RC_PATH]
        argv = ["bash", "--rcfile", RC_PATH, "-i"]
    else:
        # Run through an interactive bash (some agents, e.g. goose, need a
        # parent that stays alive) but pass arguments as positional
        # parameters so nothing is re-parsed by the shell.
        argv = ["bash", *(["-i"] if interactive else []), "-c", '"$@"', "devenv", *command]
    a += ["--", *argv]
    return plan


def is_setuid(path: str) -> bool:
    try:
        return bool(os.stat(path).st_mode & stat.S_ISUID)
    except OSError:
        return False
