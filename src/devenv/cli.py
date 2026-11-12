"""Command-line entry point."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from . import __version__, config, landlock, plan as planmod, protect


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="devenv",
        description="Run AI coding agents in a bubblewrap sandbox limited to "
        "the current directory.",
        epilog="Arguments after -- are appended to the command.",
    )
    p.add_argument("-c", "--command", help="program to run instead of the configured command")
    p.add_argument("--config", type=Path, help="config file (default: ~/.config/devenv/config.toml)")
    p.add_argument("--ro-dir", action="append", default=[], metavar="DIR",
                   help="extra directory to expose read-only (repeatable)")
    p.add_argument("--no-network", action="store_true", help="disconnect the sandbox from the network")
    p.add_argument("--allow-git-writes", action="store_true",
                   help="let the agent change .git/config and .git/hooks this time")
    p.add_argument("--dry-run", action="store_true", help="print the bwrap command and exit")
    p.add_argument("--dump-config", action="store_true", help="print the default config and exit")
    p.add_argument("--version", action="version", version=f"devenv {__version__}")
    p.add_argument("args", nargs="*", help=argparse.SUPPRESS)
    return p


def _err(msg: str) -> None:
    print(f"devenv: {msg}", file=sys.stderr)


def _open_fds(plan: planmod.Plan) -> list[int]:
    fds = []
    try:
        for src in plan.fds:
            if src.data is not None:
                fd = os.memfd_create("devenv", 0)
                os.write(fd, src.data)
                os.lseek(fd, 0, os.SEEK_SET)
            else:
                fd = os.open(src.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            fds.append(fd)
    except OSError:
        for fd in fds:
            os.close(fd)
        raise
    return fds


def _resolve_argv(plan: planmod.Plan, fds: list[int] | None) -> list[str]:
    out = []
    for a in plan.argv:
        if isinstance(a, planmod.FdRef):
            out.append(str(fds[a.index]) if fds is not None else f"<fd{a.index}>")
        else:
            out.append(a)
    return out


def _run(bwrap: str, argv: list[str], fds: list[int], use_landlock: bool) -> int:
    preexec = landlock.restrict_self if use_landlock else None
    # Ctrl-C / Ctrl-\ go to the whole foreground process group; let the
    # sandbox handle them instead of killing devenv. (Handlers, unlike SIG_IGN,
    # are reset to the default in the child on exec.)
    old = {s: signal.signal(s, lambda *_: None) for s in (signal.SIGINT, signal.SIGQUIT)}
    try:
        proc = subprocess.Popen([bwrap, *argv], pass_fds=fds, preexec_fn=preexec)
    except BaseException:
        for s, h in old.items():
            signal.signal(s, h)
        raise
    for fd in fds:
        os.close(fd)

    def forward(sig, _frame):
        proc.send_signal(sig)

    for s in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, forward)
    rc = proc.wait()
    for s, h in old.items():
        signal.signal(s, h)
    return rc if rc >= 0 else 128 - rc


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.dump_config:
        sys.stdout.write(config.default_config_text())
        return 0

    try:
        cfg_path = args.config or config.default_config_path()
        cfg = config.load(cfg_path, explicit=args.config is not None)
    except config.ConfigError as e:
        _err(f"config error: {e}")
        return 2

    command = [args.command] if args.command else list(cfg.command)
    command += args.args

    bwrap = shutil.which(cfg.bwrap_path)
    if bwrap is None and not args.dry_run:
        _err(f"cannot find {cfg.bwrap_path!r}; install bubblewrap")
        return 127
    bwrap = bwrap or cfg.bwrap_path

    landlock_ok = landlock.available()
    if landlock_ok and planmod.is_setuid(bwrap):
        # no_new_privs (required by Landlock) would stop a setuid bwrap.
        landlock_ok = False

    home = os.environ.get("HOME") or os.path.expanduser("~")
    try:
        plan = planmod.build(
            cfg,
            home=home,
            cwd=os.getcwd(),
            environ=dict(os.environ),
            command=command,
            ro_dirs=args.ro_dir,
            network=False if args.no_network else None,
            allow_git_writes=args.allow_git_writes,
            landlock_ok=landlock_ok,
            self_paths=[
                str(cfg_path),
                os.path.dirname(os.path.realpath(__file__)),
                sys.executable,
                bwrap,
            ],
            interactive=sys.stdin.isatty(),
        )
    except planmod.PlanError as e:
        _err(str(e))
        return 2

    for w in plan.warnings:
        _err(f"warning: {w}")

    if args.dry_run:
        print(shlex.join([bwrap, *_resolve_argv(plan, None)]))
        return 0

    try:
        fds = _open_fds(plan)
    except OSError as e:
        _err(f"cannot prepare sandbox files: {e}")
        return 1

    print(f"devenv: sandboxed in {os.getcwd()}", file=sys.stderr)
    try:
        rc = _run(bwrap, _resolve_argv(plan, fds), fds, plan.landlock)
    except (OSError, subprocess.SubprocessError) as e:
        _err(f"failed to start bwrap: {e}")
        rc = 1
    finally:
        # Always check, even if the launch failed half-way.
        for note in protect.check_after(plan.protections):
            _err(note)
    return rc


if __name__ == "__main__":
    sys.exit(main())
