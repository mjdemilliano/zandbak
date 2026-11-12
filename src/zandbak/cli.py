"""Command-line entry point: parse arguments, build the plan, run bwrap."""

import argparse
import os
import shlex
import shutil
import signal
import subprocess
import sys
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import FrameType

from zandbak import APP, zandbakError, __version__, config, landlock, protect
from zandbak.plan import Arg, Plan, Request, build

type SignalHandler = Callable[[int, FrameType | None], object]
"""Signature of a Python signal handler."""


def _parser() -> argparse.ArgumentParser:
    """Return the argument parser."""
    p = argparse.ArgumentParser(
        prog=APP,
        description="Run AI coding agents in a bubblewrap sandbox limited to the current "
        "directory. Arguments after -- are appended to the command.",
    )
    p.add_argument("-c", "--command", help="program to run instead of the configured command")
    p.add_argument(
        "--config", type=Path, help=f"config file (default: ~/.config/{APP}/config.toml)"
    )
    p.add_argument(
        "--ro-dir",
        action="append",
        default=[],
        metavar="DIR",
        help="extra directory to expose read-only (repeatable)",
    )
    p.add_argument(
        "--no-network", action="store_true", help="disconnect the sandbox from the network"
    )
    p.add_argument(
        "--allow-git-writes",
        action="store_true",
        help="let the agent change .git/config, .git/hooks and .git/modules this time",
    )
    p.add_argument("--dry-run", action="store_true", help="print the bwrap command and exit")
    p.add_argument("--dump-config", action="store_true", help="print the default config and exit")
    p.add_argument("--version", action="version", version=f"{APP} {__version__}")
    p.add_argument("args", nargs="*", help=argparse.SUPPRESS)
    return p


def _say(message: str) -> None:
    """Print ``message`` to stderr, prefixed with the program name."""
    print(f"{APP}: {message}", file=sys.stderr)


def _open_fds(plan: Plan, stack: ExitStack) -> list[int]:
    """Open every descriptor the plan needs; ``stack`` closes them."""
    fds = []
    for source in plan.fds:
        if isinstance(source, bytes):
            fd = os.memfd_create(APP)
            stack.callback(os.close, fd)
            os.write(fd, source)
            os.lseek(fd, 0, os.SEEK_SET)
        else:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, fd)
        fds.append(fd)
    return fds


def _argv(plan: Plan, fds: list[int] | None) -> list[str]:
    """Return the plan's arguments with descriptors filled in (placeholders if None)."""

    def show(arg: Arg) -> str:
        """Render one argument."""
        if isinstance(arg, str):
            return arg
        return str(fds[arg.index]) if fds is not None else f"<fd{arg.index}>"

    return [show(a) for a in plan.argv]


@contextmanager
def _signals(handlers: dict[signal.Signals, SignalHandler]) -> Iterator[None]:
    """Install signal ``handlers`` for the duration of the block."""
    old = {sig: signal.signal(sig, handler) for sig, handler in handlers.items()}
    try:
        yield
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)


def _ignore(_sig: int, _frame: FrameType | None) -> None:
    """Signal handler that does nothing (unlike SIG_IGN, exec resets it)."""


def _run(bwrap: str, argv: list[str], fds: list[int], *, use_landlock: bool) -> int:
    r"""Run bwrap and return its exit status as a shell would report it.

    Ctrl-C and Ctrl-\\ reach the whole foreground process group; the sandbox
    handles them, so zandbak itself ignores them. SIGTERM and SIGHUP (terminal
    closed) are forwarded so the sandbox ends and the quarantine check runs.
    """
    with _signals({signal.SIGINT: _ignore, signal.SIGQUIT: _ignore}):
        proc = subprocess.Popen(
            [bwrap, *argv],
            pass_fds=fds,
            preexec_fn=landlock.restrict_self if use_landlock else None,  # noqa: PLW1509 - single-threaded, must run between fork and exec
        )

        def forward(sig: int, _frame: FrameType | None) -> None:
            """Pass ``sig`` on to bwrap."""
            proc.send_signal(sig)

        with _signals({signal.SIGTERM: forward, signal.SIGHUP: forward}):
            status = proc.wait()
    return status if status >= 0 else 128 - status


def _find_bwrap(name: str, *, required: bool) -> str:
    """Return the bwrap path; raise zandbakError if ``required`` and it is missing."""
    path = shutil.which(name)
    if path is None and required:
        raise zandbakError(f"cannot find {name!r}; install bubblewrap")
    return path or name


def _request(args: argparse.Namespace, cfg: config.Config, cfg_path: Path, bwrap: str) -> Request:
    """Combine arguments, config and the environment into a build request."""
    program = (args.command,) if args.command else cfg.command
    return Request(
        config=cfg,
        home=Path(os.environ.get("HOME") or Path.home()),
        cwd=Path.cwd(),
        environ=os.environ,
        command=(*program, *args.args),
        ro_dirs=tuple(args.ro_dir),
        network=cfg.network and not args.no_network,
        allow_git_writes=args.allow_git_writes,
        landlock=landlock.usable(Path(bwrap)),
        self_paths=(cfg_path, Path(__file__).parent, Path(sys.executable), Path(bwrap)),
        interactive=sys.stdin.isatty(),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run zandbak with ``argv`` (default: ``sys.argv``); return the exit status."""
    args = _parser().parse_args(argv)
    if args.dump_config:
        sys.stdout.write(config.default_text())
        return 0
    cfg_path: Path = args.config or config.default_path()
    try:
        cfg = config.load(cfg_path, explicit=args.config is not None)
        bwrap = _find_bwrap(cfg.bwrap_path, required=not args.dry_run)
        plan = build(_request(args, cfg, cfg_path, bwrap))
    except zandbakError as e:
        _say(str(e))
        return 2
    for warning in plan.warnings:
        _say(f"warning: {warning}")
    if args.dry_run:
        print(shlex.join([bwrap, *_argv(plan, None)]))
        return 0

    try:
        with ExitStack() as stack:
            fds = _open_fds(plan, stack)
            _say(f"sandboxed in {Path.cwd()}")
            return _run(bwrap, _argv(plan, fds), fds, use_landlock=plan.landlock)
    except (OSError, subprocess.SubprocessError) as e:
        _say(f"failed to start the sandbox: {e}")
        return 1
    finally:
        # Runs after the sandbox is gone, even if starting it failed half-way.
        for note in protect.quarantine(plan.protections):
            _say(note)
