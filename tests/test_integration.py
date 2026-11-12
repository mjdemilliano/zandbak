"""End-to-end tests that run the real bwrap. Skipped if it can't run here."""

import os
import shutil
import socket
import subprocess
import sys
import threading

import pytest

from zandbak import landlock


def _bwrap_works():
    b = shutil.which("bwrap")
    if not b:
        return False
    r = subprocess.run(
        [b, "--ro-bind", "/", "/", "--unshare-all", "true"], capture_output=True, check=False
    )
    return r.returncode == 0


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _bwrap_works(), reason="bwrap unavailable or not permitted"),
]


@pytest.fixture
def run(env, tmp_path):
    home, proj = env
    xdg = tmp_path / "xdg"

    def _run(*args, cwd=proj, stdin=subprocess.DEVNULL):
        e = {
            "HOME": str(home),
            "PATH": os.environ["PATH"],
            "XDG_CONFIG_HOME": str(xdg),
            "TERM": "dumb",
        }
        return subprocess.run(
            [sys.executable, "-m", "zandbak", *args],
            cwd=cwd,
            env=e,
            stdin=stdin,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    return _run


def sh(run, script, *extra, **kw):
    return run(*extra, "-c", "sh", "--", "-c", script, **kw)


def test_secrets_hidden_and_home_minimal(run, env):
    home, _ = env
    r = sh(run, f"ls -A {home}; echo ---; ls -A {home}/src; cat {home}/.ssh/id_ed25519")
    assert r.returncode != 0
    top, src = r.stdout.split("---")
    # `src` is only the parent bwrap creates for the project mount
    assert set(top.split()) == {".claude", ".claude.json", ".gitconfig", "src"}
    assert src.split() == ["proj"]
    assert "secret" not in r.stdout


def test_project_writable_git_protected(run, env):
    _, proj = env
    r = sh(
        run,
        "echo hi > f && echo x >> .git/config; echo c=$?; "
        "touch .git/hooks/p; echo h=$?; mv .git .g; echo m=$?",
    )
    assert (proj / "f").read_text() == "hi\n"
    assert "c=1" in r.stdout or "c=2" in r.stdout
    assert "h=1" in r.stdout
    assert "m=1" in r.stdout
    assert (proj / ".git/config").read_text() == "[core]\n"
    assert not (proj / ".git/hooks/p").exists()


def test_allow_git_writes(run, env):
    _, proj = env
    sh(run, "echo '#x' >> .git/config", "--allow-git-writes")
    assert "#x" in (proj / ".git/config").read_text()


def test_created_hook_files_quarantined(run, env):
    home, proj = env
    r = sh(
        run,
        f"echo {{}} > .mcp.json; mkdir -p .claude && echo {{}} > .claude/settings.json; "
        f"echo {{}} > {home}/.claude/settings.json; mkdir {home}/.claude/hooks",
    )
    assert not (proj / ".mcp.json").exists()
    assert not (proj / ".claude").exists()
    assert not (home / ".claude/settings.json").exists()
    assert not (home / ".claude/hooks").exists()
    assert r.stderr.count("quarantined") == 4


def test_existing_agent_settings_read_only(run, env):
    home, _ = env
    (home / ".claude/settings.json").write_text("{}")
    sh(
        run,
        f"echo '{{\"hooks\":1}}' > {home}/.claude/settings.json; echo ok > {home}/.claude/session",
    )
    assert (home / ".claude/settings.json").read_text() == "{}"
    assert (home / ".claude/session").read_text() == "ok\n"  # rest of .claude writable


def test_ephemeral_changes_discarded(run, env):
    home, _ = env
    r = sh(run, f"cat {home}/.claude.json; echo '{{\"mcpServers\":1}}' > {home}/.claude.json")
    assert r.stdout.strip() == "{}"
    assert (home / ".claude.json").read_text() == "{}"


def test_planted_symlink_not_followed(run, env):
    home, _ = env
    (home / ".claude/settings.json").symlink_to(home / ".ssh/id_ed25519")
    r = sh(run, f"cat {home}/.claude/settings.json")
    assert "secret" not in r.stdout


def test_tiocsti_blocked(run):
    code = (
        "import fcntl,termios\n"
        "try:\n fcntl.ioctl(0, termios.TIOCSTI, b'x')\n"
        "except OSError as e: print(e.errno)"
    )
    r = run("-c", "python3", "--", "-c", code)
    assert r.stdout.strip() == "1"  # EPERM from seccomp, not ENOTTY


def test_args_and_exit_code(run):
    r = run("-c", "printf", "--", "[%s]", "a b", "$(id)")
    assert r.stdout == "[a b][$(id)]"
    assert sh(run, "exit 7").returncode == 7


def test_no_network(run):
    code = (
        "import socket\ns=socket.socket()\ns.settimeout(3)\n"
        "try: s.connect(('1.1.1.1', 53)); print('up')\n"
        "except OSError as e: print('down')"
    )
    assert run("--no-network", "-c", "python3", "--", "-c", code).stdout.strip() == "down"


def test_refuses_home(run, env):
    home, _ = env
    r = sh(run, "true", cwd=home)
    assert r.returncode == 2


@pytest.mark.skipif(landlock.abi_version() < landlock.MIN_ABI, reason="Landlock ABI 6 unavailable")
def test_abstract_socket_blocked(run):
    name = f"zandbak-test-{os.getpid()}"
    srv = socket.socket(socket.AF_UNIX)
    srv.bind("\0" + name)
    srv.listen()
    threading.Thread(target=srv.accept, daemon=True).start()
    code = (
        f"import socket\ns=socket.socket(socket.AF_UNIX)\n"
        f"try: s.connect('\\0{name}'); print('connected')\n"
        f"except OSError as e: print(e.errno)"
    )
    try:
        assert run("-c", "python3", "--", "-c", code).stdout.strip() == "1"
    finally:
        srv.close()
