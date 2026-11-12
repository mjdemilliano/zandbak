from pathlib import Path

import pytest

from zandbak import zandbakError, plan
from tests.helpers import build, cfg_with, index_of, pairs, strargs

# --- project directory checks -------------------------------------------


def test_refuses_home_as_project(env):
    home, _ = env
    with pytest.raises(zandbakError, match="contains your home"):
        build(home=home, cwd=home)


def test_refuses_ancestor_of_home(env):
    home, _ = env
    with pytest.raises(zandbakError, match="contains your home"):
        build(home=home, cwd=home.parent)


def test_refuses_root(env):
    home, _ = env
    with pytest.raises(zandbakError):
        build(home=home, cwd="/")


def test_refuses_dot_dir_project(env):
    home, _ = env
    with pytest.raises(zandbakError, match="dot-directories"):
        build(home=home, cwd=home / ".claude")


# --- home allowlist -----------------------------------------------------


def test_home_is_empty_tmpfs_plus_allowlist(env):
    home, proj = env
    a = strargs(build(home=home, cwd=proj))
    assert ("--tmpfs", str(home)) == tuple(a[index_of(a, "--tmpfs", str(home)) :][:2])
    assert (str(home / ".gitconfig"),) * 2 in pairs(a, "--ro-bind")
    assert (str(home / ".claude"),) * 2 in pairs(a, "--bind")
    joined = " ".join(a)
    assert ".ssh" not in joined
    # ephemeral file copied from an fd, not bound
    i = index_of(a, str(home / ".claude.json"))
    assert a[i - 2] == "--file"


def test_missing_home_entries_skipped(env):
    home, proj = env
    a = " ".join(strargs(build(home=home, cwd=proj)))
    assert ".gemini" not in a
    assert "goose" not in a


def test_home_entry_resolving_to_home_refused(env):
    home, proj = env
    (home / ".evil").symlink_to(home)
    with pytest.raises(zandbakError, match="whole home"):
        build(cfg_with('[home]\nro = [".evil"]'), home=home, cwd=proj)


def test_ephemeral_must_be_file(env):
    home, proj = env
    with pytest.raises(zandbakError, match="regular file"):
        build(cfg_with('[home]\nephemeral = [".claude"]\nrw = []'), home=home, cwd=proj)


def test_parents_mounted_before_children(env):
    home, proj = env
    (home / ".config" / "goose").mkdir(parents=True)
    a = strargs(
        build(cfg_with('[home]\nro = [".config"]\nrw = [".config/goose"]'), home=home, cwd=proj)
    )
    assert index_of(a, "--ro-bind", str(home / ".config")) < index_of(
        a, "--bind", str(home / ".config/goose")
    )


def test_warnings_for_dangerous_entries(env):
    home, proj = env
    (home / ".cargo").mkdir()
    p = build(cfg_with('[home]\nro = [".ssh"]\nrw = [".cargo"]'), home=home, cwd=proj)
    w = " ".join(p.warnings)
    assert ".cargo is writable" in w
    assert ".ssh may contain credentials" in w


# --- protections ----------------------------------------------------------


def test_git_protected_after_project_bind(env):
    home, proj = env
    a = strargs(build(home=home, cwd=proj))
    bind = index_of(a, "--bind", str(proj), str(proj))
    assert index_of(a, "--ro-bind", str(proj / ".git/config")) > bind
    assert index_of(a, "--ro-bind", str(proj / ".git/hooks")) > bind
    assert index_of(a, "--bind", str(proj / ".git"), str(proj / ".git")) > bind  # pinned


def test_extra_args_cannot_override_protections(env):
    home, proj = env
    cfg = cfg_with(f'bwrap_extra_args = ["--bind", "{proj}/.git", "{proj}/.git"]')
    a = strargs(build(cfg, home=home, cwd=proj))
    extra = index_of(a, "--bind", f"{proj}/.git", f"{proj}/.git")
    assert index_of(a, "--ro-bind", str(proj / ".git/config")) > extra


def test_allow_git_writes(env):
    home, proj = env
    a = " ".join(strargs(build(home=home, cwd=proj, allow_git_writes=True)))
    assert ".git/config" not in a
    assert ".git/hooks" not in a


def test_home_protect_only_inside_rw(env):
    home, proj = env
    (home / ".claude" / "settings.json").write_text("{}")
    p = build(home=home, cwd=proj)
    a = strargs(p)
    assert (str(home / ".claude/settings.json"),) * 2 in pairs(a, "--ro-bind")
    # ~/.gemini isn't mounted, so its home protect entries are skipped entirely
    assert str(home / ".gemini") not in " ".join(a)
    assert not [
        x for x in p.protections if x.watch and str(x.watch).startswith(str(home / ".gemini"))
    ]


def test_home_protect_follows_symlinked_rw_dir(env):
    home, proj = env
    real = home / "dotfiles" / "claude"
    (real / "hooks").mkdir(parents=True)
    (home / ".claude").rmdir()
    (home / ".claude").symlink_to(real)
    a = strargs(build(home=home, cwd=proj))
    assert (str(real), str(home / ".claude")) in pairs(a, "--bind")
    assert (str(real / "hooks"), str(home / ".claude/hooks")) in pairs(a, "--ro-bind")


# --- --ro-dir -----------------------------------------------------------------


def test_ro_dir_ok(env, tmp_path):
    home, proj = env
    lib = tmp_path / "lib"
    lib.mkdir()
    a = strargs(build(home=home, cwd=proj, ro_dirs=[str(lib)]))
    assert (str(lib), str(lib)) in pairs(a, "--ro-bind")


@pytest.mark.parametrize(
    ("which", "match"),
    [
        ("home", "contains your home"),
        ("root", "contains your home"),
        ("ssh", "inside ~/.ssh"),
        ("missing", "No such file"),
        ("inproj", "already visible"),
    ],
)
def test_ro_dir_refused(env, which, match):
    home, proj = env
    (proj / "sub").mkdir()
    d = {
        "home": str(home),
        "root": "/",
        "ssh": str(home / ".ssh"),
        "missing": "/nonexistent",
        "inproj": "sub",
    }[which]
    with pytest.raises(zandbakError, match=match):
        build(home=home, cwd=proj, ro_dirs=[d])


def test_ro_dir_planted_symlink_refused(env):
    home, proj = env
    docs = home / "Documents"
    docs.mkdir()
    (proj / "vendor").symlink_to(docs)
    with pytest.raises(zandbakError, match="via a symlink"):
        build(home=home, cwd=proj, ro_dirs=["vendor"])


def test_ro_dir_containing_project_mounted_first(env):
    home, proj = env
    src = home / "src"
    a = strargs(build(home=home, cwd=proj, ro_dirs=[str(src)]))
    assert index_of(a, "--ro-bind", str(src), str(src)) < index_of(
        a, "--bind", str(proj), str(proj)
    )


# --- environment, network, terminal, command --------------------------------


def test_env_allowlist(env):
    home, proj = env
    a = strargs(build(home=home, cwd=proj))
    assert a[a.index("--clearenv") - 1] != "--setenv"
    setenv = dict(pairs(a, "--setenv"))
    assert setenv["TERM"] == "xterm"
    assert setenv["HOME"] == str(home)
    assert "SECRET" not in setenv
    assert a.index("--clearenv") < a.index("--setenv")


def test_network_flags(env):
    home, proj = env
    a = strargs(build(home=home, cwd=proj, landlock=True))
    assert "--unshare-all" in a
    assert "--share-net" in a
    p = build(home=home, cwd=proj, network=False, landlock=True)
    assert "--share-net" not in strargs(p)
    assert not p.landlock
    assert not any("Landlock" in w for w in p.warnings)


def test_landlock_warning_when_unavailable(env):
    home, proj = env
    p = build(home=home, cwd=proj, landlock=False)
    assert not p.landlock
    assert any("abstract sockets" in w for w in p.warnings)
    assert build(home=home, cwd=proj, landlock=True).landlock


def test_seccomp_or_new_session(env):
    home, proj = env
    a = strargs(build(home=home, cwd=proj))
    assert "--seccomp" in a
    assert "--new-session" not in a
    p = build(home=home, cwd=proj, machine="riscv64")
    assert "--new-session" in strargs(p)
    assert "--seccomp" not in strargs(p)


def test_hardening_flags(env):
    home, proj = env
    a = strargs(build(home=home, cwd=proj))
    for f in ("--die-with-parent", "--unshare-all"):
        assert f in a
    assert index_of(a, "--cap-drop", "ALL") >= 0
    assert index_of(a, "--tmpfs", "/dev/shm") > index_of(a, "--dev", "/dev")
    assert index_of(a, "--tmpfs", "/run") >= 0


def test_bash_gets_prompt(env):
    home, proj = env
    a = strargs(build(home=home, cwd=proj))
    assert a[a.index("--") :] == ["--", "bash", "--rcfile", plan.RC_PATH, "-i"]


def test_command_args_not_reparsed(env):
    home, proj = env
    a = strargs(build(home=home, cwd=proj, command=["claude", "a b", "$(id)", ";rm -rf ~"]))
    tail = a[a.index("--") + 1 :]
    assert tail == ["bash", "-i", "-c", '"$@"', "zandbak", "claude", "a b", "$(id)", ";rm -rf ~"]


def test_command_starting_with_dash_is_safe(env):
    home, proj = env
    a = strargs(build(home=home, cwd=proj, command=["--bind", "/", "/"]))
    assert a.index("--") < a.index("bash")


# --- self-protection ---------------------------------------------------------


@pytest.mark.parametrize("where", ["project", "home_rw", "missing_cfg"])
def test_refuses_when_zandbak_is_writable(env, where):
    home, proj = env
    (home / ".config").mkdir()
    cfg = cfg_with('[home]\nro = []\nrw = [".config"]')
    target = {
        "project": proj / "venv" / "zandbak",
        "home_rw": home / ".config" / "zandbak" / "config.toml",
        "missing_cfg": home / ".config" / "nothere" / "config.toml",
    }[where]
    with pytest.raises(zandbakError, match="disable zandbak"):
        build(cfg, home=home, cwd=proj, self_paths=(target,))


def test_self_paths_elsewhere_ok(env, tmp_path):
    home, proj = env
    build(home=home, cwd=proj, self_paths=(tmp_path / "venv", Path("/usr/bin/bwrap")))


def test_non_interactive_command(env):
    home, proj = env
    a = strargs(build(home=home, cwd=proj, command=["claude"], interactive=False))
    assert "-i" not in a[a.index("--") :]
