import os

from devenv import protect


def test_existing_file_is_mounted_ro_and_parents_pinned(tmp_path):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    p = protect.analyse(tmp_path, ".git/hooks")
    assert p.ro_mounts == ((tmp_path / ".git/hooks", tmp_path / ".git/hooks"),)
    assert p.self_binds == ((tmp_path / ".git", tmp_path / ".git"),)
    assert p.watch is None


def test_missing_component_is_watched(tmp_path):
    (tmp_path / ".claude").mkdir()
    p = protect.analyse(tmp_path, ".claude/settings.json")
    assert p.ro_mounts == ()
    assert p.watch == tmp_path / ".claude/settings.json"
    assert not p.watch_before.exists
    # first missing component, not the leaf
    p = protect.analyse(tmp_path, ".vscode/tasks.json")
    assert p.watch == tmp_path / ".vscode"


def test_intermediate_file_is_frozen(tmp_path):
    # git worktree: .git is a file pointing elsewhere
    (tmp_path / ".git").write_text("gitdir: /elsewhere\n")
    p = protect.analyse(tmp_path, ".git/config")
    assert p.ro_mounts == ((tmp_path / ".git", tmp_path / ".git"),)


def test_symlinks_are_never_followed(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("x")
    (tmp_path / ".envrc").symlink_to(secret)
    p = protect.analyse(tmp_path, ".envrc")
    assert p.ro_mounts == () and p.watch == tmp_path / ".envrc"
    assert p.watch_before.link == str(secret)

    (tmp_path / "real").mkdir()
    (tmp_path / ".claude").symlink_to(tmp_path / "real")
    p = protect.analyse(tmp_path, ".claude/settings.json")
    assert p.ro_mounts == () and p.self_binds == ()
    assert p.watch == tmp_path / ".claude"


def test_dest_base_mapping(tmp_path):
    real = tmp_path / "dotfiles" / "claude"
    (real / "hooks").mkdir(parents=True)
    p = protect.analyse(real, "hooks", dest_base=tmp_path / "home" / ".claude")
    assert p.ro_mounts == ((real / "hooks", tmp_path / "home/.claude/hooks"),)


def test_check_after_quarantines_created(tmp_path):
    p = protect.analyse(tmp_path, ".mcp.json")
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {}}')
    notes = protect.check_after([p], now=0)
    assert len(notes) == 1 and "quarantined" in notes[0]
    assert not (tmp_path / ".mcp.json").exists()
    q = [x for x in os.listdir(tmp_path) if x.startswith(".mcp.json.devenv-quarantine-")]
    assert len(q) == 1


def test_check_after_quarantines_retargeted_symlink(tmp_path):
    (tmp_path / "a").write_text("a")
    (tmp_path / "b").write_text("b")
    (tmp_path / ".envrc").symlink_to("a")
    p = protect.analyse(tmp_path, ".envrc")
    os.unlink(tmp_path / ".envrc")
    (tmp_path / ".envrc").symlink_to("b")
    assert len(protect.check_after([p])) == 1
    assert not os.path.lexists(tmp_path / ".envrc")
    assert (tmp_path / "b").read_text() == "b"  # target untouched


def test_check_after_symlink_to_victim_does_not_move_victim(tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "settings.json").write_text("mine")
    p = protect.analyse(tmp_path, ".claude/settings.json")  # .claude missing
    (tmp_path / ".claude").symlink_to(victim)
    protect.check_after([p])
    assert (victim / "settings.json").read_text() == "mine"
    assert not os.path.lexists(tmp_path / ".claude")


def test_check_after_leaves_unchanged_alone(tmp_path):
    (tmp_path / ".envrc").symlink_to("x")
    p1 = protect.analyse(tmp_path, ".envrc")
    p2 = protect.analyse(tmp_path, ".mcp.json")
    assert protect.check_after([p1, p2]) == []
    assert os.path.islink(tmp_path / ".envrc")


def test_check_after_name_collision(tmp_path):
    p = protect.analyse(tmp_path, ".mcp.json")
    stamp = "19700101-000000"
    (tmp_path / f".mcp.json.devenv-quarantine-{stamp}").write_text("old")
    (tmp_path / ".mcp.json").write_text("new")
    os.environ["TZ"] = "UTC"
    import time

    time.tzset()
    protect.check_after([p], now=0)
    assert (tmp_path / f".mcp.json.devenv-quarantine-{stamp}").read_text() == "old"
    assert (tmp_path / f".mcp.json.devenv-quarantine-{stamp}-2").read_text() == "new"
