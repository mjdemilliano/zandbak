import os
import time

from zandbak import protect


def test_existing_path_is_ro_and_parents_pinned(tmp_path):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    p = protect.analyse(tmp_path, ".git/hooks")
    assert p.ro == ((tmp_path / ".git/hooks", tmp_path / ".git/hooks"),)
    assert p.pins == ((tmp_path / ".git", tmp_path / ".git"),)
    assert p.watch is None


def test_missing_component_is_watched(tmp_path):
    (tmp_path / ".claude").mkdir()
    p = protect.analyse(tmp_path, ".claude/settings.json")
    assert p.ro == ()
    assert p.watch == tmp_path / ".claude/settings.json"
    assert p.before is None
    # the first missing component is watched, not the leaf
    assert protect.analyse(tmp_path, ".vscode/tasks.json").watch == tmp_path / ".vscode"


def test_intermediate_file_is_frozen(tmp_path):
    (tmp_path / ".git").write_text("gitdir: /elsewhere\n")  # a worktree
    p = protect.analyse(tmp_path, ".git/config")
    assert p.ro == ((tmp_path / ".git", tmp_path / ".git"),)


def test_symlinks_are_never_followed(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("x")
    (tmp_path / ".envrc").symlink_to(secret)
    p = protect.analyse(tmp_path, ".envrc")
    assert p.ro == ()
    assert p.watch == tmp_path / ".envrc"
    assert p.before is not None
    assert p.before.link == str(secret)

    (tmp_path / "real").mkdir()
    (tmp_path / ".claude").symlink_to(tmp_path / "real")
    p = protect.analyse(tmp_path, ".claude/settings.json")
    assert p.ro == ()
    assert p.pins == ()
    assert p.watch == tmp_path / ".claude"


def test_dest_mapping(tmp_path):
    real = tmp_path / "dotfiles" / "claude"
    (real / "hooks").mkdir(parents=True)
    p = protect.analyse(real, "hooks", tmp_path / "home" / ".claude")
    assert p.ro == ((real / "hooks", tmp_path / "home/.claude/hooks"),)


def test_quarantines_created(tmp_path):
    p = protect.analyse(tmp_path, ".mcp.json")
    (tmp_path / ".mcp.json").write_text("{}")
    notes = protect.quarantine([p, p], now=0)  # duplicates are handled once
    assert len(notes) == 1
    assert "quarantined" in notes[0]
    assert not (tmp_path / ".mcp.json").exists()
    assert len(list(tmp_path.glob(".mcp.json.zandbak-quarantine-*"))) == 1


def test_quarantines_retargeted_symlink(tmp_path):
    (tmp_path / "a").write_text("a")
    (tmp_path / "b").write_text("b")
    (tmp_path / ".envrc").symlink_to("a")
    p = protect.analyse(tmp_path, ".envrc")
    (tmp_path / ".envrc").unlink()
    (tmp_path / ".envrc").symlink_to("b")
    assert len(protect.quarantine([p])) == 1
    assert not (tmp_path / ".envrc").exists(follow_symlinks=False)
    assert (tmp_path / "b").read_text() == "b"  # the target is untouched


def test_symlink_to_victim_does_not_move_victim(tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "settings.json").write_text("mine")
    p = protect.analyse(tmp_path, ".claude/settings.json")  # .claude is missing
    (tmp_path / ".claude").symlink_to(victim)
    protect.quarantine([p])
    assert (victim / "settings.json").read_text() == "mine"
    assert not (tmp_path / ".claude").exists(follow_symlinks=False)


def test_unchanged_and_removed_are_left_alone(tmp_path):
    (tmp_path / ".envrc").symlink_to("x")
    (tmp_path / ".old").symlink_to("y")
    p1 = protect.analyse(tmp_path, ".envrc")
    p2 = protect.analyse(tmp_path, ".mcp.json")
    p3 = protect.analyse(tmp_path, ".old")
    (tmp_path / ".old").unlink()
    assert protect.quarantine([p1, p2, p3]) == []
    assert (tmp_path / ".envrc").is_symlink()


def test_name_collision(tmp_path, monkeypatch):
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    p = protect.analyse(tmp_path, ".mcp.json")
    stamp = "19700101-000000"
    (tmp_path / f".mcp.json.zandbak-quarantine-{stamp}").write_text("old")
    (tmp_path / ".mcp.json").write_text("new")
    protect.quarantine([p], now=0)
    assert (tmp_path / f".mcp.json.zandbak-quarantine-{stamp}").read_text() == "old"
    assert (tmp_path / f".mcp.json.zandbak-quarantine-{stamp}-2").read_text() == "new"


def test_rename_failure_reported(tmp_path, monkeypatch):
    p = protect.analyse(tmp_path, ".mcp.json")
    (tmp_path / ".mcp.json").write_text("{}")

    def fail(*_a):
        raise OSError(16, os.strerror(16))

    monkeypatch.setattr("pathlib.Path.rename", fail)
    (note,) = protect.quarantine([p])
    assert note.startswith("DANGER")
