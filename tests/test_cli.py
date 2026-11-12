import tomllib

import pytest

from devenv import cli, config


@pytest.fixture
def at(monkeypatch, tmp_path, env):
    """Run from the project with a fake home and no user config."""
    home, proj = env
    monkeypatch.chdir(proj)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    return home, proj


def test_dump_config_round_trips(capsys):
    assert cli.main(["--dump-config"]) == 0
    out = capsys.readouterr().out
    tomllib.loads(out)
    assert config.parse(out, config.Config()) == config.defaults()


@pytest.mark.usefixtures("at")
def test_bad_config_exits_2(tmp_path, capsys):
    bad = tmp_path / "bad.toml"
    bad.write_text("nope = 1")
    assert cli.main(["--config", str(bad), "--dry-run"]) == 2
    assert "unknown key" in capsys.readouterr().err


@pytest.mark.usefixtures("at")
def test_missing_explicit_config_exits_2(tmp_path):
    assert cli.main(["--config", str(tmp_path / "x.toml"), "--dry-run"]) == 2


@pytest.mark.usefixtures("at")
def test_dry_run_and_passthrough(capsys):
    assert cli.main(["--dry-run", "-c", "claude", "--", "--model", "x y"]) == 0
    assert capsys.readouterr().out.rstrip().endswith("devenv claude --model 'x y'")


@pytest.mark.usefixtures("at")
def test_configured_command_gets_extra_args(capsys):
    assert cli.main(["--dry-run", "--", "-x"]) == 0
    assert capsys.readouterr().out.rstrip().endswith("devenv bash -x")


@pytest.mark.usefixtures("at")
def test_missing_bwrap(tmp_path, capsys):
    cfg = tmp_path / "c.toml"
    cfg.write_text('bwrap_path = "no-such-bwrap"')
    assert cli.main(["--config", str(cfg)]) == 2
    assert "install bubblewrap" in capsys.readouterr().err


def test_refuses_home(monkeypatch, capsys, at):
    home, _ = at
    monkeypatch.chdir(home)
    assert cli.main(["--dry-run"]) == 2
    assert "home directory" in capsys.readouterr().err
