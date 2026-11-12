import tomllib

from devenv import cli, config


def test_dump_config_round_trips(capsys):
    assert cli.main(["--dump-config"]) == 0
    out = capsys.readouterr().out
    tomllib.loads(out)
    assert config.parse(out) == config.defaults()


def test_bad_config_exits_2(tmp_path, capsys, monkeypatch, env):
    home, proj = env
    monkeypatch.chdir(proj)
    monkeypatch.setenv("HOME", str(home))
    bad = tmp_path / "bad.toml"
    bad.write_text("nope = 1")
    assert cli.main(["--config", str(bad), "--dry-run"]) == 2
    assert "unknown key" in capsys.readouterr().err


def test_missing_explicit_config_exits_2(tmp_path, monkeypatch, env):
    home, proj = env
    monkeypatch.chdir(proj)
    assert cli.main(["--config", str(tmp_path / "x.toml"), "--dry-run"]) == 2


def test_dry_run_and_passthrough(monkeypatch, capsys, env, tmp_path):
    home, proj = env
    monkeypatch.chdir(proj)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert cli.main(["--dry-run", "-c", "claude", "--", "--model", "x y"]) == 0
    out = capsys.readouterr().out
    assert out.rstrip().endswith("devenv claude --model 'x y'")


def test_refuses_home(monkeypatch, capsys, env, tmp_path):
    home, _ = env
    monkeypatch.chdir(home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert cli.main(["--dry-run"]) == 2
    assert "home directory" in capsys.readouterr().err
