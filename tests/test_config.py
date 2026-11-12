import pytest

from devenv import config
from devenv.config import ConfigError


def test_defaults_parse_and_are_safe():
    cfg = config.defaults()
    assert cfg.command == ("bash",)
    assert cfg.network is True
    # Nothing secret or host-executed is mounted by default.
    for bad in (".ssh", ".gnupg", ".aws", ".cargo", ".cache", ".config/gh", ".netrc"):
        assert bad not in cfg.home_ro + cfg.home_rw + cfg.home_ephemeral
    assert ".git/config" in cfg.project_protect
    assert ".git/hooks" in cfg.project_protect
    assert ".git/modules" in cfg.project_protect
    assert ".claude/settings.json" in cfg.home_protect
    assert ".claude.json" in cfg.home_ephemeral


def test_override_replaces_lists():
    cfg = config.parse('[home]\nrw = [".foo"]\n', base=config.defaults())
    assert cfg.home_rw == (".foo",)
    assert cfg.home_protect == config.defaults().home_protect  # untouched


@pytest.mark.parametrize(
    "text",
    [
        "bogus = 1",
        "[home]\nrww = []",
        "[project]\nprotec = []",
        "network = 'yes'",
        "command = 'bash'",
        "command = []",
        "env_allow = [1]",
        "env_allow = ['A=B']",
        "home = 3",
        "bwrap_path = ''",
    ],
)
def test_invalid_config_rejected(text):
    with pytest.raises(ConfigError):
        config.parse(text, base=config.defaults())


@pytest.mark.parametrize("path", ["/etc", "../x", ".claude/../../x", "", ".", "./", "a\x00b"])
def test_bad_paths_rejected(path):
    with pytest.raises(ConfigError):
        config.validate_rel_path(path, "t")


@pytest.mark.parametrize(
    "path,norm", [(".claude", ".claude"), ("./.claude", ".claude"), (".config//goose/", ".config/goose")]
)
def test_paths_normalised(path, norm):
    assert config.validate_rel_path(path, "t") == norm


def test_duplicate_mount_rejected():
    with pytest.raises(ConfigError, match="more than once"):
        config.parse('[home]\nro = [".a"]\nrw = [".a"]\n', base=config.defaults())


def test_invalid_toml():
    with pytest.raises(ConfigError, match="invalid TOML"):
        config.parse("= =", base=config.defaults())


def test_load_missing_file(tmp_path):
    assert config.load(tmp_path / "nope.toml") == config.defaults()
    with pytest.raises(ConfigError, match="not found"):
        config.load(tmp_path / "nope.toml", explicit=True)


def test_load_error_is_fatal_not_fallback(tmp_path):
    # The Go version warned and carried on with defaults; we refuse.
    p = tmp_path / "c.toml"
    p.write_text("network = maybe")
    with pytest.raises(ConfigError):
        config.load(p)


def test_default_path_uses_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert config.default_config_path() == tmp_path / "devenv" / "config.toml"
