import pytest

from devenv import devenvError, config
from devenv.config import Config


def test_defaults_parse_and_are_safe():
    cfg = config.defaults()
    assert cfg.command == ("bash",)
    assert cfg.network is True
    mounted = cfg.home.ro + cfg.home.rw + cfg.home.ephemeral
    for bad in (".ssh", ".gnupg", ".aws", ".cargo", ".cache", ".config/gh", ".netrc"):
        assert bad not in mounted
    assert {".git/config", ".git/hooks", ".git/modules"} <= set(cfg.project.protect)
    assert ".claude/settings.json" in cfg.home.protect
    assert ".claude.json" in cfg.home.ephemeral


def test_override_replaces_lists_only_where_set():
    cfg = config.parse('[home]\nrw = [".foo"]\n', config.defaults())
    assert cfg.home.rw == (".foo",)
    assert cfg.home.protect == config.defaults().home.protect


@pytest.mark.parametrize(
    "text",
    [
        "bogus = 1",
        "[home]\nrww = []",
        "[project]\nprotec = []",
        "network = 'yes'",
        "network = 1",
        "command = 'bash'",
        "command = []",
        "env_allow = [1]",
        "env_allow = ['A=B']",
        "home = 3",
        "bwrap_path = ''",
        "bwrap_path = 3",
    ],
)
def test_invalid_config_rejected(text):
    with pytest.raises(devenvError):
        config.parse(text, config.defaults())


@pytest.mark.parametrize("path", ["/etc", "../x", ".claude/../../x", "", ".", "./", "a\x00b"])
def test_bad_paths_rejected(path):
    with pytest.raises(devenvError):
        config.normalise(path, "t")


@pytest.mark.parametrize(
    ("path", "norm"),
    [(".claude", ".claude"), ("./.claude", ".claude"), (".config//goose/", ".config/goose")],
)
def test_paths_normalised(path, norm):
    assert config.normalise(path, "t") == norm


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ('[home]\nro = [".a"]\nrw = [".a"]', "more than once"),
        ('[home]\nro = [".claude/x"]', "inside writable"),
        ('[home]\nephemeral = [".claude/x.json"]', "inside writable"),
        ('[home]\nrw = [".claude", ".claude/x"]', "inside writable"),
    ],
)
def test_structural_rules(text, match):
    with pytest.raises(devenvError, match=match):
        config.parse(text, config.defaults())


def test_invalid_toml():
    with pytest.raises(devenvError, match="invalid TOML"):
        config.parse("= =", Config())


def test_load_missing_file(tmp_path):
    assert config.load(tmp_path / "nope.toml", explicit=False) == config.defaults()
    with pytest.raises(devenvError, match="not found"):
        config.load(tmp_path / "nope.toml", explicit=True)


def test_load_error_is_fatal_not_fallback(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("network = maybe")
    with pytest.raises(devenvError, match=str(p)):
        config.load(p, explicit=False)


def test_default_path_uses_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert config.default_path() == tmp_path / "devenv" / "config.toml"
