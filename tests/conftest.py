import pytest


@pytest.fixture
def env(tmp_path):
    """A fake home with a few dotfiles and a project directory."""
    home = tmp_path / "home"
    proj = home / "src" / "proj"
    (home / ".claude").mkdir(parents=True)
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("secret")
    (home / ".claude.json").write_text("{}")
    (home / ".gitconfig").write_text("[user]\nname = t\n")
    (proj / ".git" / "hooks").mkdir(parents=True)
    (proj / ".git" / "config").write_text("[core]\n")
    return home, proj
