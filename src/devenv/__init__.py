"""devenv: run AI coding agents inside a bubblewrap sandbox."""

__version__ = "0.2.0"
"""Package version, shown by ``devenv --version``."""

APP = "devenv"
"""Program name, used in messages, file names and the config path."""


class DevenvError(Exception):
    """A problem the user must fix; the message is shown as-is and devenv exits."""
