"""zandbak: run AI coding agents inside a bubblewrap sandbox."""

__version__ = "0.2.0"
"""Package version, shown by ``zandbak --version``."""

APP = "zandbak"
"""Program name, used in messages, file names and the config path."""


class ZandbakError(Exception):
    """A problem the user must fix; the message is shown as-is and zandbak exits."""
