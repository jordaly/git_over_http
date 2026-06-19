"""Backward-compatible entry point for PyGitHost.

New code should import from :mod:`pygithost`.  This module remains so existing
commands such as ``python server.py run`` and existing imports keep working.
"""

from pygithost import *  # noqa: F401,F403
from pygithost import main


if __name__ == "__main__":
    main()
