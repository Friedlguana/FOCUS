"""FOCUS - a network security framework with a terminal-first interface."""

from __future__ import annotations

import sys

__version__ = "2.0.0"

# Windows consoles default to a legacy code page which cannot encode the box
# drawing and block characters the interface relies on.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass

__all__ = ["__version__"]
