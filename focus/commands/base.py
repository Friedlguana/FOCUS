"""Command registry.

Each command owns its argument parser and its implementation. The CLI and the
interactive shell both build parsers from this registry, so ``focus dashboard
-h`` and ``/dashboard -h`` can never drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from argparse import ArgumentParser, Namespace


@dataclass(frozen=True)
class Command:
    name: str
    summary: str
    usage: str
    configure: Callable[[ArgumentParser], None]
    run: Callable[[Namespace], int]
    group: str = "core"


class UsageError(Exception):
    """Raised instead of argparse's ``SystemExit`` so the UI can render it."""


class FocusParser(ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise UsageError(message)
