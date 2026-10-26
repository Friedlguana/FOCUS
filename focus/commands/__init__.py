"""Command registry."""

from __future__ import annotations

from .base import Command
from .dashboard import COMMAND as DASHBOARD
from .demo import COMMAND as DEMO
from .models import COMMAND as MODELS

COMMANDS: list[Command] = [
    DASHBOARD,
    DEMO,
    MODELS,
]

BY_NAME = {command.name: command for command in COMMANDS}

__all__ = ["COMMANDS", "BY_NAME", "Command"]
