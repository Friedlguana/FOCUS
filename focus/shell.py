"""Interactive shell.

Behaves like the CLI with a persistent session: commands may be typed with or
without a leading slash, long-running views return to the prompt on ctrl-c, and
errors never terminate the shell.
"""

from __future__ import annotations

import difflib
import shlex
import sys
import time
from pathlib import Path

from rich.text import Text

from focus import __version__, theme
from focus.cli import command_parser, render_command_help
from focus.commands import BY_NAME, COMMANDS
from focus.commands.base import UsageError
from focus.core.net import hostname, local_ip
from focus.core.paths import INBOUND_MODEL, OUTBOUND_MODEL
from focus.core.store import read_traffic

HELP_WORDS = ("help", "?", "h")
EXIT_WORDS = ("exit", "quit", "q")


def _split(line: str) -> list[str]:
    try:
        parts = shlex.split(line, posix=False)
    except ValueError:
        parts = line.split()
    cleaned = []
    for part in parts:
        if len(part) > 1 and part[0] == part[-1] and part[0] in "\"'":
            part = part[1:-1]
        cleaned.append(part)
    return cleaned


def _session() -> list[tuple[str, str]]:
    samples = read_traffic()
    models = sum(1 for path in (INBOUND_MODEL, OUTBOUND_MODEL) if path.exists())
    span = f" · t={samples[0].elapsed}–{samples[-1].elapsed}" if samples else ""
    return [
        ("host", f"{local_ip()} · {hostname()}"),
        ("directory", str(Path.cwd())),
        ("traffic log", f"{len(samples)} samples{span}"),
        ("models", f"{models} present"),
        ("python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"),
        ("version", __version__),
    ]


def _print_help() -> None:
    theme.section("commands")

    table = theme.new_table()
    table.add_column("command", style=f"bold {theme.ACCENT}", no_wrap=True)
    table.add_column("description", style=theme.TEXT)

    optional = [command for command in COMMANDS if command.group != "core"]
    for command in COMMANDS:
        if command.group != "core" or command.name == "models":
            continue
        table.add_row("/" + command.name, command.summary)
    if optional:
        table.add_row("", "")
        table.add_row(Text("optional", style=theme.MUTED), "")
        for command in optional:
            table.add_row("/" + command.name, command.summary)
    table.add_row("", "")
    table.add_row("/models", next(c.summary for c in COMMANDS if c.name == "models"))
    table.add_row("/help", "Show this help")
    table.add_row("/clear", "Clear the screen")
    table.add_row("/exit", "Quit FOCUS")
    theme.show_table(table)
    theme.blank()


def _dispatch(line: str) -> tuple[bool, int]:
    """Execute one shell line. Returns ``(keep_running, exit_code)``."""
    text = line.strip()
    if not text:
        return True, 0

    if text.startswith("/"):
        text = text[1:].strip()
    if text.lower().startswith("focus "):
        text = text[6:].strip()
    if not text:
        return True, 2

    parts = _split(text)
    name, rest = parts[0], parts[1:]
    lowered = name.lower()

    if lowered in EXIT_WORDS:
        return False, 0
    if lowered in HELP_WORDS:
        if rest and rest[0] in BY_NAME:
            render_command_help(BY_NAME[rest[0]], command_parser(BY_NAME[rest[0]]), prefix="/")
        else:
            _print_help()
        return True, 0
    if lowered in ("clear", "cls"):
        theme.clear()
        return True, 0

    command = BY_NAME.get(lowered)
    if command is None:
        theme.error(f"unknown command: {name}")
        match = difflib.get_close_matches(lowered, list(BY_NAME), n=1, cutoff=0.5)
        if match:
            theme.hint(f"did you mean /{match[0]}?")
        else:
            theme.hint("type /help for the command list")
        return True, 2

    try:
        args = command_parser(command).parse_args(rest)
    except UsageError as error:
        theme.error(str(error))
        theme.hint(f"/{command.name} --help")
        return True, 2
    except SystemExit:
        return True, 0

    try:
        code = command.run(args) or 0
    except KeyboardInterrupt:
        theme.blank()
        theme.hint("stopped")
        code = 130
    except BrokenPipeError:
        return False, 0
    except Exception as error:  # noqa: BLE001 - never kill the session
        theme.error(f"{type(error).__name__}: {error}")
        theme.hint("if this persists, exit and run: python smoke_test.py")
        code = 1
    finally:
        # A --json command must not leave diagnostics redirected for the
        # next command in this long-lived shell session.
        theme.set_json_mode(False)

    return True, code


def run() -> int:
    started = time.monotonic()
    theme.clear()
    theme.banner(_session())
    _print_help()  # show the command list immediately, not only on /help

    interrupts = 0
    while True:
        try:
            line = theme.console.input(theme.prompt_text())
        except EOFError:
            theme.blank()
            break
        except KeyboardInterrupt:
            interrupts += 1
            theme.console.print()
            if interrupts >= 2:
                break
            theme.hint("ctrl-c again to exit · /exit also quits")
            continue

        interrupts = 0
        keep_running, _ = _dispatch(line)
        if not keep_running:
            break
        theme.blank()

    if not theme.console.is_terminal:
        theme.console.print()
    theme.hint(f"session closed · {theme.fmt_duration(time.monotonic() - started)}")
    return 0
