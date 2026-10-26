"""Argument parsing and the ``focus`` entry point."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from rich.text import Text

from focus import __version__, theme
from focus.commands import BY_NAME, COMMANDS
from focus.commands.base import Command, FocusParser, UsageError


class _TopHelp(argparse.Action):
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, **kwargs):
        super().__init__(option_strings, dest, nargs=0, default=default, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        render_help()
        parser.exit()


class _CommandHelp(argparse.Action):
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, command=None, **kwargs):
        super().__init__(option_strings, dest, nargs=0, default=default, **kwargs)
        self.command = command

    def __call__(self, parser, namespace, values, option_string=None):
        render_command_help(self.command, parser)
        parser.exit()


def command_parser(command: Command) -> FocusParser:
    parser = FocusParser(
        prog=f"focus {command.name}",
        add_help=False,
        description=command.summary,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    command.configure(parser)
    parser.add_argument("-h", "--help", action=_CommandHelp, command=command, help="show this help")
    return parser


def build_parser() -> FocusParser:
    parser = FocusParser(
        prog="focus",
        add_help=False,
        description="network security framework",
    )
    parser.add_argument("-h", "--help", action=_TopHelp, help="show this help")
    parser.add_argument("--version", action="version", version=f"focus {__version__}")

    subparsers = parser.add_subparsers(dest="command", parser_class=FocusParser)
    for command in COMMANDS:
        sub = subparsers.add_parser(
            command.name,
            help=command.summary,
            add_help=False,
            description=command.summary,
        )
        command.configure(sub)
        sub.add_argument("-h", "--help", action=_CommandHelp, command=command, help="show this help")
        sub.set_defaults(_command=command)

    return parser


# ------------------------------------------------------------------- help text
def _option_synopsis(action: argparse.Action) -> str:
    if not action.option_strings:
        return action.metavar or action.dest.upper()

    base = ", ".join(action.option_strings)
    if action.nargs == 0:
        return base
    metavar = action.metavar or action.dest.upper()
    return f"{base} {metavar}"


def _default_text(action: argparse.Action) -> str:
    if action.default in (None, False, "", 0, 0.0):
        return ""
    if isinstance(action.default, (list, tuple)):
        return ", ".join(str(item) for item in action.default)
    return str(action.default)


def render_command_help(command: Command, parser: argparse.ArgumentParser, prefix: str = "focus ") -> None:
    theme.blank()
    theme.console.print(Text.assemble(("  ", ""), (command.name, f"bold {theme.ACCENT}")))
    theme.console.print(Text(f"  {command.summary}", style=theme.MUTED))
    theme.blank()
    theme.console.print(Text(f"  usage  {prefix}{command.usage}", style=theme.TEXT))
    theme.blank()

    positionals = [a for a in parser._actions if not a.option_strings and a.dest != "help"]
    options = [a for a in parser._actions if a.option_strings and a.dest != "help"]

    table = theme.new_table()
    table.add_column("argument", style=f"bold {theme.TEXT}", no_wrap=True)
    table.add_column("default", style=theme.MUTED, no_wrap=True)
    table.add_column("description", style=theme.MUTED)

    for action in positionals + options:
        table.add_row(
            _option_synopsis(action),
            _default_text(action),
            action.help or "",
        )

    theme.show_table(table)
    theme.blank()
    theme.hint("run it from the shell as: /" + command.name + " …")


def render_help(*, show_banner: bool = True) -> None:
    if show_banner:
        theme.blank()
        theme.console.print(Text.assemble(("  FOCUS", f"bold {theme.ACCENT}"), ("   network security framework", theme.MUTED)))
        theme.console.print(Text(f"  v{__version__}", style=theme.FAINT))

    theme.blank()
    theme.console.print(Text.assemble(("  usage  ", theme.MUTED), ("focus <command> [options]", theme.TEXT)))
    shell_hint = "  (no arguments) opens the interactive shell" if theme.width() >= 62 else "  opens the interactive shell"
    theme.console.print(Text.assemble(("         ", ""), ("focus", theme.MUTED), (shell_hint, theme.FAINT)))

    theme.section("commands")
    table = theme.new_table()
    table.add_column("command", style=f"bold {theme.ACCENT}", no_wrap=True)
    table.add_column("description", style=theme.TEXT)

    core = [command for command in COMMANDS if command.group == "core"]
    optional = [command for command in COMMANDS if command.group != "core"]

    for command in core:
        table.add_row(command.name, command.summary)
    if optional:
        table.add_row("", "")
        table.add_row(Text("optional", style=theme.MUTED), "")
        for command in optional:
            table.add_row(command.name, command.summary)

    theme.show_table(table)
    theme.blank()
    theme.hint("focus <command> --help   ·   detailed options")


# ------------------------------------------------------------------------ main
def _die_pipe() -> int:
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except OSError:
        pass
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)

    if not arguments:
        from focus.shell import run as run_shell

        return run_shell()

    if arguments[0] == "help":
        if len(arguments) > 1 and arguments[1] in BY_NAME:
            render_command_help(BY_NAME[arguments[1]], command_parser(BY_NAME[arguments[1]]))
            return 0
        render_help()
        return 0

    parser = build_parser()
    try:
        args = parser.parse_args(arguments)
    except UsageError as error:
        theme.error(str(error))
        theme.hint("run `focus --help` for the command list")
        return 2

    command = getattr(args, "_command", None)
    if command is None:
        render_help()
        return 0

    try:
        return command.run(args) or 0
    except KeyboardInterrupt:
        theme.blank()
        theme.hint("interrupted")
        return 130
    except BrokenPipeError:
        return _die_pipe()
    except Exception as error:  # noqa: BLE001 - a CLI should fail cleanly
        theme.error(f"{type(error).__name__}: {error}")
        theme.hint("if this persists, run: python smoke_test.py")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
