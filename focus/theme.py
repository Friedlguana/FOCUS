"""Visual language for the FOCUS terminal interface.

Every command renders through the helpers in this module so spacing, colour and
glyphs stay consistent. The palette is deliberately restrained: one accent,
one muted grey ramp, and colour reserved for state.
"""

from __future__ import annotations

import math
from typing import Iterable, Sequence

from rich.console import Console, RenderableType
from rich.padding import Padding
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# --------------------------------------------------------------------- palette
ACCENT = "#7aa2f7"
ACCENT_DIM = "#3d59a1"
TEXT = "#c0caf5"
MUTED = "#565f89"
FAINT = "#3b4261"
BORDER = "#2f3549"
OK = "#9ece6a"
WARN = "#e0af68"
ERR = "#f7768e"
INFO = "#7dcfff"
SERIES_IN = "#7aa2f7"
SERIES_OUT = "#bb9af7"

LEVEL_STYLE = {
    "ok": OK,
    "warn": WARN,
    "error": ERR,
    "info": INFO,
    "muted": MUTED,
    "accent": ACCENT,
}

THEME = Theme(
    {
        "accent": ACCENT,
        "accent.dim": ACCENT_DIM,
        "text": TEXT,
        "muted": MUTED,
        "faint": FAINT,
        "ok": OK,
        "warn": WARN,
        "err": ERR,
        "info": INFO,
        "series.in": SERIES_IN,
        "series.out": SERIES_OUT,
        "key": f"bold {ACCENT}",
        "cmd": f"bold {ACCENT}",
        "label": MUTED,
        "value": TEXT,
        "head": f"bold {MUTED}",
        "rule.line": BORDER,
    }
)

console = Console(theme=THEME, highlight=False, emoji=False, soft_wrap=False)
# Human-facing diagnostics. ``--json`` commands switch to this console so the
# data stream on stdout stays parseable even when a lookup or write fails.
err_console = Console(theme=THEME, highlight=False, emoji=False, soft_wrap=False,
                      stderr=True)
_JSON_MODE = False


def set_json_mode(enabled: bool = True) -> None:
    global _JSON_MODE
    _JSON_MODE = bool(enabled)


def _diag() -> Console:
    return err_console if _JSON_MODE else console

# ----------------------------------------------------------------------- glyphs
LOGO = (
    "███████╗ ██████╗  ██████╗██╗   ██╗███████╗",
    "██╔════╝██╔═══██╗██╔════╝██║   ██║██╔════╝",
    "█████╗  ██║   ██║██║     ██║   ██║███████╗",
    "██╔══╝  ██║   ██║██║     ██║   ██║╚════██║",
    "██║     ╚██████╔╝╚██████╗╚██████╔╝███████║",
    "╚═╝      ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝",
)

BULLET = "●"
PROMPT = "❯"
ARROW = "→"

_SPARK = "▁▂▃▄▅▆▇█"


# --------------------------------------------------------------------- helpers
def safe(value: object) -> str:
    """Escape rich markup in untrusted text (process names, paths, ...)."""
    from rich.markup import escape

    return escape(str(value))


def indent(renderable: RenderableType, spaces: int = 2) -> Padding:
    return Padding(renderable, (0, 0, 0, spaces))


def width(default: int = 80) -> int:
    try:
        return max(40, console.width)
    except Exception:  # noqa: BLE001 - console width is best effort
        return default


def clear() -> None:
    if not console.is_terminal:
        return
    console.clear()  # visible screen
    # Also wipe the scrollback buffer, otherwise output from previous runs
    # stays above the fresh banner. ESC[3J needs a VT-capable terminal
    # (Windows Terminal and any modern terminal); legacy consoles ignore it.
    if console.color_system:
        console.file.write("\x1b[3J")
        console.file.flush()


def blank() -> None:
    _diag().print()


def line(char: str = "─", style: str = BORDER, spaces: int = 2) -> None:
    span = max(10, width() - spaces)
    _diag().print(Text(" " * spaces + char * span, style=style))


def section(title: str, detail: str | None = None) -> None:
    """A left-aligned heading with a hairline rule underneath."""
    blank()
    head = Text("  ")
    head.append(title, style=f"bold {TEXT}")
    if detail:
        pad = max(1, width() - 4 - len(title) - len(detail))
        head.append(" " * pad)
        head.append(detail, style=MUTED)
    _diag().print(head)
    _diag().print(Text("  " + "─" * max(10, width() - 4), style=BORDER))


def kv(pairs: Sequence[tuple[str, str]], columns: int = 2) -> None:
    """A quiet label/value grid used for session metadata."""
    if width() < 68:
        columns = 1

    grid = Table.grid(padding=(0, 2))
    for _ in range(columns):
        grid.add_column(justify="left", no_wrap=False)
        grid.add_column(justify="left", no_wrap=False)

    rows = list(pairs)
    for start in range(0, len(rows), columns):
        chunk = rows[start : start + columns]
        cells: list[Text] = []
        for label, value in chunk:
            lab = Text(f"{label}", style=MUTED)
            val = Text(str(value), style=TEXT)
            cells.extend([lab, val])
        while len(cells) < columns * 2:
            cells.extend([Text(""), Text("")])
        grid.add_row(*cells)

    console.print(indent(grid))


def banner(session: Sequence[tuple[str, str]] | None = None, *, show_logo: bool = True) -> None:
    """The shell header. Compact fallback for narrow terminals."""
    if show_logo and width() >= 62:
        for art in LOGO:
            console.print(Text("  " + art, style=ACCENT))
    else:
        console.print(Text.assemble(("  FOCUS", f"bold {ACCENT}")))

    console.print(Text("  network security framework", style=MUTED))

    if session:
        blank()
        kv(session)
        blank()


def new_table(*, box_style: object | None = None, expand: bool = False) -> Table:
    return Table(
        box=box_style,
        show_edge=False,
        pad_edge=False,
        expand=expand,
        border_style=BORDER,
        header_style=f"bold {MUTED}",
        row_styles=["", ""],
        padding=(0, 2),
    )


def show_table(table: Table, *, pad: int = 2) -> None:
    console.print(indent(table, pad))


def state(level: str, label: str) -> Text:
    """``● label`` with the colour for the given state."""
    colour = LEVEL_STYLE.get(level, MUTED)
    out = Text()
    out.append(BULLET, style=colour)
    out.append(" ")
    out.append(label, style=colour)
    return out


def max_pool(values: list[float], columns: int) -> list[float]:
    """Downsample to ``columns`` buckets, preserving peaks."""
    if len(values) <= columns:
        return list(values)
    step = len(values) / columns
    result = []
    for index in range(columns):
        start = int(index * step)
        end = max(start + 1, int((index + 1) * step))
        chunk = values[start:end]
        result.append(max(chunk) if chunk else 0.0)
    return result


def stat_grid(items: Sequence[tuple[str, str]]) -> None:
    """A row of ``value label`` cells used for dashboard summaries."""
    from rich.table import Table

    grid = Table.grid(padding=(0, 3))
    for _ in items:
        grid.add_column()
    cells = []
    for value, label in items:
        cell = Text()
        cell.append(value, style=f"bold {TEXT}")
        cell.append(" " + label, style=MUTED)
        cells.append(cell)
    grid.add_row(*cells)
    console.print(indent(grid))


def sparkline(values: Iterable[float], columns: int = 40) -> Text:
    """A downsampled block sparkline. Peaks are preserved by max pooling."""
    data = [float(v) for v in values if v is not None and not math.isnan(float(v))]
    if not data:
        return Text("─" * columns, style=FAINT)

    data = max_pool(data, columns)

    low, high = min(data), max(data)
    if high - low < 1e-9:
        return Text(_SPARK[0] * len(data), style=ACCENT)

    out = Text()
    for value in data:
        index = int(round((value - low) / (high - low) * (len(_SPARK) - 1)))
        out.append(_SPARK[index])
    return out


def fmt_rate(value: float) -> str:
    if value >= 100:
        return f"{value:,.0f}"
    if value >= 10:
        return f"{value:,.1f}"
    return f"{value:,.2f}"


def fmt_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024 or unit == "TB":
            return f"{num:,.1f} {unit}" if unit != "B" else f"{num:,.0f} B"
        num /= 1024
    return f"{num:,.1f} TB"


def fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def ok(message: str) -> None:
    _diag().print(Text("  "), state("ok", message))


def warn(message: str) -> None:
    _diag().print(Text("  "), state("warn", message))


def error(message: str, hint: str | None = None) -> None:
    text = Text("  ")
    text.append("✗", style=ERR)
    text.append("  ")
    text.append(message, style=ERR)
    _diag().print(text)
    if hint:
        _diag().print(Text(f"     {hint}", style=MUTED))


def info(message: str) -> None:
    _diag().print(Text("  "), state("info", message))


def hint(message: str) -> None:
    _diag().print(Text(f"  {message}", style=MUTED))


def prompt_text() -> str:
    return f"[bold {ACCENT}]{PROMPT}[/] "


def ask(prompt: str, default: str | None = None) -> str:
    """Read a line, returning ``default`` on empty input."""
    suffix = f" [{MUTED}]{default}[/]" if default else ""
    try:
        value = console.input(f"  [bold {ACCENT}]?[/] {safe(prompt)}{suffix} ")
    except (EOFError, KeyboardInterrupt):
        console.print()
        return default or ""
    return value.strip() or (default or "")


def confirm(prompt: str, *, default: bool = False) -> bool:
    from rich.prompt import Confirm

    try:
        return Confirm.ask(f"  [bold {ACCENT}]?[/] {safe(prompt)}", default=default, console=console)
    except (EOFError, KeyboardInterrupt):
        console.print()
        return False
