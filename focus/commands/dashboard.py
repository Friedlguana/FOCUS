"""``focus dashboard`` - everything FOCUS sees, on one live terminal screen.

One process, one screen, every section at once:

  ports        background port scan with service, process and risk
  vitals       surge level, rates, download attribution, events (side panel)
  activity     per-process I/O and live connections
  endpoints    who the machine talks to - organisations and locations
  history      live throughput while sampling, then the recorded CSV chart

Keys (interactive terminal): c closes every found port owner · ↑↓ selects a
port or process and Enter closes it · r rescans · q or ctrl-c quits.
Redirected output stays line-oriented (``--json`` makes it machine-readable);
``--tab <name>`` renders that single section once and exits, on a terminal
too. The old
``scan``, ``watch``, ``geo`` and ``graph`` commands are merged here - the
one-shot geo features survive as ``--map``, ``--history`` and ``--downloads``.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import sys
import threading
import time
from collections import deque
from pathlib import Path

from rich import box
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from focus import theme
from focus.core import geo
from focus.core.anomaly import CALM, SURGE, RollingDetector, combine, demo_offset
from focus.core.browsers import browser_downloads, browser_history
from focus.core.net import (
    ProcessSampler,
    ThroughputSampler,
    established_connections,
)
from focus.core.ports import (
    RISK_ORDER,
    collect_findings,
    parse_port_spec,
    scan_ports,
)
from focus.core.paths import TRAFFIC_CSV
from focus.core.privileges import (
    environment_note,
    request_elevation,
    summarize,
    terminate_many,
)
from focus.core.store import (
    TrafficSample,
    append_traffic,
    last_elapsed,
    read_traffic,
    timestamp,
)

from .base import Command

LEVEL_COLOUR = {CALM: theme.OK, "elevated": theme.WARN, SURGE: theme.ERR}
# A download is *sustained asymmetric inbound*: inbound above the floor AND
# above DOWNLOAD_ASYMMETRY times the outbound. The fixed 5 Mbps rule missed
# real Chrome downloads on slow links (background traffic alone peaks near
# 4 Mbps there) - the asymmetry is what separates downloads from browsing
# noise, not the absolute rate.
DOWNLOAD_FLOOR_MBPS = 1.0
DOWNLOAD_ASYMMETRY = 3.0
DOWNLOAD_BYTES_PER_MBPS_SECOND = 1_024_000 / 8
TAB_NAMES = ("overview", "ports", "endpoints", "history")


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tab", choices=TAB_NAMES, help="start on a specific tab")
    parser.add_argument("--ports", default="all", help="range for the ports tab (default: all 65,535)")
    parser.add_argument("--host", default="127.0.0.1", help="scan target")
    parser.add_argument("--timeout", type=float, default=0.25, help="scan connect timeout in seconds")
    parser.add_argument("--workers", type=int, default=2000, help="scan concurrent probes")
    parser.add_argument("--interval", type=float, default=1.0, help="sample interval in seconds")
    parser.add_argument("--no-processes", action="store_true", help="hide the process panel on the overview tab")
    parser.add_argument("--duration", type=float, default=0.0, help="stop after N seconds (0 = until quit)")
    parser.add_argument("--last", type=int, default=120, help="history tab: samples to chart")
    parser.add_argument("--record", action="store_true", help="append samples to the traffic CSV")
    parser.add_argument("--csv", type=Path, default=TRAFFIC_CSV, help="destination CSV with --record")
    parser.add_argument("--threshold", type=float, default=2.5, help="surge z-score")
    parser.add_argument("--download-threshold", type=float, default=DOWNLOAD_FLOOR_MBPS,
                        help="inbound Mbps floor for a download (must also exceed outbound 3x)")
    parser.add_argument("--sustain", type=int, default=2, help="consecutive samples that confirm an event")
    parser.add_argument("--no-geo", action="store_true", help="skip endpoint organisation lookups")
    parser.add_argument("--demo", action="store_true", help="inject a synthetic 50 Mbps spike at t+8s")
    parser.add_argument("--map", action="store_true", help="write server_location_map.html, then continue")
    parser.add_argument("--history", action="store_true", help="print the browser's top domains and exit")
    parser.add_argument("--history-days", type=int, default=7, help="history window in days")
    parser.add_argument("--downloads", action="store_true", help="print the browser's download records and exit")
    parser.add_argument("--json", action="store_true", help="newline-delimited JSON samples and events")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation in the bulk close flow (c)")
    parser.add_argument("--no-elevate", action="store_true",
                        help="never request UAC; report processes that need administrator rights")


# ------------------------------------------------------------------- input
@contextlib.contextmanager
def key_reader():
    """Yield a ``read() -> str | None`` for the last keypress, cross-platform.

    The pump thread stops when the context exits - otherwise it would keep
    consuming the keystrokes meant for whatever reads stdin next (the shell
    prompt, after ``/dashboard`` returns).
    """
    import queue

    keys: queue.Queue = queue.Queue()
    stop = threading.Event()

    if os.name == "nt":
        import msvcrt

        arrows = {"H": "UP", "P": "DOWN", "K": "LEFT", "M": "RIGHT"}

        def pump():
            while not stop.is_set():
                if msvcrt.kbhit():
                    char = msvcrt.getwch()
                    if char in ("\x00", "\xe0"):  # arrow/function keys
                        code = msvcrt.getwch()
                        if code in arrows:
                            keys.put(arrows[code])
                        continue
                    keys.put(char)
                stop.wait(0.03)

    else:
        import select
        import termios
        import tty

        def pump():
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                while not stop.is_set():
                    ready, _, _ = select.select([fd], [], [], 0.05)
                    if not ready:
                        continue
                    char = sys.stdin.read(1)
                    if char == "\x1b":  # escape sequence: try to assemble it
                        more = ""
                        for _ in range(2):
                            r2, _, _ = select.select([fd], [], [], 0.01)
                            if not r2:
                                break
                            more += sys.stdin.read(1)
                        if more == "[A":
                            keys.put("UP")
                        elif more == "[B":
                            keys.put("DOWN")
                        elif more == "[C":
                            keys.put("RIGHT")
                        elif more == "[D":
                            keys.put("LEFT")
                        else:
                            keys.put("\x1b")  # bare esc
                            for ch in more:
                                keys.put(ch)
                    else:
                        keys.put(char)
            except Exception:  # noqa: BLE001 - stdin closed / not a tty
                pass
            finally:
                with contextlib.suppress(Exception):
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)

    threading.Thread(target=pump, daemon=True).start()
    try:
        def read() -> str | None:
            try:
                return keys.get_nowait()
            except queue.Empty:
                return None

        yield read
    finally:
        stop.set()


# ------------------------------------------------------------------ views
def _main_width() -> int:
    """Width available to the main panel (side panel takes ~30 columns when wide)."""
    total = theme.width()
    if total >= 100:
        return max(40, int(total * 0.66) - 6)
    return max(40, total - 6)


def _rows() -> int:
    return max(20, theme.console.height or 24)


def _vitals(state: dict, args: argparse.Namespace) -> Table:
    """Always-on vitals for the side panel (every line ≤ ~30 chars)."""
    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(width=1)
    grid.add_column(justify="left")
    grid.add_column(justify="right")

    status = state["surge"]
    colour = LEVEL_COLOUR.get(status["level"], theme.MUTED)
    top = Text(status["level"].upper(), style=f"bold {colour}")
    top.append(f" · {status['events']} ev", style=theme.MUTED)
    grid.add_row(Text("●", style=colour), top,
                 Text(f"z {status['z']:.2f}", style=theme.TEXT))

    for key, icon, colour in (("in", "↓", theme.SERIES_IN), ("out", "↑", theme.SERIES_OUT)):
        grid.add_row(
            Text(icon, style=colour),
            Text(f"{theme.fmt_rate(state[key])} Mbps", style=f"bold {colour}"),
            Text(f"peak {theme.fmt_rate(max(state[key + '_history']) if state[key + '_history'] else 0.0)}",
                 style=theme.MUTED),
        )

    totals = state.get("totals") or {"in": 0.0, "out": 0.0}
    grid.add_row(Text("Σ"), Text(f"{theme.fmt_bytes(totals['in'])} in · {theme.fmt_bytes(totals['out'])} out",
                                 style=theme.MUTED), Text(""))

    download = state["download"]
    if download["active"]:
        grid.add_row(Text("⤓", style=theme.ERR),
                     Text("DOWNLOADING", style=f"bold {theme.ERR}"),
                     Text(theme.fmt_bytes(download["size"]), style=f"bold {theme.TEXT}"))
        if download["process"]:
            grid.add_row(Text(""), Text(download["process"][:24], style=theme.TEXT), Text(""))
        if download["org"]:
            grid.add_row(Text(""), Text(f"← {download['org']}"[:26], style=theme.MUTED), Text(""))
    else:
        grid.add_row(Text(""), Text("no download", style=theme.FAINT), Text(""))

    # scan status + host keep the panel full when idle
    if state.get("scanning"):
        pct = state.get("scan_done", 0) * 100 // max(state.get("scan_total", 1), 1)
        grid.add_row(Text("⌕"), Text(f"scan {state.get('scan_spec', '')}"[:24], style=theme.MUTED),
                     Text(f"{pct}%", style=theme.TEXT))
    else:
        found = len(state.get("findings") or [])
        grid.add_row(Text("⌕"), Text(f"scan done · {found} open" if found else "scan clean",
                                     style=theme.MUTED), Text(""))
    if state.get("host"):
        grid.add_row(Text(""), Text(str(state["host"])[:28], style=theme.FAINT), Text(""))

    if state["events"]:
        grid.add_row(Text(""), Text("─" * 24, style=theme.BORDER), Text(""))
        for event in list(state["events"])[-3:][::-1]:
            style = theme.ERR if event["kind"] in ("surge", "download") else theme.MUTED
            grid.add_row(Text(""), Text(f"{event['time']} {event['text']}"[:30], style=style), Text(""))
    return grid


def _process_table(rates, limit: int = 6, highlight: str | None = None,
                   selected: int | None = None) -> Table:
    table = theme.new_table()
    table.add_column("process", style=theme.TEXT)
    table.add_column("pid", justify="right", style=theme.MUTED, width=7)
    table.add_column("read", justify="right", style=theme.SERIES_IN, width=11)
    table.add_column("write", justify="right", style=theme.SERIES_OUT, width=11)
    for index, rate in enumerate(rates[:limit]):
        name = Text(rate.name)
        if highlight and rate.name.lower() == highlight.lower():
            name = Text(rate.name, style=f"bold {theme.ACCENT}")
            name.append("  ◄ downloading", style=theme.OK)
        row_style = "bold reverse" if selected == index and not highlight else None
        table.add_row(name, str(rate.pid),
                      theme.fmt_rate(rate.read), theme.fmt_rate(rate.write),
                      style=row_style)
    return table


def _connection_table(connections, limit: int = 6) -> Table:
    table = theme.new_table()
    table.add_column("remote", style=theme.TEXT)
    table.add_column("process", style=theme.MUTED)
    table.add_column("local", justify="right", style=theme.FAINT, width=7)
    for conn in connections[:limit]:
        table.add_row(f"{conn.remote_ip}:{conn.remote_port}", Text(conn.process), str(conn.local_port))
    return table


def _events_table(events: list[dict], limit: int = 5) -> Table:
    table = theme.new_table()
    table.add_column("time", style=theme.MUTED, width=9)
    table.add_column("event", width=9)
    table.add_column("detail", style=theme.TEXT)
    for event in list(events)[-limit:][::-1]:
        style = theme.ERR if event["kind"] in ("surge", "download") else theme.MUTED
        table.add_row(event["time"], Text(event["kind"], style=style), Text(event["text"]))
    return table


def _window(total: int, limit: int, selected: int | None) -> tuple[int, int]:
    """Visible slice that keeps ``selected`` on screen."""
    limit = max(1, min(limit, total)) if total else 0
    if total <= limit:
        return 0, total
    if selected is None:
        return 0, limit
    start = max(0, min(selected - limit // 2, total - limit))
    return start, start + limit


def _view_overview(state: dict, args: argparse.Namespace):
    body = Table.grid(expand=True)
    body.add_column()

    ui = state.get("ui", {})
    n_ports = len(state.get("findings") or [])
    sel = state.get("sel", 0) - n_ports  # process index within the selection list
    if not args.no_processes:
        body.add_row(Text("process i/o", style=f"bold {theme.MUTED}"))
        limit = ui.get("procs", 5)
        processes = state["processes"]
        process_sel = sel if 0 <= sel < len(processes) else None
        start, end = _window(len(processes), limit, process_sel)
        highlight = state["download"]["process"] if state["download"]["active"] else None
        body.add_row(_process_table(processes[start:end], limit,
                                    highlight,
                                    selected=(process_sel - start) if process_sel is not None else None)
                      if processes else Text("  sampling…", style=theme.FAINT))
        if len(processes) > end - start:
            body.add_row(Text(f"  rows {start + 1}–{end} of {len(processes)} · ↑↓ scroll",
                              style=theme.FAINT))
        body.add_row(Text("  i/o = disk + network per process · svchost hosts"
                          " Update/Defender/indexing", style=theme.FAINT))
        body.add_row(Text(""))

    # live connections: only when the region is tall enough to fit them
    if ui.get("conns", 0) and (_rows() >= 30 or args.no_processes):
        body.add_row(Text("connections", style=f"bold {theme.MUTED}"))
        body.add_row(_connection_table(state["connections"], ui["conns"]) if state["connections"]
                     else Text("  no established external connections", style=theme.FAINT))
    return body


def _view_ports(state: dict, args: argparse.Namespace):
    if state.get("scan_error"):
        return Text(f"  scan failed: {state['scan_error']}", style=theme.ERR)

    findings = state["findings"]
    body = Table.grid(expand=True)
    body.add_column()

    # Results first, at a CONSTANT row limit: the progress line goes at the
    # bottom, so the table never shifts when a sweep starts or ends.
    if findings:
        limit = state.get("ui", {}).get("ports", 7)
        sel = state.get("sel", 0)
        selected = sel if sel < len(findings) else None
        start, end = _window(len(findings), limit, selected)
        table = theme.new_table()
        table.add_column("port", justify="right", style=f"bold {theme.TEXT}", no_wrap=True)
        table.add_column("service", style=theme.TEXT, no_wrap=True)
        table.add_column("process", style=theme.TEXT)
        table.add_column("risk", justify="right", no_wrap=True)
        for index in range(start, end):
            item = findings[index]
            process = ", ".join(item.processes) if item.processes else "—"
            row_selected = selected == index and not state.get("dialog")
            table.add_row(str(item.port), item.service, Text(process),
                          Text(item.risk, style=_risk_style(item.risk)),
                          style="bold reverse" if row_selected else None)
        body.add_row(table)
        if len(findings) > end - start:
            body.add_row(Text(f"  rows {start + 1}–{end} of {len(findings)} · ↑↓ scroll",
                              style=theme.FAINT))
    elif findings is not None:
        body.add_row(Text(f"  no open ports on {args.host} ({state['scan_spec']})", style=theme.OK))
    else:
        body.add_row(Text(f"  waiting for the first scan of {args.host}…", style=theme.MUTED))

    # The progress line is LAST so it appears and disappears without moving
    # the results above it.
    if state.get("scanning"):
        done, total = state.get("scan_done", 0), state.get("scan_total", 0)
        width = max(24, min(72, _main_width() - 52))
        filled = width * done // max(total, 1)
        # Lower-eighth blocks render as a 1-pixel horizon line, not a bar.
        bar = Text("  ")
        bar.append("▁" * filled, style=theme.OK)
        bar.append("▁" * (width - filled), style=theme.BORDER)
        bar.append(f" {done * 100 // max(total, 1):3d}%", style=theme.MUTED)
        bar.append(" · rescanning", style=theme.FAINT)
        body.add_row(bar)
    return body


def _risk_style(risk: str) -> str:
    return {"critical": f"bold {theme.ERR}", "high": theme.ERR,
            "medium": theme.WARN, "low": theme.MUTED}.get(risk, theme.MUTED)


def _view_endpoints(state: dict, args: argparse.Namespace):
    grouped: dict[str, set[str]] = {}
    for conn in state["all_connections"]:
        if conn.private:
            continue
        grouped.setdefault(conn.remote_ip, set()).add(conn.process)
    ordered = sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0]))[: state.get("ui", {}).get("eps", 8)]

    body = Table.grid(expand=True)
    body.add_column()
    if not ordered:
        body.add_row(Text("  no established external connections", style=theme.FAINT))
        return body

    table = theme.new_table()
    table.add_column("address", style=f"bold {theme.TEXT}", no_wrap=True)
    table.add_column("organisation", style=theme.TEXT)
    table.add_column("location", style=theme.MUTED)
    table.add_column("process", style=theme.MUTED)
    located = 0
    for address, processes in ordered:
        if args.no_geo:
            org, where = "—", "—"
        elif address not in state["geo"]:
            org, where = "resolving…", ""
        else:
            result = state["geo"].get(address)
            if result:
                located += 1
                org, where = result.isp, result.location
            else:
                org, where = "unavailable", "—"
        table.add_row(address, Text(org), Text(where), Text(", ".join(sorted(processes))))
    body.add_row(table)
    body.add_row(Text(f"  {located}/{len(ordered)} located · refreshed live", style=theme.FAINT))
    return body


_BRAILLE_BIT = {(0, 0): 0x01, (0, 1): 0x02, (0, 2): 0x04, (0, 3): 0x40,
                (1, 0): 0x08, (1, 1): 0x10, (1, 2): 0x20, (1, 3): 0x80}


def _braille_series(values: list[float], *, cell_rows: int, width: int, colour: str) -> list[Text]:
    """A connected line graph drawn in braille dots: each character is a 2x4
    dot cell, so the curve has sub-character horizontal and vertical detail.

    The series is stretched to the full panel width (interpolated when there
    are fewer samples than columns, peak-pooled when there are more), and the
    height is fixed (``cell_rows`` lines) so it cannot clip.
    """
    width = max(20, width)
    vals = [max(0.0, v) for v in values]
    if len(vals) < 2:
        # nothing to draw yet (first frame) - a flat line, never an error
        return [Text("  " + "─" * width, style=theme.BORDER) for _ in range(cell_rows)]
    cols = width * 2
    if len(vals) >= cols:
        pts = theme.max_pool(vals, cols)
    else:
        pts = []
        for i in range(cols):
            pos = i * (len(vals) - 1) / max(cols - 1, 1)
            low = int(pos)
            high = min(low + 1, len(vals) - 1)
            weight = pos - low
            pts.append(vals[low] * (1 - weight) + vals[high] * weight)
    peak = max(pts) if pts else 0.0
    use_log = peak > 2.0
    scale = math.log1p(peak) if use_log else peak

    def frac(v: float) -> float:
        return math.log1p(v) / scale if use_log and v > 0 else (v / scale if v > 0 else 0.0)

    rows = cell_rows * 4
    grid = [[0] * width for _ in range(cell_rows)]
    prev_y = None
    for x, v in enumerate(pts):
        y = rows - 1 - round(frac(v) * (rows - 1))
        cx, sx = x // 2, x % 2
        if prev_y is not None and abs(prev_y - y) > 1:
            # connect the vertical gap so spikes draw as lines, not dots
            for yy in range(min(prev_y, y), max(prev_y, y) + 1):
                grid[yy // 4][cx] |= _BRAILLE_BIT[(sx, yy % 4)]
        grid[y // 4][cx] |= _BRAILLE_BIT[(sx, y % 4)]
        prev_y = y

    lines = []
    for row in range(cell_rows):
        line = Text("  ")
        for col in range(width):
            bits = grid[row][col]
            line.append(chr(0x2800 + bits) if bits else " ", style=colour)
        lines.append(line)
    return lines


def _view_history(state: dict, args: argparse.Namespace):
    body = Table.grid(expand=True)
    body.add_column()

    live_in, live_out = state.get("live_in") or [], state.get("live_out") or []
    if len(live_in) >= 4:
        inbound, outbound = list(live_in), list(live_out)
        source = f"live · {len(live_in)} samples @ 4/s"
        span = len(inbound) / 4.0
        start = max(0.0, float(state.get("elapsed") or 0.0) - span)
        end = float(state.get("elapsed") or 0.0)
    else:
        samples = state["history_samples"]
        if not samples:
            body.add_row(Text("  sampling live traffic…", style=theme.MUTED))
            return body
        inbound = [s.inbound for s in samples]
        outbound = [s.outbound for s in samples]
        source = f"recorded · {len(samples)} samples"
        start, end = samples[0].elapsed, samples[-1].elapsed

    def axis(value: float) -> str:
        return f"{value:.1f}".rstrip("0").rstrip(".")

    width = max(30, theme.width() - 8)
    cells = state.get("ui", {}).get("cells", 2)
    for label, colour, values in (("inbound", theme.SERIES_IN, inbound),
                                  ("outbound", theme.SERIES_OUT, outbound)):
        head = Text("  ")
        head.append(label, style=f"bold {colour}")
        head.append(f"   peak {theme.fmt_rate(max(values))} Mbps", style=theme.MUTED)
        head.append(f"   {source} · t={axis(start)}–{axis(end)}s", style=theme.FAINT)
        body.add_row(head)
        for line in _braille_series(values, cell_rows=cells, width=width, colour=colour):
            body.add_row(line)
    return body


VIEWS = {name: view for name, view in (
    ("overview", _view_overview), ("ports", _view_ports),
    ("endpoints", _view_endpoints), ("history", _view_history))}


def _header(state: dict, args: argparse.Namespace) -> Table:
    bar = Table.grid(expand=True, padding=(0, 1))
    bar.add_column(justify="left")
    bar.add_column(justify="right")

    title = Text(" FOCUS", style=f"bold {theme.ACCENT}")
    if args.demo:
        title.append(" demo", style=f"bold {theme.WARN}")
    title.append("  network security framework", style=theme.MUTED)
    keys = Text("  ↑↓ select · Enter close · r rescan · q quit  ·  ", style=theme.FAINT)
    keys.append(theme.fmt_duration(state["elapsed"]), style=theme.MUTED)
    bar.add_row(title, keys)
    return bar


def _attribute_download(state: dict) -> str:
    """Best-guess owner of an in-progress download.

    Windows has no per-process network counters, and io_counters mixes disk
    with socket I/O. A browser download is write-heavy (socket to disk) while
    svchost-hosted services (Update, Defender, indexing) READ heavily in
    parallel - ranking by reads attributes the download to the wrong process.
    So: prefer processes that hold an external connection, and among those,
    the one whose write rate matches the transfer.
    """
    net_procs = {c.process.lower() for c in (state.get("connections") or [])
                 if not c.private and c.process and c.process != "—"}
    ranked = sorted(state.get("processes") or [], key=lambda r: r.write, reverse=True)
    for rate in ranked:
        if rate.name.lower() in net_procs:
            return rate.name
    fallback = sorted(state.get("processes") or [], key=lambda r: r.total, reverse=True)
    return fallback[0].name if fallback else ""


def _selectable_items(state: dict, args: argparse.Namespace) -> list[dict]:
    """The rows the user can cycle through with the arrow keys: every open
    port (close its owners) followed by every visible process (close it)."""
    items: list[dict] = []
    for item in state.get("findings") or []:
        items.append({
            "kind": "port", "port": item.port, "service": item.service,
            "risk": item.risk, "pids": list(item.pids),
            "processes": list(item.processes), "bind": item.bind,
        })
    if not args.no_processes:
        for rate in state.get("processes") or []:
            items.append({"kind": "proc", "pid": rate.pid, "name": rate.name,
                          "read": rate.read, "write": rate.write})
    return items


def _dialog_panel(dialog: dict) -> Panel:
    """The small centred dialog: what will be closed, and how to confirm."""
    item = dialog.get("item") or {}
    body = Table.grid(expand=True, padding=(0, 1))
    body.add_column()

    if item["kind"] == "port":
        title = Text(" close port owners ", style=f"bold {theme.ERR}")
        body.add_row(Text(f"port {item['port']} - {item['service']} - risk {item['risk']}",
                          style=f"bold {theme.TEXT}"))
        owners = ", ".join(item["processes"]) or "unknown"
        body.add_row(Text(f"owners: {owners}", style=theme.TEXT))
        if item.get("bind"):
            body.add_row(Text(f"bound to: {item['bind']}", style=theme.MUTED))
        pids = item["pids"]
    else:
        title = Text(" close process ", style=f"bold {theme.ERR}")
        body.add_row(Text(f"{item['name']} (pid {item['pid']})", style=f"bold {theme.TEXT}"))
        body.add_row(Text(f"i/o: read {theme.fmt_rate(item['read'])} - "
                          f"write {theme.fmt_rate(item['write'])} Mbps", style=theme.MUTED))
        pids = [item["pid"]]

    if os.getpid() in [pid for pid in pids if pid]:
        body.add_row(Text("! this is the dashboard itself - it cannot close its own process",
                          style=f"bold {theme.WARN}"))

    names = {str(name).lower() for name in item.get("processes") or []}
    if item.get("kind") == "proc":
        names.add(str(item.get("name") or "").lower())
    if "svchost.exe" in names:
        body.add_row(Text("! svchost hosts several services - prefer: sc stop <service>",
                          style=f"bold {theme.WARN}"))
    elif names & {"lsass.exe", "csrss.exe", "winlogon.exe", "wininit.exe", "services.exe"}:
        body.add_row(Text("! this is a critical Windows process - closing it can log you out",
                          style=f"bold {theme.WARN}"))

    notice = dialog.get("notice")
    if notice:
        body.add_row(Text(""))
        body.add_row(Text(notice, style=theme.WARN))

    body.add_row(Text(""))
    actions = Text("  ")
    if dialog.get("elevate"):
        actions.append("Enter", style=f"bold {theme.WARN}")
        actions.append(" retry with UAC   ", style=theme.MUTED)
    else:
        actions.append("Enter", style=f"bold {theme.OK}")
        actions.append(" terminate   ", style=theme.MUTED)
    actions.append("Esc", style=f"bold {theme.ACCENT}")
    actions.append(" cancel", style=theme.MUTED)
    body.add_row(actions)

    return Panel(body, box=box.ROUNDED, border_style=theme.ERR,
                 title=title, title_align="left", padding=(0, 2))


def _dialog_pids(dialog: dict) -> list[int]:
    item = dialog.get("item") or {}
    pids = item.get("pids") if item.get("kind") == "port" else [item.get("pid")]
    return [pid for pid in (pids or []) if pid]


def _close_results_text(results) -> str:
    closed, failed, elevated = summarize(results)
    parts = [f"closed {closed}/{len(results)}"]
    if failed:
        parts.append("failed: " + ", ".join(f"{item.name} ({item.pid})" for item in failed))
    if elevated:
        parts.append(f"{len(elevated)} need administrator rights")
    return " · ".join(parts)


def _retry_elevated(state: dict, args: argparse.Namespace) -> None:
    dialog = state.get("dialog") or {}
    pids = _dialog_pids(dialog)
    label = state.get("dialog_label") or "selection"
    outcome = request_elevation(pids)
    if outcome.cancelled:
        notice = "administrator prompt cancelled - nothing was closed"
    elif outcome.error:
        notice = outcome.error
    else:
        closed, failed, elevated = summarize(outcome.results)
        notice = f"elevated close: {closed}/{len(outcome.results)} closed"
        if failed:
            notice += " · failed: " + ", ".join(f"{item.name} ({item.pid})" for item in failed)
        if elevated:
            notice += " · access still denied"
    state["dialog"] = None
    state["events"].append({"time": timestamp(), "kind": "demo",
                            "text": f"{notice} - {label}"})
    _start_scan(state, args)


def _confirm_close(state: dict, args: argparse.Namespace) -> None:
    """Terminate whatever the open dialog points at, then rescan to verify."""
    dialog = state.get("dialog") or {}
    if dialog.get("elevate"):
        _retry_elevated(state, args)
        return

    item = dialog.get("item") or {}
    pids = _dialog_pids(dialog)
    label = (f"port {item['port']}" if item["kind"] == "port"
             else f"{item.get('name')} (pid {item.get('pid')})")
    results = terminate_many(pids)
    _closed, _failed, elevated = summarize(results)

    if elevated and not args.no_elevate:
        state["dialog"] = {
            "item": item,
            "elevate": True,
            "notice": (f"{len(elevated)} process(es) must be elevated. "
                       "Enter opens the Windows UAC prompt; the dashboard stays unprivileged."),
        }
        state["dialog_label"] = label
        state["events"].append({"time": timestamp(), "kind": "demo",
                                "text": f"needs administrator rights - {label}"})
        return

    text = _close_results_text(results) + f" - {label}"
    if elevated and args.no_elevate:
        text += " (elevation disabled with --no-elevate)"
    state["events"].append({"time": timestamp(), "kind": "demo", "text": text})
    state["dialog"] = None
    state["dialog_label"] = ""
    _start_scan(state, args)  # rescan so the panel proves the port is gone


def _screen(state: dict, args: argparse.Namespace):
    """The whole terminal, everything at once: ports + vitals on top, activity +
    endpoints in the middle, the history chart below, and a key-hint footer."""
    from rich.align import Align
    from rich.layout import Layout

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=1),
        Layout(name="rule", size=1),
        Layout(name="body"),
        # One empty row at the very bottom: if cmd reports a height larger
        # than the visible window (conhost buffer quirk), the crop eats this
        # padding instead of the history panel.
        Layout(name="pad", size=1),
    )

    layout["header"].update(_header(state, args))
    layout["rule"].update(Text("─" * max(10, theme.width() - 2), style=theme.BORDER))
    layout["pad"].update(Text(""))  # else rich outlines the empty region

    body_rows = max(18, _rows() - 3)  # header+rule+pad take 3

    state["items"] = _selectable_items(state, args)
    state["sel"] = max(0, min(state.get("sel", 0), max(len(state["items"]) - 1, 0)))

    # Row sizes FIRST, driven by the actual content, so no panel carries dead
    # rows; the leftover flows into the history charts (taller braille grids).
    if theme.width() >= 110:
        groups = len(state.get("findings") or [])
        procs = len(state.get("processes") or [])
        conns = len(state.get("connections") or [])
        ips = len({c.remote_ip for c in (state.get("all_connections") or []) if not c.private})
        events = min(len(state.get("events") or []), 3)

        # content each panel wants (excluding its 2 border rows)
        ports_need = min(max(groups, 1), 10) + 4        # header + blank + hint + progress reserve
        vitals_need = 7 + events                        # status/rates/totals/download/scan/host
        act_need = 4 + min(procs, 12)
        end_need = min(max(ips, 1), 12) + 3             # rows + located line

        want_a = max(ports_need, vitals_need) + 2
        want_b = max(act_need, end_need) + 2
        row_c = max(11, min(20, body_rows // 3 + 2))
        left = body_rows - row_c
        row_a = max(8, min(want_a, int(left * want_a / max(1, want_a + want_b))))
        row_b = max(7, min(want_b, left - row_a))
        row_a = max(8, min(row_a, left - row_b))
        row_c = body_rows - row_a - row_b

        state["ui"] = {
            "ports": max(2, row_a - 6),
            "procs": max(2, row_b - 6),
            "eps": max(2, row_b - 3),
            "cells": max(2, min(14, (row_c - 5) // 2)),
        }
    else:
        state["ui"] = {"ports": 6, "procs": 5, "conns": 3, "eps": 6, "cells": 2}

    side = Panel(_vitals(state, args), box=box.ROUNDED, border_style=theme.BORDER,
                 title=Text(" vitals ", style=f"bold {theme.TEXT}"), title_align="left",
                 padding=(0, 1))
    ports = Panel(_view_ports(state, args), box=box.ROUNDED, border_style=theme.BORDER,
                  title=Text(" ports ", style=f"bold {theme.TEXT}"), title_align="left",
                  padding=(0, 1))
    activity = Panel(_view_overview(state, args), box=box.ROUNDED, border_style=theme.BORDER,
                     title=Text(" activity ", style=f"bold {theme.TEXT}"), title_align="left",
                     padding=(0, 1))
    endpoints = Panel(_view_endpoints(state, args), box=box.ROUNDED, border_style=theme.BORDER,
                      title=Text(" endpoints ", style=f"bold {theme.TEXT}"), title_align="left",
                      padding=(0, 1))
    history = Panel(_view_history(state, args), box=box.ROUNDED, border_style=theme.BORDER,
                    title=Text(" history ", style=f"bold {theme.TEXT}"), title_align="left",
                    padding=(0, 1))

    if state.get("dialog"):
        # A small centred dialog replaces the screen while it is open.
        return Align.center(_dialog_panel(state["dialog"]), vertical="middle")

    if theme.width() >= 110:
        layout["body"].split_column(
            Layout(name="rowA", size=row_a),
            Layout(name="rowB", size=row_b),
            Layout(name="rowC", size=row_c),
        )
        layout["body"]["rowA"].split_row(Layout(name="ports", ratio=5), Layout(name="side", ratio=3))
        layout["body"]["rowA"]["ports"].update(ports)
        layout["body"]["rowA"]["side"].update(side)
        layout["body"]["rowB"].split_row(Layout(name="activity"), Layout(name="endpoints"))
        layout["body"]["rowB"]["activity"].update(activity)
        layout["body"]["rowB"]["endpoints"].update(endpoints)
        layout["body"]["rowC"].update(history)
    else:
        # Narrow terminal: one column, vitals first.
        layout["body"].split_column(
            Layout(name="side", size=10),
            Layout(name="ports", size=8),
            Layout(name="activity"),
            Layout(name="endpoints"),
        )
        layout["body"]["side"].update(side)
        layout["body"]["ports"].update(ports)
        layout["body"]["activity"].update(activity)
        layout["body"]["endpoints"].update(endpoints)
    return layout


# --------------------------------------------------------------- background
RESCAN_PAUSE = 10  # seconds between automatic port rescans


def _scan_loop(state: dict, args: argparse.Namespace, stop: threading.Event) -> None:
    """Rescan forever on a background thread.

    Results only replace ``state['findings']`` when a sweep finishes, so the
    panel keeps showing the previous results (with a progress bar on top)
    while the next scan runs. Pauses RESCAN_PAUSE seconds between sweeps;
    setting ``state['rescan_now']`` skips the pause.
    """
    while not stop.is_set():
        state["scan_error"] = ""
        state["scan_spec"] = args.ports
        try:
            ports = parse_port_spec(args.ports)
        except ValueError as error:
            state["scan_error"] = str(error)
            return
        state["scan_total"] = len(ports)
        state["scan_done"] = 0
        state["scanning"] = True

        def progress(done: int, _total: int, found: int) -> None:
            state["scan_done"], state["scan_found"] = done, found

        try:
            open_ports = scan_ports(args.host, ports, timeout=args.timeout,
                                    workers=args.workers, on_progress=progress,
                                    cancel=stop)
            if stop.is_set():
                return
            state["scan_open"] = open_ports
            state["findings"] = collect_findings(open_ports, args.host)
            state["scanning"] = False
        except Exception as error:  # noqa: BLE001 - a background thread dies quietly
            state["scanning"] = False
            if isinstance(error, RuntimeError) or "shutdown" in str(error).lower():
                return  # interpreter exiting mid-sweep - nothing to report
            state["scan_error"] = str(error)

        for _ in range(RESCAN_PAUSE):
            if stop.is_set() or state.pop("rescan_now", False):
                break
            stop.wait(1.0)


def _scan_once(state: dict, args: argparse.Namespace) -> None:
    """Synchronous sweep used by ``--tab ports`` (no background thread)."""
    state["scan_error"] = ""
    state["scan_spec"] = args.ports
    try:
        ports = parse_port_spec(args.ports)
    except ValueError as error:
        state["scan_error"] = str(error)
        state["findings"] = []
        return
    state["scan_total"] = len(ports)
    state["scan_done"] = 0
    state["scanning"] = True
    try:
        open_ports = scan_ports(
            args.host, ports, timeout=args.timeout, workers=args.workers,
            on_progress=lambda done, _total, found: state.update(
                scan_done=done, scan_found=found),
        )
        state["scan_open"] = open_ports
        state["findings"] = collect_findings(open_ports, args.host)
    except Exception as error:  # noqa: BLE001 - one-shot reports the failure as data
        state["scan_error"] = str(error)
        state["findings"] = []
    finally:
        state["scanning"] = False


def _start_scan(state: dict, args: argparse.Namespace) -> None:
    """Start the scan loop, or poke the running loop to rescan immediately."""
    if state.get("scan_thread") and state["scan_thread"].is_alive():
        state["rescan_now"] = True
        return
    stop = threading.Event()
    state["scan_stop"] = stop
    thread = threading.Thread(target=_scan_loop, args=(state, args, stop), daemon=True)
    state["scan_thread"] = thread
    thread.start()


def _series_worker(state: dict, args: argparse.Namespace, stop: threading.Event,
                   started: float) -> None:
    """Sample machine throughput 4x a second into the live series.

    The history charts plot this, so they move in real time whether or not
    ``--record`` is writing the CSV (which only updates at the slower
    detection cadence).
    """
    sampler = ThroughputSampler()
    while not stop.is_set():
        stop.wait(0.25)
        try:
            rate = sampler.sample()
        except Exception:  # noqa: BLE001 - a bad counter read must not kill the thread
            continue
        inbound, outbound = rate.inbound, rate.outbound
        if args.demo:
            add_in, add_out = demo_offset(int(time.monotonic() - started))
            inbound += add_in
            outbound += add_out
        state["live_in"].append(inbound)
        state["live_out"].append(outbound)


def _geo_worker(state: dict, stop: threading.Event) -> None:
    """Resolve the top external endpoints forever; the 1h cache keeps it cheap."""
    while not stop.is_set():
        try:
            grouped: dict[str, set[str]] = {}
            for conn in established_connections():
                if not conn.private:
                    grouped.setdefault(conn.remote_ip, set()).add(conn.process)
            addresses = [address for address, _ in
                         sorted(grouped.items(), key=lambda item: -len(item[1]))[:8]
                         if address not in state["geo"]]
            if addresses:
                state["geo"].update(geo.lookup_many(addresses, timeout=4))
        except Exception:  # noqa: BLE001 - background thread: shutdown noise stays quiet
            return
        stop.wait(5.0)


def _close_flow(state: dict, args: argparse.Namespace) -> None:
    """Terminate the owners of the found ports, then rescan to verify."""
    findings = state["findings"] or []
    owners: dict[int, dict] = {}
    for finding in findings:
        for pid, name in zip(finding.pids, finding.processes):
            owners.setdefault(pid, {"name": name, "ports": []})["ports"].append(finding.port)
        if finding.pids and len(finding.pids) > len(finding.processes):
            for pid in finding.pids:
                owners.setdefault(pid, {"name": "?", "ports": []})["ports"].append(finding.port)

    theme.section("close", f"{len(owners)} process(es) · privilege: {environment_note()}")
    if not owners:
        theme.warn("no owning processes found")
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            theme.hint("remote scans cannot attribute listener PIDs to this machine")
        else:
            theme.hint("system services may require an elevated shell: sc stop <service>")
        return

    from rich.text import Text as _Text

    table = theme.new_table()
    table.add_column("pid", justify="right", style=theme.MUTED, no_wrap=True)
    table.add_column("process", style=theme.TEXT)
    table.add_column("ports", justify="right", style=theme.TEXT)
    names = set()
    for pid, entry in sorted(owners.items()):
        names.add(str(entry["name"]).lower())
        table.add_row(str(pid), _Text(entry["name"]),
                      ", ".join(str(p) for p in entry["ports"]))
    theme.show_table(table)

    if "svchost.exe" in names:
        theme.warn("svchost.exe can host several services - prefer: sc stop <service>")
    if names & {"lsass.exe", "csrss.exe", "winlogon.exe", "wininit.exe", "services.exe"}:
        theme.warn("the selection includes a critical Windows process that can log you out")

    if not args.yes and not theme.confirm("terminate these processes?", default=False):
        theme.hint("ports left untouched")
        return

    pids = sorted(owners)
    results = terminate_many(pids)
    closed, failed, elevated = summarize(results)

    if elevated:
        if args.no_elevate:
            theme.warn(f"{len(elevated)} process(es) require administrator rights "
                       "(--no-elevate was given)")
        elif theme.confirm(
                f"{len(elevated)} process(es) require administrator rights. "
                "Open the UAC prompt?", default=True):
            outcome = request_elevation([item.pid for item in elevated])
            if outcome.cancelled:
                theme.hint("administrator prompt cancelled")
            elif outcome.error:
                theme.warn(outcome.error)
            else:
                extra_closed, extra_failed, extra_elevated = summarize(outcome.results)
                closed += extra_closed
                failed.extend(extra_failed)
                elevated = extra_elevated
                if elevated:
                    theme.warn(f"{len(elevated)} process(es) still denied access")

    theme.blank()
    if closed:
        theme.ok(f"terminated {closed} process(es)")
    if failed:
        theme.warn("could not terminate: " + ", ".join(
            f"{item.name} ({item.pid}): {item.error}" for item in failed))
    if elevated:
        theme.hint("the dashboard stays unprivileged; only the UAC helper is elevated")
    _start_scan(state, args)  # rescan to verify


# --------------------------------------------------------------------- run
def _one_shot_browser(args: argparse.Namespace) -> int | None:
    if args.history:
        rows = browser_history(args.history_days, limit=15)
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        theme.section("browser history", f"top domains · last {args.history_days} day(s)")
        if not rows:
            theme.info("no Chromium/Edge history database found or readable")
            return 0
        table = theme.new_table()
        table.add_column("domain", style=f"bold {theme.TEXT}", no_wrap=True)
        table.add_column("visits", justify="right", style=theme.MUTED)
        table.add_column("last seen", style=theme.MUTED, no_wrap=True)
        table.add_column("title", style=theme.TEXT)
        for row in rows:
            table.add_row(row["domain"], str(row["visits"]), row["last_seen"], Text(row["title"][:48]))
        theme.show_table(table)
        return 0

    if args.downloads:
        rows = browser_downloads(limit=12)
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        theme.section("browser downloads", f"{len(rows)} record(s) · newest first")
        if not rows:
            theme.info("no Chromium/Edge download records found")
            return 0
        table = theme.new_table()
        table.add_column("file", style=f"bold {theme.TEXT}", no_wrap=True)
        table.add_column("source", style=theme.MUTED, no_wrap=True)
        table.add_column("size", justify="right", style=theme.TEXT)
        table.add_column("started", style=theme.MUTED, no_wrap=True)
        table.add_column("state", no_wrap=True)
        for row in rows:
            if row["total"]:
                size = theme.fmt_bytes(row["total"])
                if row["received"] and row["received"] < row["total"]:
                    size = f"{theme.fmt_bytes(row['received'])} / {size}"
            else:
                size = theme.fmt_bytes(row["received"]) if row["received"] else "—"
            style = theme.OK if row["state"] == "complete" else theme.WARN
            table.add_row(Text(row["name"][:32]), row["domain"], size, row["started"],
                          Text(row["state"], style=style))
        theme.show_table(table)
        return 0
    return None


def _refresh_overview_once(state: dict, args: argparse.Namespace) -> None:
    """Take a real throughput/process/connection snapshot without threads."""
    wait = max(0.4, min(args.interval, 2.0))
    sampler = ThroughputSampler()
    time.sleep(wait)
    rate = sampler.sample()
    proc_sampler = ProcessSampler()
    proc_sampler.sample(0.0)
    time.sleep(0.4)
    processes = proc_sampler.sample(0.4)
    connections = established_connections()
    state.update({
        "elapsed": wait + 0.4,
        "in": rate.inbound, "out": rate.outbound,
        "processes": processes,
        "connections": connections,
        "all_connections": connections,
        "ui": {"procs": 8, "conns": 5},
    })


def _refresh_endpoints_once(state: dict, args: argparse.Namespace) -> None:
    connections = established_connections()
    grouped: dict[str, set[str]] = {}
    for conn in connections:
        if not conn.private:
            grouped.setdefault(conn.remote_ip, set()).add(conn.process)
    addresses = [address for address, _ in
                 sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0]))[:8]]
    state["all_connections"] = connections
    state["connections"] = connections
    if addresses and not args.no_geo:
        state["geo"].update(geo.lookup_many(
            [address for address in addresses if address not in state["geo"]], timeout=5))


def _render_one_shot(state: dict, args: argparse.Namespace) -> int:
    """Render one tab once and exit, on a TTY *and* in a pipe.

    ``--json`` data goes to stdout; every diagnostic goes to stderr through
    :mod:`focus.theme`.
    """
    tab = args.tab

    if tab == "ports":
        _scan_once(state, args)
        if args.json:
            findings = state["findings"] or []
            print(json.dumps({
                "host": args.host, "range": state["scan_spec"],
                "error": state.get("scan_error") or None,
                "open": [{"port": item.port, "service": item.service, "bind": item.bind,
                          "exposure": item.exposure, "pids": item.pids,
                          "processes": item.processes, "risk": item.risk}
                         for item in sorted(findings, key=lambda entry: entry.port)],
            }, indent=2))
            return 1 if state.get("scan_error") else 0

    elif tab == "history":
        if args.json:
            samples = read_traffic(args.csv, limit=max(1, args.last))
            print(json.dumps({
                "csv": str(args.csv),
                "samples": [{"elapsed": sample.elapsed, "inbound": sample.inbound,
                             "outbound": sample.outbound} for sample in samples],
            }, indent=2))
            return 0

    elif tab == "endpoints":
        _refresh_endpoints_once(state, args)
        if args.json:
            grouped: dict[str, set[str]] = {}
            for conn in state["all_connections"]:
                if not conn.private:
                    grouped.setdefault(conn.remote_ip, set()).add(conn.process)
            payload = []
            for address, processes in sorted(grouped.items(),
                                             key=lambda item: (-len(item[1]), item[0]))[:8]:
                result = state["geo"].get(address)
                entry = {"ip": address, "process": ", ".join(sorted(processes)),
                         "resolved": result is not None}
                if result:
                    entry.update({"org": result.isp, "location": result.location,
                                  "asn": result.asn, "source": result.source})
                elif args.no_geo:
                    entry["status"] = "geo disabled"
                else:
                    entry["status"] = "unavailable"
                payload.append(entry)
            print(json.dumps(payload, indent=2))
            return 0

    elif tab == "overview":
        _refresh_overview_once(state, args)
        if args.json:
            print(json.dumps({
                "t": round(state["elapsed"], 2),
                "inbound": round(state["in"], 3),
                "outbound": round(state["out"], 3),
                "privilege": environment_note(),
                "processes": [{"pid": item.pid, "name": item.name,
                               "read": round(item.read, 3), "write": round(item.write, 3)}
                              for item in state["processes"]],
                "connections": [{"remote_ip": conn.remote_ip,
                                 "remote_port": conn.remote_port,
                                 "local_port": conn.local_port,
                                 "pid": conn.pid, "process": conn.process}
                                for conn in state["connections"]],
                "scan": {"range": state["scan_spec"], "running": False,
                         "note": "the overview tab does not scan ports; use --tab ports"},
            }, indent=2))
            return 0

    theme.console.print(Panel(
        VIEWS[tab](state, args), box=box.ROUNDED, border_style=theme.BORDER,
        title=Text(f" {tab} ", style=f"bold {theme.TEXT}"), title_align="left",
        padding=(0, 1)))
    return 0


def run(args: argparse.Namespace) -> int:
    theme.set_json_mode(args.json)
    if args.interval <= 0 or args.threshold <= 0 or args.sustain < 1:
        theme.error("interval and threshold must be positive; sustain must be at least 1")
        return 2

    one_shot = _one_shot_browser(args)
    if one_shot is not None:
        return one_shot

    offset = 0
    if args.record:
        try:
            offset = last_elapsed(args.csv)
        except OSError as error:
            theme.error(f"cannot read {args.csv}: {error}")
            return 1

    state: dict = {
        "tab": args.tab or "overview",
        "elapsed": 0.0,
        "host": "",
        "in": 0.0, "out": 0.0,
        "in_history": deque(maxlen=48), "out_history": deque(maxlen=48),
        "live_in": deque(maxlen=480), "live_out": deque(maxlen=480),
        "processes": [], "connections": [], "all_connections": [],
        "surge": {"level": CALM, "z": 0.0, "baseline": 0.0, "events": 0},
        "download": {"active": False, "size": 0.0, "peak": 0.0, "process": "", "org": ""},
        "events": [], "written": 0,
        "sel": 0, "dialog": None,
        "totals": {"in": 0.0, "out": 0.0},
        "geo": {},
        "findings": None, "scan_open": [], "scan_done": 0, "scan_total": 0,
        "scan_error": "", "scan_spec": args.ports,
        "history_samples": read_traffic(args.csv, limit=max(1, args.last)),
        "history_tick": 0,
    }

    if args.map:
        targets = geo.external_targets(8)
        located = [result for result in
                   geo.lookup_many([ip for ip, _ in targets], timeout=5).values() if result]
        if located:
            path = geo.write_map(located)
            theme.ok(f"map written to {path.name}")
        else:
            theme.warn("no endpoints located yet - map skipped")

    if args.tab:
        return _render_one_shot(state, args)

    interactive = theme.console.is_terminal and not args.json

    # Initialise the samplers BEFORE the session clock starts: the first
    # ProcessSampler.sample() walks every process and can take over a second,
    # which used to make --duration 2 record a single, late sample.
    sampler = ThroughputSampler()
    proc_sampler = ProcessSampler()
    proc_sampler.sample(0.0)
    in_detector = RollingDetector(z_surge=args.threshold, sustain=args.sustain)
    out_detector = RollingDetector(z_surge=args.threshold, sustain=args.sustain)

    started = time.monotonic()
    _start_scan(state, args)  # the ports panel is on screen from the start
    geo_stop = threading.Event()
    series_stop = threading.Event()
    if interactive and not args.no_geo:
        threading.Thread(target=_geo_worker, args=(state, geo_stop), daemon=True).start()
    if interactive:
        threading.Thread(target=_series_worker,
                         args=(state, args, series_stop, started), daemon=True).start()

    deadline = started + args.duration if args.duration > 0 else None

    shared = {
        "tick": 0, "in_alert": False, "events": 0, "dl_above": 0, "dl_below": 0,
        "total_in": 0.0, "total_out": 0.0, "peak": 0.0,
        "last_tick": started, "last_proc": started,
        "quit": False, "close_requested": False,
    }

    def emit(kind: str, text: str, payload: dict) -> None:
        state["events"].append({"time": timestamp(), "kind": kind, "text": text})
        if args.json:
            print(json.dumps(payload), flush=True)
        elif not interactive:
            print(f"{timestamp()}  {text}", flush=True)

    def step() -> int:
        """One sampling tick: 0 continue, 1 error, 2 stop, 3 close requested."""
        shared["tick"] += 1
        time.sleep(args.interval)
        now = time.monotonic()
        elapsed = now - started
        dt = max(now - shared["last_tick"], 0.0)
        shared["last_tick"] = now

        rate = sampler.sample()
        inbound, outbound = rate.inbound, rate.outbound
        add_in = add_out = 0.0
        if args.demo:
            add_in, add_out = demo_offset(int(elapsed))
            inbound += add_in
            outbound += add_out
        shared["demo_active"] = add_in > 0 or add_out > 0

        shared["total_in"] += inbound * dt
        shared["total_out"] += outbound * dt
        state["totals"]["in"] += inbound * 1_024_000 / 8 * dt
        state["totals"]["out"] += outbound * 1_024_000 / 8 * dt
        shared["peak"] = max(shared["peak"], inbound, outbound)

        verdict_in = in_detector.update(inbound)
        verdict_out = out_detector.update(outbound)
        level, driver = combine(verdict_in, verdict_out)

        state["in"], state["out"] = inbound, outbound
        state["in_history"].append(inbound)
        state["out_history"].append(outbound)
        state["elapsed"] = elapsed
        state["surge"] = {"level": level, "z": driver.z,
                          "baseline": driver.baseline, "events": shared["events"]}

        if shared["tick"] % 3 == 0:
            state["processes"] = proc_sampler.sample(max(now - shared["last_proc"], 1e-6))
            shared["last_proc"] = now
        if shared["tick"] % 3 == 0:
            conns = established_connections()
            state["connections"] = conns
            state["all_connections"] = conns
        if shared["tick"] % 5 == 0:
            state["history_samples"] = read_traffic(args.csv, limit=max(1, args.last))

        # ---- surge events
        if level == SURGE and not shared["in_alert"]:
            shared["in_alert"] = True
            shared["events"] += 1
            direction = "inbound" if driver is verdict_in else "outbound"
            value = inbound if driver is verdict_in else outbound
            emit("surge", f"SURGE {direction} {value:.2f} Mbps · z {driver.z:.1f}",
                 {"event": "surge", "t": round(elapsed, 2), "direction": direction,
                  "mbps": round(value, 3), "z": round(driver.z, 3)})
        elif level != SURGE:
            shared["in_alert"] = False

        # ---- download events
        floor = max(args.download_threshold, 0.05)
        is_inbound_heavy = inbound >= max(floor, DOWNLOAD_ASYMMETRY * max(outbound, 0.05))
        download = state["download"]
        if not download["active"]:
            shared["dl_above"] = shared["dl_above"] + 1 if is_inbound_heavy else 0
            if shared["dl_above"] >= args.sustain:
                download.update(active=True, size=0.0, peak=inbound,
                                process=_attribute_download(state), org="")
                if args.demo and shared.get("demo_active"):
                    # The spike is injected locally, so naming a real process
                    # (usually svchost) would be a lie. Label it as synthetic.
                    download["process"] = "demo traffic (synthetic)"
                    download["org"] = ""
                elif download["process"] and not args.no_geo:
                    result = state["geo"].get(
                        next((c.remote_ip for c in state["connections"]
                              if download["process"].lower() in c.process.lower()), ""))
                    download["org"] = result.isp if result else ""
                emit("download", "DOWNLOAD started · " + f"{theme.fmt_rate(inbound)} Mbps"
                     + (f" · {download['process']}" if download["process"] else "")
                     + (f" ← {download['org']}" if download["org"] else ""),
                     {"event": "download-start", "t": round(elapsed, 2),
                      "process": download["process"], "org": download["org"]})
                shared["dl_above"] = 0
        else:
            download["size"] += inbound * DOWNLOAD_BYTES_PER_MBPS_SECOND * dt
            download["peak"] = max(download["peak"], inbound)
            shared["dl_below"] = shared["dl_below"] + 1 if not is_inbound_heavy else 0
            if shared["dl_below"] >= args.sustain:
                emit("download", "DOWNLOAD finished · " + theme.fmt_bytes(download["size"])
                     + (f" · {download['process']}" if download["process"] else "")
                     + (f" ← {download['org']}" if download["org"] else ""),
                     {"event": "download-end", "t": round(elapsed, 2),
                      "bytes": round(download["size"]),
                      "process": download["process"], "org": download["org"]})
                download.update(active=False, size=0.0, peak=0.0, process="", org="")
                shared["dl_below"] = 0

        # ---- recording
        if args.record:
            try:
                append_traffic([TrafficSample(offset + round(elapsed, 3),
                                              rate.inbound, rate.outbound)], args.csv)
            except OSError as error:
                theme.error(f"write failed: {error}")
                return 1
            state["written"] += 1

        if args.json:
            payload = {"t": round(elapsed, 2), "inbound": round(inbound, 3),
                       "outbound": round(outbound, 3), "level": level, "z": round(driver.z, 3),
                       "download": "active" if download["active"] else "idle"}
            if download["active"]:
                payload["download_bytes"] = round(download["size"])
                payload["download_process"] = download["process"]
            if args.record:
                payload["recorded"] = state["written"]
            print(json.dumps(payload), flush=True)
        elif not theme.console.is_terminal:
            print(f"t={elapsed:.1f} inbound={inbound:.3f} outbound={outbound:.3f} "
                  f"level={level} download={'yes' if download['active'] else 'no'}", flush=True)

        if deadline and now >= deadline:
            return 2
        return 0

    if not interactive:
        try:
            while True:
                code = step()
                if code:
                    return 0 if code == 2 else code
        except KeyboardInterrupt:
            return 0

    # ---- interactive full-screen loop
    try:
        with key_reader() as read_key:
            running = True
            while running:
                # screen=True clears the whole terminal (alternate buffer) and restores
                # it on exit - the dashboard owns the console while it runs.
                with Live(_screen(state, args), console=theme.console,
                          refresh_per_second=4, screen=True) as live:
                    action = ""
                    while True:
                        key = read_key()
                        if key:
                            if state.get("dialog"):
                                if key in ("\x1b", "q", "Q"):
                                    state["dialog"] = None
                                    state["dialog_label"] = ""
                                elif key in ("\r", "\n"):
                                    _confirm_close(state, args)
                            else:
                                if key in ("q", "Q", "\x03"):
                                    action = "quit"
                                    break
                                if key == "\x1b":
                                    state["sel"] = 0  # esc clears the selection
                                elif key == "UP":
                                    state["sel"] = max(0, state["sel"] - 1)
                                elif key == "DOWN":
                                    state["sel"] = min(len(state.get("items") or []) - 1,
                                                       state["sel"] + 1)
                                elif key == "r":
                                    _start_scan(state, args)
                                elif key in ("\r", "\n"):
                                    items = state.get("items") or []
                                    if items and 0 <= state.get("sel", 0) < len(items):
                                        item = items[state["sel"]]
                                        state["dialog"] = {"item": item}
                                        state["dialog_label"] = (
                                            f"port {item['port']}" if item["kind"] == "port"
                                            else f"{item.get('name')} (pid {item.get('pid')})")
                                        live.update(_screen(state, args))
                                elif key == "c" and state["findings"]:
                                    action = "close"
                                    break
                        code = step()
                        if code == 1:
                            return 1
                        if code == 2:
                            action = "quit"
                            break
                        live.update(_screen(state, args))
                if action == "close":
                    _close_flow(state, args)
                    theme.hint("returning to the dashboard…")
                    time.sleep(1.0)
                else:
                    running = False
    except KeyboardInterrupt:
        pass
    finally:
        geo_stop.set()
        series_stop.set()
        if state.get("scan_stop"):
            state["scan_stop"].set()

    elapsed = max(time.monotonic() - started, 1e-6)
    theme.blank()
    theme.hint(
        f"session {theme.fmt_duration(elapsed)} · "
        f"{theme.fmt_bytes(shared['total_in'] * 1_024_000 / 8)} in · "
        f"{theme.fmt_bytes(shared['total_out'] * 1_024_000 / 8)} out · "
        f"peak {theme.fmt_rate(shared['peak'])} Mbps · {shared['events']} surge event(s)"
    )
    if args.record:
        theme.hint(f"recorded {state['written']} sample(s) to {args.csv.name}")
    return 0


COMMAND = Command(
    name="dashboard",
    summary="Everything live: ports, traffic, endpoints, history",
    usage="dashboard [--tab T] [--record] [--ports RANGE] [--map] [--json]",
    configure=configure,
    run=run,
)
