"""``focus demo`` - a portal that generates REAL events to demonstrate FOCUS.

Run the dashboard in one terminal (``python main.py dashboard``) and this
portal in another. Every option here creates genuine activity on the
machine - a real listener, a real terminate, real internet traffic - which
the dashboard then detects through its normal samplers. Nothing is faked.

  1 decoy port       open / close a real listener on 127.0.0.1:5555
  2 scan + close     scan for the decoy, terminate it, verify gone
  3 real download    download from the internet until toggled off
  4 real upload      POST data to speed-test endpoints (outbound spike)
  5 dashboard        the full live dashboard (q returns here)
  6 endpoints        geolocate the machine's live endpoints
  7 endpoint map     write and open server_location_map.html
  8 models           inspect the traffic models
  9 smoke test       verify every component end to end

Also available as a standalone script: ``python demo_portal.py``.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path

import requests
from rich.text import Text

from focus import theme
from focus.core.ports import (
    collect_findings,
    parse_port_spec,
    scan_ports,
)
from focus.core.privileges import request_elevation, summarize, terminate_many
from focus.core.store import timestamp

from .base import Command

BASE_DIR = Path(__file__).resolve().parents[2]
DECOY_PORT = 5555
CHUNK = 65536

DOWNLOAD_URLS = (
    "https://speed.cloudflare.com/__down?bytes=500000000",
    "https://proof.ovh.net/files/100Mb.dat",
    "https://speed.hetzner.de/100MB.bin",
    "http://ipv4.download.thinkbroadband.com/50MB.zip",
)
UPLOAD_URLS = (
    "https://speed.cloudflare.com/__up",
    "https://httpbin.org/post",
)

_decoy: dict = {"proc": None}
_traffic: dict = {
    "download": {"thread": None, "stop": None, "bytes": 0, "url": "", "error": ""},
    "upload": {"thread": None, "stop": None, "bytes": 0, "url": "", "error": ""},
}


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="unused; the portal is interactive")


# ------------------------------------------------------------- decoy port
def _decoy_running() -> bool:
    proc = _decoy.get("proc")
    return proc is not None and proc.poll() is None


def _decoy_toggle() -> None:
    """Start or stop the 127.0.0.1:5555 test listener.

    The decoy runs as a SEPARATE process (PortOpener.py): scan + close
    terminates *its* owner, and this portal survives to tell the tale.
    """
    if _decoy_running():
        _decoy["proc"].terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            _decoy["proc"].wait(timeout=5)
        _decoy["proc"] = None
        theme.ok(f"decoy listener on port {DECOY_PORT} closed")
        return

    proc = subprocess.Popen(
        [sys.executable, "-u", str(BASE_DIR / "PortOpener.py"), str(DECOY_PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _decoy["proc"] = proc
    time.sleep(0.4)  # give the child a moment to bind
    theme.ok(f"decoy listener open on 127.0.0.1:{DECOY_PORT} (pid {proc.pid}) - scan it, then close it")


def _terminate_pids(pids: list[int], label: str) -> int:
    """Terminate same-user processes, offering UAC only if Windows denies it."""
    results = terminate_many(pids)
    closed, failed, elevated = summarize(results)

    if elevated and theme.confirm(
            "some owners require administrator rights - retry with UAC?", default=True):
        outcome = request_elevation([item.pid for item in elevated])
        if outcome.cancelled:
            theme.hint("administrator prompt cancelled")
        elif outcome.error:
            theme.warn(outcome.error)
        else:
            closed += sum(1 for item in outcome.results if item.ok)
            failed.extend(item for item in outcome.results if not item.ok)

    if closed:
        theme.ok(f"terminated {closed} process(es) - {label}")
    if failed:
        theme.warn("could not terminate: " + ", ".join(
            f"{item.name} ({item.pid}): {item.error}" for item in failed))
    return closed


def _scan_and_close_decoy() -> None:
    """Scan for the decoy, terminate its owner, rescan to prove it gone."""
    ports = parse_port_spec(str(DECOY_PORT))
    with theme.console.status("[muted]scanning…[/]", spinner="dots"):
        open_ports = scan_ports("127.0.0.1", ports, timeout=0.5, workers=50)
    findings = collect_findings(open_ports)

    if not findings:
        theme.warn(f"port {DECOY_PORT} is not open - start the decoy first (option 1)")
        return

    table = theme.new_table()
    table.add_column("port", justify="right", style=f"bold {theme.TEXT}", no_wrap=True)
    table.add_column("service", style=theme.TEXT, no_wrap=True)
    table.add_column("process", style=theme.TEXT)
    table.add_column("risk", justify="right", no_wrap=True)
    for item in findings:
        process = ", ".join(item.processes) if item.processes else "—"
        table.add_row(str(item.port), item.service, Text(process), Text(item.risk, style=theme.WARN))
    theme.show_table(table)

    if not theme.confirm("terminate the decoy's owner?", default=True):
        theme.hint("left untouched")
        return

    closed = _terminate_pids(
        [pid for finding in findings for pid in finding.pids],
        f"decoy port {DECOY_PORT}",
    )
    if not closed:
        theme.hint("the listener may belong to another user or require elevation")

    with theme.console.status("[muted]rescanning to verify…[/]", spinner="dots"):
        open_ports = scan_ports("127.0.0.1", ports, timeout=0.5, workers=50)
    if not open_ports:
        theme.ok(f"verified: port {DECOY_PORT} is closed")
    else:
        theme.warn(f"port {DECOY_PORT} is still open")


# ------------------------------------------------------- real traffic gen
def _traffic_on(kind: str) -> bool:
    entry = _traffic[kind]
    return entry["thread"] is not None and entry["thread"].is_alive()


def _download_worker(stop: threading.Event, entry: dict) -> None:
    """Stream real bytes from the internet until stopped.

    Cycles through public speed-test files; when one is exhausted it starts
    the next, so the download runs as long as the toggle is on.
    """
    path = Path(tempfile.gettempdir()) / "focus_demo_download.bin"
    index = 0
    with contextlib.suppress(Exception):
        path.unlink(missing_ok=True)
    try:
        while not stop.is_set():
            url = DOWNLOAD_URLS[index % len(DOWNLOAD_URLS)]
            index += 1
            entry["url"] = url.split("/")[2]
            try:
                with requests.get(url, stream=True, timeout=(5, 30)) as response:
                    response.raise_for_status()
                    with path.open("wb") as handle:
                        for chunk in response.iter_content(CHUNK):
                            if stop.is_set():
                                return
                            handle.write(chunk)
                            entry["bytes"] += len(chunk)
            except requests.RequestException as error:
                entry["error"] = f"{url.split('/')[2]}: {error.__class__.__name__}"
                if stop.wait(1.0):
                    return
    finally:
        with contextlib.suppress(Exception):
            path.unlink(missing_ok=True)


def _upload_worker(stop: threading.Event, entry: dict) -> None:
    """POST real bytes to a speed-test endpoint until stopped (outbound spike)."""
    payload = os.urandom(CHUNK)
    index = 0
    while not stop.is_set():
        url = UPLOAD_URLS[index % len(UPLOAD_URLS)]
        index += 1
        entry["url"] = url.split("/")[2]
        try:
            response = requests.post(url, data=payload, timeout=(5, 60))
            entry["bytes"] += len(payload)
            if response.status_code >= 400:
                entry["error"] = f"{url.split('/')[2]}: HTTP {response.status_code}"
        except requests.RequestException as error:
            entry["error"] = f"{url.split('/')[2]}: {error.__class__.__name__}"
            if stop.wait(1.0):
                return


def _traffic_toggle(kind: str) -> None:
    entry = _traffic[kind]
    if _traffic_on(kind):
        entry["stop"].set()
        entry["thread"].join(timeout=10)
        entry["thread"] = None
        moved = theme.fmt_bytes(entry["bytes"])
        theme.ok(f"real {kind} stopped · {moved} actually transferred")
        return

    entry["stop"] = threading.Event()
    entry["bytes"] = 0
    entry["error"] = ""
    worker = _download_worker if kind == "download" else _upload_worker
    thread = threading.Thread(target=worker, args=(entry["stop"], entry), daemon=True)
    entry["thread"] = thread
    thread.start()
    time.sleep(1.0)  # let the first connection attempt land

    if _traffic_on(kind) and not entry["error"]:
        theme.ok(f"real {kind} running - watch the dashboard react")
        if entry["url"]:
            theme.hint(f"transferring via {entry['url']}")
        theme.hint("toggle it off here (same option) when you are done")
    else:
        entry["stop"].set()
        if entry.get("thread") is not None:
            entry["thread"].join(timeout=5)
        entry["thread"] = None
        theme.error(f"could not start the real {kind}")
        if entry["error"]:
            theme.hint(f"last provider said: {entry['error']}")
        theme.hint("check the internet connection - everything else in this portal still works")


def _shutdown() -> None:
    """Stop every background worker and close the decoy before returning."""
    for kind in ("download", "upload"):
        entry = _traffic[kind]
        if entry.get("stop") is not None:
            entry["stop"].set()
        thread = entry.get("thread")
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        entry["thread"] = None
    proc = _decoy.get("proc")
    if proc is not None and proc.poll() is None:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        if proc.poll() is None:
            with contextlib.suppress(OSError):
                proc.kill()
    _decoy["proc"] = None


# ------------------------------------------------------------- other items
def _run_dashboard() -> None:
    from .dashboard import COMMAND as DASHBOARD_COMMAND
    from focus.cli import command_parser

    ns = command_parser(DASHBOARD_COMMAND).parse_args([])
    DASHBOARD_COMMAND.run(ns)


def _run_models() -> None:
    from .models import COMMAND as MODELS_COMMAND
    from focus.cli import command_parser

    ns = command_parser(MODELS_COMMAND).parse_args([])
    MODELS_COMMAND.run(ns)


def _show_endpoints() -> None:
    from focus.core import geo
    from focus.core.net import established_connections

    grouped: dict[str, set[str]] = {}
    for conn in established_connections():
        if not conn.private:
            grouped.setdefault(conn.remote_ip, set()).add(conn.process)
    ordered = sorted(grouped.items(), key=lambda item: -len(item[1]))[:8]

    if not ordered:
        theme.info("no established external connections")
        return

    results = []
    with theme.console.status("[muted]resolving endpoints…[/]", spinner="dots"):
        resolved = geo.lookup_many([address for address, _ in ordered], timeout=5)
    for address, processes in ordered:
        results.append((address, ", ".join(sorted(processes)), resolved.get(address)))

    table = theme.new_table()
    table.add_column("address", style=f"bold {theme.TEXT}", no_wrap=True)
    table.add_column("organisation", style=theme.TEXT)
    table.add_column("location", style=theme.MUTED)
    table.add_column("process", style=theme.MUTED)
    located = 0
    for address, processes, result in results:
        if result:
            located += 1
            table.add_row(address, Text(result.isp), Text(result.location), Text(processes))
        else:
            table.add_row(address, Text("unresolved", style=theme.FAINT), "—", Text(processes))
    theme.show_table(table)
    theme.hint(f"{located}/{len(results)} located")


def _write_map() -> None:
    from focus.core import geo

    targets = geo.external_targets(8)
    located = [result for result in
               geo.lookup_many([ip for ip, _ in targets], timeout=5).values() if result]
    if not located:
        theme.warn("no endpoints located yet - map skipped")
        return
    path = geo.write_map(located)
    theme.ok(f"map written to {path.name}")
    with contextlib.suppress(Exception):
        webbrowser.open(path.as_uri())


def _run_smoke_test() -> None:
    theme.info("running the full smoke test (this takes about a minute)…")
    code = subprocess.call([sys.executable, "-u", str(BASE_DIR / "smoke_test.py")])
    if code == 0:
        theme.ok("smoke test passed - every component works")
    else:
        theme.warn("smoke test reported failures - see the output above")


# ------------------------------------------------------------------ portal
MENU = [
    ("1", "decoy port", "open / close a real listener on 127.0.0.1:5555", _decoy_toggle),
    ("2", "scan + close", "scan for the decoy, terminate it, verify gone", _scan_and_close_decoy),
    ("3", "real download", "download from the internet until toggled off", lambda: _traffic_toggle("download")),
    ("4", "real upload", "POST data out until toggled off (outbound spike)", lambda: _traffic_toggle("upload")),
    ("5", "dashboard", "the full live dashboard (q returns here)", _run_dashboard),
    ("6", "endpoints", "geolocate the machine's live endpoints", _show_endpoints),
    ("7", "endpoint map", "write and open server_location_map.html", _write_map),
    ("8", "models", "inspect the traffic models", _run_models),
    ("9", "smoke test", "verify every component end to end", _run_smoke_test),
]


def _traffic_note(kind: str) -> str:
    entry = _traffic[kind]
    if _traffic_on(kind):
        moved = theme.fmt_bytes(entry["bytes"])
        via = f" via {entry['url']}" if entry["url"] else ""
        err = f" · {entry['error']}" if entry["error"] else ""
        return f"  ● running · {moved}{via}{err}"
    return ""


def _portal_screen() -> Table:
    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(width=3)
    grid.add_column(width=16)
    grid.add_column()

    grid.add_row("", Text("capability", style=f"bold {theme.MUTED}"),
                 Text("what it does (all of it is real)", style=f"bold {theme.MUTED}"))
    for key, name, description, _handler in MENU:
        note = ""
        if key == "1" and _decoy_running():
            note = f"  ● open (pid {_decoy['proc'].pid})"
        elif key in ("3", "4"):
            note = _traffic_note("download" if key == "3" else "upload")
        grid.add_row(Text(key, style=f"bold {theme.ACCENT}"),
                     Text(name, style=theme.TEXT),
                     Text(description + note, style=theme.MUTED))
    return grid


def _portal_loop() -> None:
    while True:
        theme.section("capabilities")
        theme.show_table(_portal_screen())
        theme.blank()
        try:
            choice = theme.ask("choose a capability (q to quit)").lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice in ("q", "quit", "exit", ""):
            break
        match = next((item for item in MENU if item[0] == choice), None)
        if match is None:
            theme.error(f"unknown option: {choice}")
            continue

        theme.blank()
        try:
            match[3]()
        except KeyboardInterrupt:
            theme.blank()
            theme.hint("stopped")
        theme.blank()


def run(args: argparse.Namespace) -> int:
    theme.clear()
    theme.banner(None)
    theme.blank()
    theme.console.print(Text("  demo portal", style=f"bold {theme.ACCENT}"))
    theme.hint("everything here is real - run the dashboard in another terminal and watch it detect these")
    theme.hint("  python main.py dashboard")
    theme.blank()

    try:
        _portal_loop()
    finally:
        _shutdown()

    theme.hint("demo portal closed")
    return 0


COMMAND = Command(
    name="demo",
    summary="Portal that generates real events to demonstrate FOCUS",
    usage="demo",
    configure=configure,
    run=run,
)
