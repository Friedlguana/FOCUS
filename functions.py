"""Compatibility layer for the original script interface.

The implementation now lives in :mod:`focus.core`. This module keeps the
historical function names and globals working for the smoke test and any
external scripts that imported ``functions`` directly.
"""

from __future__ import annotations

import platform
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import psutil

from focus.core.net import listening_map
from focus.core.paths import BASE_DIR
from focus.core.ports import close_pid, port_open

from focus import theme


def enableUnicodeOutput() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


enableUnicodeOutput()

Platform = platform.system()

OpenPorts: list[int] = []
target = "127.0.0.1"

_print_lock = threading.Lock()
_ports_lock = threading.Lock()


def clear() -> None:
    theme.clear()


def isPortOpen(port: int, host: str | None = None, timeout: float = 0.5) -> bool:
    return port_open(host or target, port, timeout)


def singlePortScanner(port, verbose=True, host=None, found=None):
    if not isPortOpen(port, host=host):
        return None

    if found is not None:
        found.append(port)
    else:
        with _ports_lock:
            OpenPorts.append(port)

    if verbose:
        with _print_lock:
            print(port)

    return port


def multiPortScanner(startPort, endPort, maxWorkers=1000, verbose=True, host=None):
    # endPort is inclusive, matching focus.core.ports.parse_port_spec.
    ports = list(range(startPort, endPort + 1))
    found: list[int] = []

    with ThreadPoolExecutor(max_workers=max(1, maxWorkers)) as executor:
        for result in executor.map(lambda p: singlePortScanner(p, False, host, found), ports):
            if result is not None and verbose:
                with _print_lock:
                    print(result)

    found.sort()
    with _ports_lock:
        OpenPorts.clear()
        OpenPorts.extend(found)

    return list(found)


def getPortOwners(port: int) -> list[int]:
    owners: list[int] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.Error):
        return owners

    for conn in connections:
        if conn.laddr and conn.laddr.port == port and conn.pid:
            if conn.pid not in owners:
                owners.append(conn.pid)
    return owners


def PortCloser(port: int) -> None:
    for pid in getPortOwners(port):
        try:
            process = psutil.Process(pid)
            name = process.name()
            print(f"Process {name} (PID {pid}) is using port {port}")
            if close_pid(pid):
                print("Process terminated")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except OSError:
            pass


__all__ = [
    "BASE_DIR",
    "Platform",
    "OpenPorts",
    "clear",
    "enableUnicodeOutput",
    "getPortOwners",
    "isPortOpen",
    "listening_map",
    "multiPortScanner",
    "PortCloser",
    "singlePortScanner",
]
