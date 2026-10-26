"""Network sampling: throughput, per-process I/O, and live connections."""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass

import psutil


def bytes_to_mbps(delta_bytes: float) -> float:
    """Match the convention used by the shipped CSV and models.

    The original scripts computed ``bytes / 1024 * 8 / 1000``. Keeping that
    formula means new samples remain numerically compatible with the existing
    log, even though it is a binary-megabit approximation.
    """
    return round(max(delta_bytes, 0) * 8 / 1_024_000, 4)


@dataclass(frozen=True)
class Rate:
    inbound: float
    outbound: float

    @property
    def total(self) -> float:
        return self.inbound + self.outbound


class ThroughputSampler:
    """Whole-machine throughput between two calls to :meth:`sample`."""

    def __init__(self) -> None:
        counters = psutil.net_io_counters()
        self._prev_recv = counters.bytes_recv
        self._prev_sent = counters.bytes_sent
        self._prev_time = time.monotonic()

    def sample(self) -> Rate:
        counters = psutil.net_io_counters()
        now = time.monotonic()
        elapsed = max(now - self._prev_time, 1e-6)

        inbound = bytes_to_mbps((counters.bytes_recv - self._prev_recv) / elapsed)
        outbound = bytes_to_mbps((counters.bytes_sent - self._prev_sent) / elapsed)

        self._prev_recv = counters.bytes_recv
        self._prev_sent = counters.bytes_sent
        self._prev_time = now
        return Rate(inbound, outbound)


@dataclass(frozen=True)
class ProcessRate:
    pid: int
    name: str
    read: float
    write: float

    @property
    def total(self) -> float:
        return self.read + self.write


class ProcessSampler:
    """Per-process I/O deltas.

    Windows exposes process I/O counters (``GetProcessIoCounters``), which
    include file and socket traffic. The numbers are therefore an I/O
    approximation, not a packet-level breakdown; they are labelled accordingly
    in the interface.
    """

    def __init__(self) -> None:
        self._prev: dict[int, tuple[int, int]] = {}
        self._names: dict[int, str] = {}

    def sample(self, interval: float = 1.0) -> list[ProcessRate]:
        interval = max(interval, 1e-6)
        current: dict[int, tuple[int, int]] = {}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                counters = proc.io_counters()
            except (psutil.Error, OSError):
                continue
            pid = proc.pid
            current[pid] = (counters.read_bytes, counters.write_bytes)
            name = proc.info.get("name")
            if name:
                self._names[pid] = name

        rates: list[ProcessRate] = []
        if self._prev:
            for pid, (read, write) in current.items():
                prev_read, prev_write = self._prev.get(pid, (read, write))
                down = bytes_to_mbps((read - prev_read) / interval)
                up = bytes_to_mbps((write - prev_write) / interval)
                if down + up >= 0.001:
                    rates.append(ProcessRate(pid, self._names.get(pid, "?"), down, up))

        self._prev = current
        return sorted(rates, key=lambda item: item.total, reverse=True)


@dataclass(frozen=True)
class Connection:
    remote_ip: str
    remote_port: int
    local_port: int
    pid: int | None
    process: str
    private: bool
    proto: str = "tcp"


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def listening_map() -> dict[int, list[tuple[str, int | None]]]:
    """port -> [(bind address, pid), ...] for TCP/UDP sockets in LISTEN."""
    result: dict[int, list[tuple[str, int | None]]] = {}
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.Error):
        return result

    for conn in connections:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        result.setdefault(conn.laddr.port, []).append((conn.laddr.ip, conn.pid))
    return result


def established_connections(external_only: bool = True, include_udp: bool = False) -> list[Connection]:
    """Live connections with owning processes.

    TCP only by default; ``include_udp`` also reports UDP sockets that have a
    remote address (Chrome and friends move much of their traffic to
    QUIC/UDP 443, which has no connection status to filter on).
    """
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.Error):
        return []

    names: dict[int, str] = {}
    seen: set[tuple[str, int, int | None]] = set()
    result: list[Connection] = []

    for conn in connections:
        is_tcp = conn.type == socket.SOCK_STREAM
        if not include_udp and not is_tcp:
            continue
        if is_tcp and conn.status != psutil.CONN_ESTABLISHED:
            continue
        if not conn.raddr:
            continue

        ip, port = conn.raddr[0], conn.raddr[1]
        if external_only and _is_loopback(ip):
            continue

        key = (ip, port, conn.pid)
        if key in seen:
            continue
        seen.add(key)

        name = "—"
        if conn.pid:
            if conn.pid not in names:
                try:
                    names[conn.pid] = psutil.Process(conn.pid).name()
                except (psutil.Error, OSError):
                    names[conn.pid] = "—"
            name = names[conn.pid]

        result.append(
            Connection(
                remote_ip=ip,
                remote_port=port,
                local_port=conn.laddr.port if conn.laddr else 0,
                pid=conn.pid,
                process=name,
                private=_is_private(ip),
                proto="tcp" if is_tcp else "udp",
            )
        )

    return sorted(result, key=lambda item: (item.process.lower(), item.remote_ip))


def local_ip() -> str:
    """Best-effort address of the interface used for outbound traffic."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "localhost"
