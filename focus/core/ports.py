"""TCP port scanning, service identification and exposure classification."""

from __future__ import annotations

import contextlib
import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import psutil

from .net import hostname, listening_map, local_ip

# Friendly names for ports that ``socket.getservbyport`` does not know on
# every platform.
COMMON_SERVICES = {
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3000: "dev-server",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "upnp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# Base severity (0 = informational, 3 = critical) before exposure is applied.
SENSITIVE = {
    21: 3,
    23: 3,
    512: 3,
    513: 3,
    514: 3,
    2375: 3,
    6379: 3,
    9200: 3,
    11211: 3,
    27017: 3,
    139: 2,
    445: 2,
    1433: 2,
    1521: 2,
    3306: 2,
    3389: 2,
    5432: 2,
    5900: 2,
    2049: 2,
    111: 1,
    22: 1,
    25: 1,
    110: 1,
    143: 1,
    3000: 1,
    5000: 1,
    8000: 1,
    8080: 1,
    8443: 1,
}

RISK_LABELS = {3: "critical", 2: "high", 1: "medium", 0: "low"}
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def service_name(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    """Probe one TCP port. ``connect_ex`` avoids exception overhead."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def scan_ports(
    host: str,
    ports: list[int],
    *,
    timeout: float = 0.25,
    workers: int = 2000,
    on_progress=None,
    cancel: threading.Event | None = None,
) -> list[int]:
    """Scan ``ports`` concurrently, returning the open ones in ascending order.

    ``on_progress(done, total, found)`` is called roughly 200 times regardless
    of the range size, which keeps redraws cheap without hiding progress.

    The default of 2000 workers was measured on Windows loopback, where a
    connect to a closed port only receives its RST after ~2s - far past the
    0.25s timeout - so every closed port costs a full timeout and throughput
    is purely a function of probes in flight (500 workers: ~38s for a full
    sweep, 2000: ~12s; beyond that thread overhead cancels the gain).
    """
    total = len(ports)
    if total == 0:
        return []

    found: list[int] = []
    done = 0
    step = max(1, total // 200)
    batch_size = max(256, workers * 4)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for start in range(0, total, batch_size):
            if cancel is not None and cancel.is_set():
                break
            batch = ports[start : start + batch_size]
            try:
                futures = {pool.submit(port_open, host, port, timeout): port for port in batch}
            except RuntimeError:
                # The executor (or the interpreter) is shutting down mid-scan -
                # drop the rest of the sweep instead of spraying tracebacks.
                break
            for future in as_completed(futures):
                if cancel is not None and cancel.is_set():
                    for pending in futures:
                        pending.cancel()
                    break
                port = futures[future]
                try:
                    if future.result():
                        found.append(port)
                except Exception:  # noqa: BLE001 - a probe must never abort a scan
                    pass
                done += 1
                if on_progress and (done % step == 0 or done == total):
                    on_progress(done, total, len(found))

    found.sort()
    return found


@dataclass
class PortFinding:
    port: int
    service: str
    bind: str
    exposure: str  # network | loopback | unknown
    pids: list[int] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    risk: str = "low"


def _exposure(bind: str) -> str:
    if bind in {"0.0.0.0", "::", "*"}:
        return "network"
    if bind.startswith("127.") or bind == "::1":
        return "loopback"
    if bind:
        return "network"
    return "unknown"


def _risk(port: int, exposure: str) -> str:
    severity = SENSITIVE.get(port, 0)
    # A loopback-only listener is materially less exposed than one bound to
    # every interface, so soften (but never hide) the rating.
    if exposure == "loopback":
        severity = max(0, severity - 1)
    return RISK_LABELS[severity]


def is_local_target(host: str) -> bool:
    """Whether ``host`` names this machine, so listener PIDs are meaningful."""
    target = (host or "").strip().lower()
    if target in {"127.0.0.1", "localhost", "::1", "0.0.0.0", ""}:
        return True
    with contextlib.suppress(ValueError):
        if ipaddress.ip_address(target).is_loopback:
            return True
    try:
        return target in {hostname().lower(), socket.getfqdn().lower(), local_ip()}
    except OSError:
        return False


def collect_findings(open_ports: list[int], host: str = "127.0.0.1") -> list[PortFinding]:
    """Enrich raw open ports with bind addresses, owners and a risk rating.

    Listener ownership is only read when ``host`` refers to this machine. A
    remote scan must never attribute a remote port to a local process that
    happens to listen on the same number.
    """
    local = is_local_target(host)
    listeners = listening_map() if local else {}

    pid_names: dict[int, str] = {}

    def name_for(pid: int) -> str:
        if pid not in pid_names:
            try:
                pid_names[pid] = psutil.Process(pid).name()
            except (psutil.Error, OSError):
                pid_names[pid] = "?"
        return pid_names[pid]

    findings: list[PortFinding] = []
    for port in open_ports:
        entries = listeners.get(port, [])
        pids = sorted({pid for _, pid in entries if pid})
        binds = sorted({bind for bind, _ in entries if bind})

        if not local:
            bind = "remote"
        elif not binds:
            bind = "?"
        elif len(binds) == 1:
            bind = binds[0]
        else:
            bind = ",".join(binds)

        if not local:
            exposure = "network"
        elif len(binds) == 1:
            exposure = _exposure(binds[0])
        elif len(binds) > 1:
            exposure = "network"
        else:
            exposure = "unknown"

        findings.append(
            PortFinding(
                port=port,
                service=service_name(port),
                bind=bind,
                exposure=exposure,
                pids=pids,
                processes=[name_for(pid) for pid in pids],
                risk=_risk(port, exposure),
            )
        )

    findings.sort(key=lambda item: (RISK_ORDER[item.risk], item.port))
    return findings


def parse_port_spec(spec: str) -> list[int]:
    """Parse ``80``, ``1-1024``, ``22,80,443`` or ``1-100,443``."""
    ports: set[int] = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if chunk.lower() == "all":
            ports.update(range(1, 65536))
            continue
        if "-" in chunk:
            start_text, _, end_text = chunk.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as error:
                raise ValueError(f"invalid port range {chunk!r}") from error
            if start > end:
                start, end = end, start
            ports.update(range(max(1, start), min(65535, end) + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as error:
                raise ValueError(f"invalid port {chunk!r}") from error
            if 0 < port < 65536:
                ports.add(port)
    if not ports:
        raise ValueError("no ports selected")
    return sorted(ports)


def close_pid(pid: int, wait: float = 1.0) -> bool:
    """Terminate a process and report whether it exited.

    Kept as a thin boolean wrapper for callers that do not need the reason.
    Use :mod:`focus.core.privileges` when access-denied must be distinguished
    from a protected process or a genuine failure.
    """
    from .privileges import terminate_one

    return terminate_one(pid, wait=wait).ok
