"""Reading and writing the project's flat-file data stores."""

from __future__ import annotations

import csv
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .paths import TRAFFIC_CSV

CSV_HEADER = ["elapsed_time", "inbound_data", "outbound_data"]
_WRITE_LOCK = threading.Lock()


# --------------------------------------------------------------- traffic log
@dataclass(frozen=True)
class TrafficSample:
    # Float, not int: the dashboard records several samples per second and
    # rounding every row to the same second destroyed the time axis.
    elapsed: float
    inbound: float
    outbound: float


def read_traffic(path: Path = TRAFFIC_CSV, limit: int | None = None) -> list[TrafficSample]:
    """Read the traffic log. Bad rows are skipped rather than raising."""
    if not path.exists():
        return []

    samples: list[TrafficSample] = []
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                try:
                    samples.append(
                        TrafficSample(
                            float(row["elapsed_time"]),
                            float(row["inbound_data"]),
                            float(row["outbound_data"]),
                        )
                    )
                except (KeyError, TypeError, ValueError):
                    continue
    except OSError:
        return []

    if limit is not None and limit > 0:
        samples = samples[-limit:]
    return samples


def last_elapsed(path: Path = TRAFFIC_CSV) -> float:
    samples = read_traffic(path, limit=1)
    return samples[-1].elapsed if samples else 0.0


def append_traffic(samples: Iterable[TrafficSample], path: Path = TRAFFIC_CSV) -> int:
    """Append samples, writing the header only for a new/empty file.

    The lock keeps two threads/processes in this interpreter from interleaving
    rows. The trailing-newline guard matters when a CSV was truncated by hand:
    without it the new first row is glued onto the last existing row.
    """
    rows = list(samples)
    if not rows:
        return 0

    with _WRITE_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        needs_newline = False
        if path.exists() and path.stat().st_size:
            with path.open("rb") as handle:
                handle.seek(-1, 2)
                needs_newline = handle.read(1) not in (b"\n", b"\r")

        write_header = not path.exists() or path.stat().st_size == 0
        with path.open("a", encoding="utf-8", newline="") as handle:
            if needs_newline:
                handle.write("\n")
            writer = csv.writer(handle)
            if write_header:
                writer.writerow(CSV_HEADER)
            for sample in rows:
                writer.writerow([
                    f"{sample.elapsed:.3f}".rstrip("0").rstrip("."),
                    sample.inbound,
                    sample.outbound,
                ])
    return len(rows)


def timestamp() -> str:
    return time.strftime("%H:%M:%S")
