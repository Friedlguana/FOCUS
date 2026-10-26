"""Read what Chromium browsers record about themselves.

Chrome, Chromium, Edge and Brave keep history and downloads in a SQLite
database inside each user profile. The database (and its ``-wal``/``-shm``
sidecars) is locked while the browser runs, so every reader here copies the
database to a private temporary directory first. A locked, missing or
older-schema database is reported as "no records", never raised.

Timestamps in these databases count microseconds since 1601-01-01.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01

DOWNLOAD_STATES = {0: "in progress", 1: "complete", 2: "cancelled", 3: "interrupted"}

WINDOWS_BROWSERS = (
    "Google/Chrome",
    "Google/Chrome Beta",
    "Google/Chromium",
    "Microsoft/Edge",
    "BraveSoftware/Brave-Browser",
)
MAC_BROWSERS = WINDOWS_BROWSERS
LINUX_BROWSERS = (
    "google-chrome",
    "google-chrome-beta",
    "chromium",
    "microsoft-edge",
    "BraveSoftware/Brave-Browser",
)


def _profile_containers() -> list[Path]:
    """Directories whose immediate children are Chromium profiles."""
    containers: list[Path] = []
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            base = Path(local)
            containers.extend(
                base / browser / "User Data"
                for browser in WINDOWS_BROWSERS
            )
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
        containers.extend(base / browser for browser in MAC_BROWSERS)
    else:
        base = Path.home() / ".config"
        containers.extend(base / browser for browser in LINUX_BROWSERS)
        # Snap and Flatpak keep their profiles outside ~/.config.
        containers.extend((
            Path.home() / "snap" / "chromium" / "common" / "chromium",
            Path.home() / ".var" / "app" / "com.google.Chrome" / "config" / "google-chrome",
            Path.home() / ".var" / "app" / "org.chromium.Chromium" / "config" / "chromium",
        ))
    return list(dict.fromkeys(path for path in containers if path.is_dir()))


def browser_profiles() -> list[Path]:
    """History databases of installed Chromium browsers, one per profile."""
    found: list[Path] = []
    for container in _profile_containers():
        found.extend(path for path in container.glob("*/History") if path.is_file())
    return list(dict.fromkeys(found))


def chrome_time(chrome_us: float) -> str:
    """Format a Chromium timestamp (microseconds since 1601-01-01)."""
    if not chrome_us:
        return "—"
    from datetime import datetime

    try:
        return datetime.fromtimestamp(chrome_us / 1_000_000 - CHROME_EPOCH_OFFSET).strftime("%Y-%m-%d %H:%M")
    except (OSError, OverflowError, ValueError):
        return "—"


def _copy_database(profile: Path, directory: Path) -> Path:
    """Copy History plus its WAL/SHM sidecars into ``directory``."""
    target = directory / "History"
    shutil.copy2(profile, target)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = profile.with_name(profile.name + suffix)
        if sidecar.is_file():
            shutil.copy2(sidecar, target.with_name(target.name + suffix))
    return target


def _iter_rows(queries: tuple[str, ...], params: tuple = ()):
    """Yield rows from every readable profile.

    Column names changed across Chrome versions, so each profile is probed
    with the query list. A profile that raises is skipped, not fatal.
    """
    for profile in browser_profiles():
        directory = Path(tempfile.mkdtemp(prefix="focus-browser-"))
        try:
            database = _copy_database(profile, directory)
            connection = sqlite3.connect(str(database))
            try:
                for query in queries:
                    try:
                        rows = connection.execute(query, params).fetchall()
                    except sqlite3.Error:
                        continue
                    if rows:
                        yield rows
                        break
            finally:
                connection.close()
        except (OSError, sqlite3.Error):
            continue
        finally:
            shutil.rmtree(directory, ignore_errors=True)


def browser_history(days: int = 7, limit: int = 15) -> list[dict]:
    """Top visited domains within the window, most-visited first.

    TLS hides hostnames from anyone watching the wire, so the browser's own
    record is the honest way to answer "which sites was that traffic for?".
    """
    cutoff = int((time.time() - days * 86400 - CHROME_EPOCH_OFFSET) * 1_000_000)
    queries = (
        "SELECT url, title, visit_count, last_visit_time FROM urls "
        f"WHERE last_visit_time >= {cutoff} ORDER BY last_visit_time DESC LIMIT 5000",
    )

    domains: dict[str, dict] = {}
    for rows in _iter_rows(queries):
        for url, title, visit_count, last_visit in rows:
            host = urllib.parse.urlparse(url or "").hostname or ""
            if not host:
                continue
            entry = domains.setdefault(host, {"visits": 0, "title": "", "last": 0.0})
            entry["visits"] += visit_count or 0
            if last_visit and last_visit > entry["last"]:
                entry["last"] = last_visit
                entry["title"] = title or ""

    ordered = sorted(domains.items(), key=lambda item: -item[1]["visits"])[:limit]
    return [
        {"domain": host, "visits": entry["visits"], "title": entry["title"],
         "last_seen": chrome_time(entry["last"])}
        for host, entry in ordered
    ]


def browser_downloads(limit: int = 12) -> list[dict]:
    """Recent downloads across all profiles, newest first.

    Newer Chrome keeps the source URL in ``downloads_url_chains`` (chain
    index 0); older versions had a ``current_url`` column - both are tried.
    """
    queries = (
        "SELECT d.target_path, c.url, d.received_bytes, d.total_bytes, d.start_time, d.state "
        "FROM downloads d LEFT JOIN downloads_url_chains c ON c.id = d.id AND c.chain_index = 0 "
        "ORDER BY d.start_time DESC LIMIT ?",
        "SELECT target_path, current_url, received_bytes, total_bytes, start_time, state "
        "FROM downloads ORDER BY start_time DESC LIMIT ?",
    )

    raw: list[tuple] = []
    for rows in _iter_rows(queries, params=(limit,)):
        raw.extend(rows)
    raw.sort(key=lambda row: row[4] or 0, reverse=True)

    found: list[dict] = []
    for path, url, received, total, started, state in raw[:limit]:
        domain = urllib.parse.urlparse(url or "").hostname or (url or "—")[:24]
        found.append({
            "name": Path(path).name if path else domain,
            "domain": domain,
            "received": received or 0,
            "total": total or 0,
            "started": chrome_time(started or 0),
            "state": DOWNLOAD_STATES.get(state, f"state {state}"),
        })
    return found
