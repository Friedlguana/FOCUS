"""Filesystem locations.

In a source checkout the data files stay at the repository root: they are part
of the project's history (and the original scripts read them from there). An
installed wheel cannot write to site-packages, so it carries seed copies in
``focus/data`` and keeps the writable traffic log and map in the per-user data
directory.

``FOCUS_DATA_DIR`` overrides the writable directory and ``FOCUS_TRAFFIC_CSV``
overrides the traffic log path (used by the smoke test and packaging checks).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
PACKAGE_DATA = Path(__file__).resolve().parent.parent / "data"

# A source checkout has a pyproject at the repository root; an installed wheel
# does not. This decides where writable files should live.
SOURCE_CHECKOUT = (BASE_DIR / "pyproject.toml").is_file()


def user_data_dir() -> Path:
    override = os.environ.get("FOCUS_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(root) / "focus"


def _data_file(name: str, *, writable: bool) -> Path:
    """Prefer the checkout copy, then packaged data, then the user directory."""
    override = os.environ.get(f"FOCUS_{name.upper().replace('.', '_')}")
    if name == "network_data_log.csv":
        override = os.environ.get("FOCUS_TRAFFIC_CSV") or override
    if override:
        return Path(override).expanduser()
    if SOURCE_CHECKOUT:
        candidate = BASE_DIR / name
        if candidate.exists() or writable:
            return candidate
    packaged = PACKAGE_DATA / name
    if packaged.exists():
        return packaged if not writable else user_data_dir() / name
    return user_data_dir() / name


TRAFFIC_CSV = _data_file("network_data_log.csv", writable=True)
INBOUND_MODEL = _data_file("inboundModel.joblib", writable=False)
OUTBOUND_MODEL = _data_file("outboundModel.joblib", writable=False)
MAP_FILE = _data_file("server_location_map.html", writable=True)
