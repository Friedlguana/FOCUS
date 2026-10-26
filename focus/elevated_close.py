"""Short-lived elevated helper for closing specific processes.

This file is launched by :func:`focus.core.privileges.request_elevation` through
the Windows UAC prompt. It is deliberately standalone: it can be executed as a
plain script from a source checkout or from an installed package, and it only
writes a JSON result file - the dashboard reads that file after the helper
exits.

Never run this directly unless you understand that it terminates the PIDs you
pass on the command line.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _write(path: Path, payload: dict) -> None:
    """Write atomically so the waiting dashboard never reads a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=path.name, suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--result", required=True)
    parser.add_argument("--pids", required=True)
    args = parser.parse_args(argv)

    result_path = Path(args.result)
    pids: list[int] = []
    for chunk in args.pids.split(","):
        try:
            pid = int(chunk.strip())
        except ValueError:
            continue
        if pid > 0:
            pids.append(pid)

    try:
        from focus.core.privileges import result_payload, terminate_many

        results = terminate_many(pids)
        payload = result_payload(results)
    except BaseException as error:  # noqa: BLE001 - always report back to the caller
        payload = {"error": f"{type(error).__name__}: {error}"}

    try:
        _write(result_path, payload)
    except OSError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
