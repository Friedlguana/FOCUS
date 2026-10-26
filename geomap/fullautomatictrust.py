"""Compatibility shim.

The original implementation of this script lived in ``geomap/`` and duplicated
the one in the repository root. It now delegates straight to the canonical
``focus dashboard --map`` command.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

if __name__ == '__main__':
    sys.path.insert(0, str(ROOT))
    try:
        from focus.cli import main
    except ImportError as error:
        import focusenv

        raise SystemExit(focusenv.reexec_or_explain(error))
    raise SystemExit(main(['dashboard', '--map', *sys.argv[1:]]))
