"""Deprecated: use ``focus dashboard`` (ports tab)."""

import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from focus.cli import main
    except ImportError as error:
        import focusenv

        raise SystemExit(focusenv.reexec_or_explain(error))
    raise SystemExit(main(["dashboard", "--tab", "ports", *sys.argv[1:]]))
