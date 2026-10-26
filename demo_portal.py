"""Demo portal - generates real events for the FOCUS dashboard to detect.

Run this in one terminal and the dashboard in another:

    python main.py dashboard      # terminal 1: watch it
    python demo_portal.py         # terminal 2: trigger real downloads,
                                  #             listeners, scans, uploads

Every option here is real: a genuine listener on port 5555, a genuine
terminate, genuine internet traffic. Nothing is simulated.
"""

import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from focus.cli import main
    except ImportError as error:
        import focusenv

        raise SystemExit(focusenv.reexec_or_explain(error))
    raise SystemExit(main(["demo", *sys.argv[1:]]))
