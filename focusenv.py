"""Interpreter bootstrap shared by the repository entry scripts.

``python main.py`` and the legacy shims must work
from a plain terminal, where the active interpreter may simply not have the
dependencies installed (a system Python instead of the project ``.venv``).

Each entry script inserts its repository root into ``sys.path`` before
importing ``focus`` and, if that import fails, calls
:func:`reexec_or_explain` - which re-runs the same script through the
project's ``.venv`` interpreter, or prints install instructions when no
venv exists. Only the standard library is used here on purpose.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
VENV_PYTHON = BASE_DIR / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _instructions() -> None:
    if os.name == "nt":
        create = "  python -m venv .venv"
        install = "  .venv\\Scripts\\pip install -r requirements.txt"
        run = '  then run: .venv\\Scripts\\python.exe main.py'
    else:
        create = "  python -m venv .venv"
        install = "  .venv/bin/pip install -r requirements.txt"
        run = "  then run: .venv/bin/python main.py"
    print("Create the virtual environment and install the dependencies first:")
    print(create)
    print(install)
    print(run)


def _explain(error: ImportError) -> int:
    module = getattr(error, "name", None) or "the FOCUS dependencies"
    print(f"{type(error).__name__}: {error}")
    print()
    print(f"FOCUS could not import {module} with this interpreter:")
    print(f"  {sys.executable}")
    print()
    if VENV_PYTHON.exists():
        print("The project virtual environment is available. Run:")
        print(f'  "{VENV_PYTHON}" {Path(sys.argv[0]).name}')
    else:
        _instructions()
    return 1


def reexec_or_explain(error: ImportError) -> int:
    """Re-run this entry script through the ``.venv`` interpreter if possible.

    Guarded against loops: the child carries ``FOCUS_REEXEC=1`` and never
    re-execs again, so a venv that exists but lacks the dependencies fails
    once with instructions instead of spawning an endless process chain.
    """
    same_interpreter = Path(sys.executable).resolve() == VENV_PYTHON.resolve()
    if VENV_PYTHON.exists() and sys.argv[0] and not same_interpreter \
            and os.environ.get("FOCUS_REEXEC") != "1":
        environment = dict(os.environ, FOCUS_REEXEC="1")
        try:
            return subprocess.call([str(VENV_PYTHON), sys.argv[0], *sys.argv[1:]], env=environment)
        except OSError:
            pass  # broken venv interpreter - fall through to the instructions
    return _explain(error)
