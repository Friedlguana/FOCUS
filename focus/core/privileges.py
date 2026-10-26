"""Process termination policy, access checks and optional Windows elevation.

Windows enforces process access with integrity levels and access tokens. A
normal (medium-integrity) process can terminate processes owned by the same
user that are not elevated, but terminating an elevated, service-account or
protected process requires administrator rights. There is no supported way to
bypass that check.

FOCUS therefore keeps the dashboard unprivileged and elevates only the close
action: :func:`request_elevation` launches a short-lived helper through the
Windows UAC prompt, and the helper writes its result to a temporary file.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import psutil

# Never terminate these: the kernel, the session manager and memory-only
# pseudo processes. Their PIDs are fixed on Windows.
CRITICAL_PIDS = {0, 4}
PROTECTED_NAMES = {
    "system",
    "system idle process",
    "idle",
    "registry",
    "memory compression",
    "secure system",
}

# Closing these can take the desktop or a shared service host down. They are
# allowed only after an explicit warning in the dialog; svchost is additionally
# called out because one process can host many unrelated services.
SENSITIVE_NAMES = {
    "csrss.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "spoolsv.exe",
    "svchost.exe",
    "wininit.exe",
    "winlogon.exe",
}

PROCESS_TERMINATE = 0x0001
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
SW_HIDE = 0


@dataclass
class TerminationResult:
    pid: int
    name: str
    ok: bool
    needs_elevation: bool = False
    error: str = ""

    @property
    def protected(self) -> bool:
        return self.error.startswith("protected:")

    @property
    def sensitive(self) -> bool:
        return self.name.lower() in SENSITIVE_NAMES


def is_windows() -> bool:
    return os.name == "nt"


def is_elevated() -> bool:
    """True when the current process has an administrator token."""
    if not is_windows():
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _process_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except (psutil.Error, OSError):
        return "?"


def environment_note() -> str:
    """A one-line description of the current privilege level."""
    if not is_windows():
        return "root" if is_elevated() else "user"
    return "administrator" if is_elevated() else "standard user"


def _windows_can_open(pid: int) -> tuple[bool, str]:
    """Probe PROCESS_TERMINATE without terminating anything.

    Returns ``(allowed, reason)``. Opening the handle is the same access check
    ``TerminateProcess`` performs, so an access-denied result reliably predicts
    whether the close would need elevation.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_bool

    handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if handle:
        kernel32.CloseHandle(handle)
        return True, ""
    error = ctypes.get_last_error()
    if error == ERROR_ACCESS_DENIED:
        return False, "access denied (administrator rights required)"
    if error == ERROR_INVALID_PARAMETER:
        return False, "process is no longer running"
    return False, f"OpenProcess failed (Windows error {error})"


def terminate_one(pid: int, *, wait: float = 1.0) -> TerminationResult:
    """Terminate one process, classifying the failure instead of hiding it."""
    if not pid or pid < 0:
        return TerminationResult(pid, "?", False, error="invalid pid")
    if pid in CRITICAL_PIDS:
        return TerminationResult(pid, _process_name(pid), False,
                                 error="protected: core Windows process")
    if pid == os.getpid():
        return TerminationResult(pid, _process_name(pid), False,
                                 error="protected: this is the FOCUS process")

    name = _process_name(pid)
    if name.lower() in PROTECTED_NAMES:
        return TerminationResult(pid, name, False,
                                 error="protected: core Windows process")

    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return TerminationResult(pid, name, True, error="already exited")
    except psutil.AccessDenied:
        return TerminationResult(pid, name, False, needs_elevation=True,
                                 error="access denied (administrator rights required)")
    except (psutil.Error, OSError) as error:
        return TerminationResult(pid, name, False, error=str(error))

    if is_windows():
        allowed, reason = _windows_can_open(pid)
        if not allowed:
            if "no longer running" in reason:
                return TerminationResult(pid, name, True, error="already exited")
            return TerminationResult(pid, name, False,
                                     needs_elevation="access denied" in reason,
                                     error=reason)

    try:
        process.terminate()
        try:
            process.wait(timeout=wait)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait(timeout=wait)
        return TerminationResult(pid, name, True)
    except psutil.NoSuchProcess:
        return TerminationResult(pid, name, True, error="already exited")
    except psutil.AccessDenied:
        return TerminationResult(pid, name, False, needs_elevation=True,
                                 error="access denied (administrator rights required)")
    except (psutil.Error, OSError) as error:
        return TerminationResult(pid, name, False, error=str(error))


def terminate_many(pids: list[int], *, wait: float = 1.0) -> list[TerminationResult]:
    """Terminate a de-duplicated list, preserving input order."""
    seen: set[int] = set()
    results: list[TerminationResult] = []
    for pid in pids:
        if not pid or pid in seen:
            continue
        seen.add(pid)
        results.append(terminate_one(pid, wait=wait))
    return results


def summarize(results: list[TerminationResult]) -> tuple[int, list[TerminationResult], list[TerminationResult]]:
    """Return ``(closed, failed, need_elevation)`` for display code."""
    closed = sum(1 for item in results if item.ok)
    failed = [item for item in results if not item.ok and not item.needs_elevation]
    elevated = [item for item in results if item.needs_elevation]
    return closed, failed, elevated


@dataclass
class ElevationOutcome:
    launched: bool
    cancelled: bool
    results: list[TerminationResult]
    error: str = ""


def _helper_path() -> Path:
    return Path(__file__).resolve().parents[1] / "elevated_close.py"


def _launcher() -> str:
    """Prefer pythonw.exe so the elevated helper does not flash a console."""
    executable = Path(sys.executable)
    if executable.suffix.lower() == ".exe":
        windowless = executable.with_name("pythonw.exe")
        if windowless.is_file():
            return str(windowless)
    return str(executable)


def request_elevation(pids: list[int], *, timeout: float = 120.0) -> ElevationOutcome:
    """Run the close helper elevated through UAC and read its JSON result.

    The dashboard stays in its normal console; only the helper is elevated.
    If the user declines the UAC prompt, ``cancelled`` is true and nothing is
    terminated. The helper never trusts the caller blindly: it re-applies the
    same protected-process policy.
    """
    if not is_windows():
        return ElevationOutcome(False, False, [], "elevation is only available on Windows")
    if not pids:
        return ElevationOutcome(False, False, [], "no processes selected")

    helper = _helper_path()
    if not helper.is_file():
        return ElevationOutcome(False, False, [], f"elevation helper missing: {helper.name}")

    handle, name = tempfile.mkstemp(prefix="focus-elevated-", suffix=".json")
    os.close(handle)
    result_path = Path(name)
    result_path.unlink(missing_ok=True)  # the helper must create it

    parameters = subprocess.list2cmdline([
        str(helper),
        "--result", str(result_path),
        "--pids", ",".join(str(pid) for pid in pids if pid),
    ])

    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.ShellExecuteW.argtypes = (
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int,
        )
        shell32.ShellExecuteW.restype = ctypes.c_void_p
        code = shell32.ShellExecuteW(
            None, "runas", _launcher(), parameters,
            str(helper.parent.parent), SW_HIDE,
        )
    except (AttributeError, OSError) as error:
        result_path.unlink(missing_ok=True)
        return ElevationOutcome(False, False, [], f"cannot start the UAC helper: {error}")

    if code <= 32:
        result_path.unlink(missing_ok=True)
        error_code = ctypes.get_last_error()
        if error_code == 1223:  # ERROR_CANCELLED
            return ElevationOutcome(False, True, [], "administrator prompt cancelled")
        return ElevationOutcome(False, False, [], f"UAC helper failed to start (code {code})")

    deadline = time.monotonic() + max(10.0, timeout)
    payload: dict | None = None
    while time.monotonic() < deadline:
        if result_path.exists():
            try:
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                break
            except (OSError, ValueError):
                pass
        time.sleep(0.2)
    result_path.unlink(missing_ok=True)

    if payload is None:
        return ElevationOutcome(True, False, [],
                                "the elevated helper did not report back in time")

    if payload.get("error"):
        return ElevationOutcome(True, False, [], str(payload["error"]))

    results = []
    for item in payload.get("results") or []:
        if not isinstance(item, dict):
            continue
        results.append(TerminationResult(
            pid=int(item.get("pid") or 0),
            name=str(item.get("name") or "?"),
            ok=bool(item.get("ok")),
            needs_elevation=bool(item.get("needs_elevation")),
            error=str(item.get("error") or ""),
        ))
    return ElevationOutcome(True, False, results)


def result_payload(results: list[TerminationResult]) -> dict:
    return {"results": [asdict(item) for item in results]}
