"""Smoke test for the FOCUS framework.

Runs every component once against temporary data and reports a pass/fail
summary:

    python smoke_test.py

The real ``network_data_log.csv`` is never modified: the CLI subprocesses get
``FOCUS_TRAFFIC_CSV`` pointing at a temporary file.
"""
import csv
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

results = []
TEMP_DIR = tempfile.TemporaryDirectory(prefix="focus-smoke-")
TEMP = Path(TEMP_DIR.name)
TEST_CSV = TEMP / "traffic.csv"
BASE_ENV = dict(os.environ, PYTHONIOENCODING="utf-8", FOCUS_TRAFFIC_CSV=str(TEST_CSV))


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))
    return bool(condition)


def cli(*arguments, timeout=180, input_text=None, env=None):
    """Run the real CLI in a clean subprocess and return the completed process."""
    merged = dict(BASE_ENV)
    if env:
        merged.update(env)
    try:
        return subprocess.run(
            [sys.executable, "-u", str(BASE_DIR / "main.py"), *arguments],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=merged, input=input_text,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            arguments or ["shell"], returncode=124,
            stdout="", stderr=f"timed out after {timeout}s")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def parse_json_lines(text):
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def listener(port):
    return subprocess.Popen(
        [sys.executable, "-u", "-c",
         "import socket,time; s=socket.socket();"
         "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);"
         f"s.bind(('127.0.0.1', {port})); s.listen(); time.sleep(120)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


# ---------------------------------------------------------------- imports
print("== imports ==")
modules = [
    "focusenv", "functions", "main", "logger", "networkgrapher",
    "aiNetworkSpikeDetector", "randomForestRegressorModel", "fullautomatictrust",
    "PortScanner", "PortOpener",
]
for name in modules:
    source = (BASE_DIR / f"{name}.py").read_text(encoding="utf-8")
    try:
        compile(source, name, "exec")
        ok = True
        detail = ""
    except SyntaxError as error:
        ok = False
        detail = str(error)
    check(f"{name}.py compiles", ok, detail)

try:
    import functions
except ImportError as error:  # interpreter without the dependencies installed
    import focusenv

    raise SystemExit(focusenv.reexec_or_explain(error))

from focus.core import geo
from focus.core.browsers import browser_profiles
from focus.core.ports import collect_findings, scan_ports
from focus.core.privileges import is_windows, terminate_many, terminate_one

# ---------------------------------------------------------------- scanner
print("\n== port scanner ==")
probe_port = free_port()
with socket.socket() as listener_socket:
    listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener_socket.bind(("127.0.0.1", probe_port))
    listener_socket.listen()

    found = scan_ports("127.0.0.1", [probe_port], timeout=0.5, workers=4)
    check("scanner finds an open port", probe_port in found, f"{probe_port} in {found}")

    findings = collect_findings(found, "127.0.0.1")
    owner_ok = bool(findings) and os.getpid() in findings[0].pids
    check("local findings include the listener owner", owner_ok,
          f"pids={findings[0].pids if findings else []}")

    closed = free_port()
    while closed == probe_port:
        closed = free_port()
    not_found = scan_ports("127.0.0.1", [closed], timeout=0.5, workers=4)
    check("scanner ignores a closed port", closed not in not_found, str(closed))

remote = collect_findings([probe_port], "203.0.113.10")
check("remote scans do not borrow local PIDs",
      bool(remote) and not remote[0].pids and remote[0].bind == "remote",
      f"pids={remote[0].pids if remote else 'none'}")

# ---------------------------------------------------------- process closer
print("\n== process closer ==")
victim_port = free_port()
victim = listener(victim_port)
try:
    time.sleep(1.5)
    check("victim port is reachable", bool(scan_ports("127.0.0.1", [victim_port], timeout=0.5, workers=4)))
    close_results = terminate_many([victim.pid], wait=2.0)
    check("terminate_many closes a same-user process",
          bool(close_results) and close_results[0].ok,
          close_results[0].error if close_results else "no result")
    try:
        victim.wait(timeout=8)
        gone = True
    except subprocess.TimeoutExpired:
        gone = False
    check("victim process terminated", gone)
finally:
    if victim.poll() is None:
        victim.kill()

if is_windows():
    guarded = terminate_one(4)
    check("core Windows PID 4 is protected", not guarded.ok and guarded.protected, guarded.error)

# ---------------------------------------------------------------- logger
print("\n== network logger ==")
record_run = cli("dashboard", "--record", "--duration", "2", "--interval", "1",
                 "--json", "--ports", "65000-65005", "--no-geo", timeout=90)
try:
    record_rows = parse_json_lines(record_run.stdout)
    json_ok = bool(record_rows)
except ValueError as error:
    record_rows = []
    json_ok = False
    record_run.stderr += f"\ninvalid JSON: {error}"
check("dashboard --record exits cleanly", record_run.returncode == 0,
      f"{len(record_rows)} JSON line(s)" if record_run.returncode == 0
      else record_run.stderr.strip()[:100])
check("dashboard JSON stream is pure JSON", json_ok,
      f"{len(record_run.stdout.splitlines())} stdout line(s)")
check("dashboard reports surge and download state",
      bool(record_rows) and all(key in record_rows[-1]
                                for key in ("inbound", "level", "download")),
      f"level={record_rows[-1].get('level')}" if record_rows else "no sample")

with TEST_CSV.open(encoding="utf-8", newline="") as handle:
    rows = list(csv.DictReader(handle))
check("csv header is correct",
      bool(rows) and set(rows[0]) == {"elapsed_time", "inbound_data", "outbound_data"},
      ",".join(rows[0].keys()) if rows else "empty")
check("recorded elapsed values are fractional or increasing",
      len(rows) >= 2 and len({round(float(row["elapsed_time"]), 2) for row in rows}) == len(rows),
      f"{len(rows)} rows")

# ---------------------------------------------------------------- one-shot
print("\n== one-shot tabs ==")
ports_run = cli("dashboard", "--tab", "ports", "--ports", "65000-65010", "--json",
                "--no-geo", timeout=60)
try:
    ports_payload = json.loads(ports_run.stdout)
    check("ports --json is one object", isinstance(ports_payload, dict)
          and "open" in ports_payload and ports_payload.get("host") == "127.0.0.1",
          f"{len(ports_payload.get('open', []))} open")
except ValueError as error:
    check("ports --json is one object", False, f"invalid JSON: {error}")

history_run = cli("dashboard", "--tab", "history", "--last", "5", "--json", timeout=60)
try:
    history_payload = json.loads(history_run.stdout)
    check("history --json uses the CSV", isinstance(history_payload.get("samples"), list)
          and len(history_payload["samples"]) >= 1,
          f"{len(history_payload.get('samples', []))} samples")
except (ValueError, AttributeError) as error:
    check("history --json uses the CSV", False, f"invalid JSON: {error}")

overview_run = cli("dashboard", "--tab", "overview", "--json", timeout=60)
try:
    overview_payload = json.loads(overview_run.stdout)
    check("overview --json has processes and privilege",
          isinstance(overview_payload.get("processes"), list)
          and overview_payload.get("privilege") in ("administrator", "standard user", "root", "user"),
          f"{len(overview_payload.get('processes', []))} processes")
except (ValueError, AttributeError) as error:
    check("overview --json has processes and privilege", False, f"invalid JSON: {error}")

endpoints_run = cli("dashboard", "--tab", "endpoints", "--json", "--no-geo", timeout=60)
try:
    endpoints_payload = json.loads(endpoints_run.stdout)
    check("endpoints --json is a list", isinstance(endpoints_payload, list),
          f"{len(endpoints_payload)} endpoint(s)")
except ValueError as error:
    check("endpoints --json is a list", False, f"invalid JSON: {error}")

# ---------------------------------------------------------------- demo
print("\n== demo detector ==")
# A high download floor keeps ordinary background traffic from opening the
# download detector before the synthetic 50 Mbps spike does; otherwise a real
# browser/update download can mask the demo event and make this check flaky.
demo_run = cli("dashboard", "--demo", "--duration", "15", "--interval", "1",
               "--download-threshold", "49.5", "--json", "--no-geo",
               "--ports", "65000-65005", timeout=90)
try:
    demo_rows = parse_json_lines(demo_run.stdout)
    starts = [row for row in demo_rows if row.get("event") == "download-start"]
    synthetic = [row for row in starts if "synthetic" in str(row.get("process", ""))]
    demo_ok = (bool(synthetic) and synthetic[0].get("t", 0) >= 8
               and all(row.get("t", 0) >= 8 for row in synthetic))
    detail = (f"t={synthetic[0].get('t')}s process={synthetic[0].get('process')}"
              if synthetic else f"{len(starts)} download-start event(s), none synthetic")
except ValueError as error:
    demo_ok = False
    detail = f"invalid JSON: {error}"
check("demo spike produces a synthetic download event", demo_ok, detail)

# ---------------------------------------------------------------- map/browser
print("\n== map and browser ==")
sample = geo.GeoResult(
    ip="203.0.113.10", city="<script>alert(1)</script>", region="Test",
    country="Nowhere", country_code="ZZ", isp="Example & Co",
    asn="AS64500", latitude=1.0, longitude=2.0, source="test",
)
map_path = geo.write_map([sample], TEMP / "map.html")
map_text = map_path.read_text(encoding="utf-8")
check("map writes a Leaflet document", "leaflet" in map_text and "circleMarker" in map_text,
      f"{map_path.stat().st_size} bytes")
check("map escapes popup fields", "function esc" in map_text and "esc(point.label)" in map_text)
check("geo lookup_many handles an empty list", geo.lookup_many([]) == {})

try:
    profiles = browser_profiles()
    browser_ok = isinstance(profiles, list)
    browser_detail = f"{len(profiles)} profile(s)"
except Exception as error:  # noqa: BLE001 - a reader must never take the suite down
    browser_ok = False
    browser_detail = str(error)
check("browser profile discovery is safe", browser_ok, browser_detail)

# ---------------------------------------------------------------- models
print("\n== ai models ==")
models_run = cli("models", "--json", timeout=90)
try:
    models_payload = json.loads(models_run.stdout)
    models_ok = (models_run.returncode == 0 and len(models_payload) == 2
                 and all(item.get("loaded") for item in models_payload))
    models_detail = ", ".join(item["name"] for item in models_payload)
except (ValueError, KeyError, TypeError) as error:
    models_ok = False
    models_detail = f"invalid JSON: {error}"
check("focus models --json", models_ok, models_detail)

# ---------------------------------------------------------------- cli/packaging
print("\n== cli and packaging ==")
help_run = cli("--help")
check("focus --help renders", help_run.returncode == 0
      and "network security framework" in help_run.stdout
      and all(name in help_run.stdout for name in ("dashboard", "models")),
      f"{len(help_run.stdout.splitlines())} lines" if help_run.returncode == 0
      else help_run.stderr.strip()[:80])

data_dir = BASE_DIR / "focus" / "data"
check("packaged data files exist",
      all((data_dir / name).is_file()
          for name in ("inboundModel.joblib", "outboundModel.joblib", "network_data_log.csv")))

shell_run = cli(input_text="help\nexit\n", timeout=60)
check("interactive shell", shell_run.returncode == 0
      and "commands" in shell_run.stdout and "session closed" in shell_run.stdout,
      f"{len(shell_run.stdout.splitlines())} lines" if shell_run.returncode == 0
      else shell_run.stderr.strip()[:80])

# ---------------------------------------------------------------- summary
passed = sum(1 for _, ok, _ in results if ok)
total = len(results)
print(f"\n{'=' * 50}")
print(f"{passed}/{total} checks passed")
TEMP_DIR.cleanup()
if passed != total:
    print("\nFailures:")
    for name, ok, detail in results:
        if not ok:
            print(f"  - {name} {detail}")
    sys.exit(1)
print("All good.")
