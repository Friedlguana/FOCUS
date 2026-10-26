
<h1 align="center">
  <br>
  <a href="https://github.com/Friedlguana/FOCUS"><img src="ProjectPhotos/FOCUS.png" alt="FOCUS" width="900"></a>
  <br>
  <b> <u>
  🌧️ The FOCUS Framework 🌧️
  </b> </u>
  <br>
</h1>

<h4 align="center">A terminal-first network security framework for port exposure analysis, live traffic monitoring and anomaly detection. Made with  <a href="https://www.python.org/" target="_blank">Python</a>.</h4>


</p>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#how-to-use">How To Use</a> •
  <a href="#credits">Credits</a>
</p>

<u>

## **✨Key Features**
</u>

* ### **The Dashboard 🖥️**
- One command, one screen, everything at once: **ports** (background scan with service,
  process and risk), **vitals** (surge level, rates, download attribution, events),
  **activity** (per-process I/O, connections), **endpoints** (who the machine talks to,
  with organisation and location), and **history** (live or recorded-traffic chart).
- Keys: **↑↓** select a port/process · **Enter** close it · **c** close every port owner ·
  **r** rescan · **q** quit.
* ### **Live Traffic 📶**
- `focus dashboard --record` appends samples to `network_data_log.csv`; the history panel charts it.
* ### **Anomaly Detection 🔍**
- A two-timescale EWMA baseline and a sustained one-sided z-score; no training data needed.
- Downloads are detected too - *sustained asymmetric inbound* (inbound above a small floor
  and 3x the outbound), attributed to the connection-holding process whose write rate best
  matches the transfer, with the volume and remote organisation tracked. `--demo` labels its
  injected spike as synthetic instead of blaming a real process.
- `--demo` injects a deterministic 50 Mbps spike for a repeatable demonstration.
* ### **Endpoint Geolocation 🌍**
- Resolves live endpoints through a provider fallback chain (concurrently) and writes an
  interactive Leaflet map. The map loads Leaflet and CARTO tiles from the internet; it is a
  single HTML file, not an offline map.
- The endpoints panel answers "who is this machine talking to?" with live IPs, owning
  organisation and location; `--history` / `--downloads` read the browser's own records;
  `--map` writes the Leaflet map.
* ### **Self-verification 🩺**
- `python smoke_test.py` exercises every component end to end against temporary data and
  reports a pass/fail summary without touching the real traffic log.
* ### **Cross platform 🪟🍎🐧**
- Windows, macOS and Linux ready. Process termination follows OS permissions: same-user,
  non-elevated processes close normally; elevated, service-account and protected processes
  require the UAC helper described below.

<b> <u>
## **✨Installation**
</b> </u>

```bash
# Clone this repository
$ git clone https://github.com/Friedlguana/FOCUS
$ cd FOCUS

# Create a virtual environment (recommended)
$ python -m venv .venv

# Activate it
# Windows (PowerShell):
> .venv\Scripts\Activate.ps1
# macOS / Linux:
$ source .venv/bin/activate

# Install the dependencies
$ pip install -r requirements.txt

# Optional: install the `focus` console command from this checkout
$ pip install -e .
```

> **Note:** On Windows PowerShell, running `.\.venv\Scripts\Activate.ps1` may be blocked by the
> execution policy. You can skip activation entirely: `python main.py` automatically re-runs
> itself through the project's `.venv` interpreter when the active Python is missing the
> dependencies, so a plain terminal works too.

<b> <u>
## **✨How To Use**
</b> </u>
```bash
# Start the interactive shell (type /help inside for the command list)
$ python main.py

# Or run any command directly
$ python main.py                # interactive shell
$ python main.py dashboard      # the live dashboard (one screen, every section)
```

| Command | What it does |
| --- | --- |
| `dashboard` | The one live view: traffic, port scan, endpoint orgs, history chart; `--record` logs, `--demo` injects a spike |
| `demo` | Portal that generates REAL events: decoy port, scan+close, internet download/upload, endpoints, map, smoke test |
| `models` | Inspect / retrain (`--train`) / query (`--predict N`) the Random Forest models |

### The dashboard

```bash
$ python main.py dashboard                  # full-screen: every section at once
$ python main.py dashboard --record         # also append samples to the traffic CSV
$ python main.py dashboard --demo           # inject a 50 Mbps spike at t+8s
$ python main.py dashboard --tab history    # render one section once and exit
$ python main.py dashboard --tab ports --json   # machine-readable one-shot
```

Keys: **↑↓** select a row · **Enter** close the selected port's owners or process ·
**c** close every port owner (confirmation table, then an automatic rescan proves
the port is gone) · **r** rescans · **q** quits. The surge detector (EWMA baseline
+ z-score) and the download detector (sustained inbound above a floor and 3x
outbound) run continuously; their alerts land in the vitals panel. The port scan
runs in a background thread, so the dashboard stays live while 65,535 ports are
probed.

`--map` writes the endpoint map, `--history`/`--downloads` print the browser's
own records, and `--tab <overview|ports|endpoints|history>` renders a single
section once and exits - on a terminal *and* through a pipe. Add `--json` for a
single object (ports/history/overview) or array (endpoints); diagnostics always
go to stderr so stdout stays parseable.

### The ports panel

```bash
$ python main.py dashboard --ports 1-1024     # scan a bounded range (default: all)
```

The scan runs in a background thread - full 65,535-port sweeps take ~12s
while the dashboard keeps ticking. Every open port is its own row with service,
owning process and risk; the list scrolls with **↑↓** instead of hiding rows
behind a group. Press **Enter** to close one owner or **c** to close them all,
each after an explicit confirmation; then the rescan proves the port is gone.

> ⚠️ **The bulk closer terminates the owner of every open port it found.**
> There is no whitelist - narrow the scan range before you answer `y`.
> `--yes` skips that bulk confirmation for scripted sessions.

### Permissions and elevation

Windows enforces process access with integrity levels and access tokens. A normal
FOCUS dashboard can terminate same-user, non-elevated processes. It **cannot**
terminate an elevated process, a service running as another account, or a
protected process - no user-mode workaround changes that.

FOCUS keeps the dashboard unprivileged. When a close is denied, the dialog offers
to retry **only that close** through a short-lived elevated helper
(`focus/elevated_close.py`) and the normal Windows UAC prompt. The dashboard
itself stays in your normal CMD, so its rendering and key handling do not change.

* `--no-elevate` never shows the UAC prompt; denied processes are reported instead.
* Critical PIDs/processes (`System`, `Idle`, `Registry`, `csrss`, `lsass`, ...) are
  refused even when FOCUS runs elevated.
* `svchost.exe` is called out explicitly: it can host many services. Prefer
  `sc stop <service>` (admin) over killing the shared host.
* Blocking a port with Windows Firewall also requires admin and does **not**
  terminate the process.

### Legacy entry points

The original scripts still work as thin deprecated shims that forward to the
equivalent `focus` command:

| Command | Forwards to |
| --- | --- |
| `python main.py` | Interactive shell |
| `python PortScanner.py` | `focus dashboard --tab ports` |
| `python PortOpener.py` | Opens a listener on a port of your choice (test utility) |
| `python logger.py` | `focus dashboard --record` |
| `python networkgrapher.py` | `focus dashboard --tab history` |
| `python aiNetworkSpikeDetector.py` | `focus dashboard` |
| `python randomForestRegressorModel.py` | `focus models --train` |
| `python fullautomatictrust.py` | `focus dashboard --map` |
| `python smoke_test.py` | Verify every component works |

### Data and models

* `network_data_log.csv` - network samples. `focus dashboard --record` **appends** to it, so the samples
  shipped with the repository are preserved. Columns are `elapsed_time`, `inbound_data`,
  `outbound_data`. Set `FOCUS_TRAFFIC_CSV` or pass `--csv` to use another file.
* `inboundModel.joblib` / `outboundModel.joblib` - Random Forest regressors kept for
  compatibility. Live surge detection is statistical (two-timescale EWMA baseline +
  sustained one-sided z-score), because models keyed on elapsed time cannot generalize
  across sessions; inspect or retrain them with `focus models` / `focus models --train`.
* A source checkout reads the repository copies. An installed wheel carries seed copies in
  `focus/data/` and writes the traffic log and map to the per-user data directory
  (`%LOCALAPPDATA%\focus` on Windows, `~/Library/Application Support/focus` on macOS,
  `~/.local/share/focus` on Linux). `FOCUS_DATA_DIR` overrides it.

------------------------
<b> <u>
## **✨Credits**
</b> </u>

* <a href="https://github.com/Friedlguana">Friedlguana</a>
* <a href="https://github.com/humaidhahm">humaidhahm</a>
* <a href="https://github.com/svm1048">svm1048</a>
