# FOCUS — Demo Run Sheet

A ~9 minute walkthrough. Everything runs from the interactive shell
(`python main.py`), so you never leave one session. Commands are shown with
their optional leading `/` — both forms work.

## Before the audience arrives

- [ ] Terminal opened in the repo, font size bumped up, `.venv` activated.
- [ ] `python smoke_test.py` passes all checks — proves the machine is demo-ready.
- [ ] A second terminal ready for `python PortOpener.py 5555`.
- [ ] A browser tab with a video or download ready (to generate traffic on the main screen).
- [ ] Internet works (endpoint organisations resolve live; the demo works without it too).
- [ ] You know the elevation story: same-user listeners close normally; system services need UAC.

## The walkthrough

The recommended setup is two terminals: `python main.py dashboard` in the first, and
`python demo_portal.py` in the second. The portal's menu generates REAL events - a decoy
listener, a real terminate, an internet download, an outbound upload spike - and the
dashboard detects every one of them through its normal samplers. Nothing in the portal is
simulated. (The dashboard's separate `--demo` flag injects a synthetic spike, labelled as
such below.)

| # | Step | Command | Time |
|---|------|---------|------|
| 1 | Open the shell, show the map of everything | `python main.py`, then `/help` | 0:30 |
| 2 | The dashboard - every section on one screen | `/dashboard` | 1:30 |
| 3 | Walk the sections: ports scan, vitals, activity, endpoints, history | (point at each) | 1:30 |
| 4 | Detect → identify → close → verify story | key `c`, or ↑↓ then Enter | 2:00 |
| 5 | Inject a spike, watch both detectors fire | `/dashboard --demo` | 0:45 |
| 6 | The ML models | `/models`, `/models --predict 120` | 0:45 |
| 7 | Exit | `/exit` | 0:05 |

### Step 4 — the story to tell

```
terminal 2:  python PortOpener.py 5555
terminal 1:  /dashboard          → the ports panel (top-left) scans in the
                                   background and finds 5555: python.exe, rated
             press c             → confirmation table → process terminated
             the panel rescans itself → 5555 is gone
```

For a single port you can use **↑↓** to select its row and **Enter** to open the
close dialog. Same-user listeners close immediately. If the owner needs
administrator rights, the dialog offers a UAC retry for that close only; the
dashboard itself stays in the normal console. Use `--no-elevate` to suppress the
prompt, or stop a service with `sc stop <service>` instead of killing its host.

Talking point: the dashboard found an unauthorized listener, identified the
owning process, and closed it after an explicit confirmation — then the
automatic rescan proved it, all on one screen.

### Step 7 — what to point at

`/dashboard --demo` injects a synthetic 50 Mbps inbound spike at ~t+8s for
~12s. The status line goes CALM → ELEVATED → **SURGE** (red) and the
download detector flags the transfer — both alerts land in the same event
log. The download is labelled **demo traffic (synthetic)**: the spike is
injected locally, so FOCUS does not pretend a real process or organisation
caused it. No internet traffic is needed for the spike itself.

## Fallbacks

| If... | Then |
|-------|------|
| No internet | Endpoint organisations show as unavailable; the dashboard (all sections), `--demo` and `/models` all work offline. |
| Machine has no visible traffic on the main screen | Start the prepared video/download; or run `/dashboard --demo` to inject a spike. |
| The close fails on a system port | Expected without elevation. Demo the close on the PortOpener listener you own, or show the UAC retry in the close dialog. |
| Something unexpected breaks | `python smoke_test.py` proves every component in about a minute; then continue from where it broke. |

## One-liner for the README story

FOCUS = one dashboard: ports · traffic · endpoints · history, plus models.
