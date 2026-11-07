# NetScope v0.3.0 — Windows 11 Network Diagnostics

Read-only Windows 11 network diagnostics, with CLI, a PySide6 desktop UI and a **live ICMP monitoring** tab. Designed to help investigate flaky Wi-Fi, VPN and gaming connections without changing any network settings.

## Install / update in VS Code (CMD)

Python 3.11+ and Windows 11 required. Open the repository's root directory.

```cmd
.\.venv\Scripts\python.exe -m pip install -e ".[dev,gui]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m netscope.gui
```

For a new clone, create the environment first: `py -3 -m venv .venv`.

### Live monitoring (v0.3.0)

1. Open **Мониторинг LIVE**.
2. Enter **1–3** comma-separated IPv4 addresses or DNS hostnames (e.g. `1.1.1.1, 8.8.8.8, www.python.org`).
3. Click **Старт мониторинга**, observe per-host min/avg/max RTT, replies and loss percentage, and watch the chart.
4. Click **Стоп**, then **Экспорт CSV** to save the sample history.

Each host is probed with **one Windows ICMP ping per cycle**. Probes run in parallel; new cycles start **at least one second apart**. If probes are slow, an interval may exceed one second. A blocked ICMP reply is reported as a missed probe, not evidence of a full internet outage. Graph uses the last 120 cycles; missing samples are red crosses (not 0 ms).

Lifetime counters track the whole current session. Memory and CSV history are limited to the most recent **10,000 samples per host**; starting a new session clears the previous in-memory history. Export CSV before starting another monitoring session if the existing history matters. CSV includes timestamps and addresses; check before sharing.

### Existing functions (v0.1–v0.2)

- One-off ping, DNS, HTTPS (Python + Schannel fallback on TLS certificate mismatch), routes and network adapter diagnostics.
- Optional tracert and JSON report export.
- CLI still works:

```cmd
.\.venv\Scripts\python.exe -m netscope --trace --json reports\trace.json
```

### Privacy and safety

- Read-only checks. No administrator rights, no DNS/firewall/route/VPN modifications, no TLS bypass.
- Subprocesses use argument arrays, never `shell=True`; host inputs are validated.
- ICMP results may be distorted by VPN/TUN routing and filtering. A 0.5ms ping to `1.1.1.1` through a tunnel is **not proof** of remote server latency.
- Tests run offline with fake samples.
- Monitoring is stopped cleanly before GUI exit. Running individual one-off scans are also allowed to finish before exit.

## Code layout

```text
src/netscope/gui.py            Existing diagnostic UI + Live monitoring tab
src/netscope/monitor_ui.py     Live monitoring worker, chart, table & CSV export UI
src/netscope/core/monitor.py  Validations, ICMP probe and session statistics
src/netscope/core/           Existing diagnostic modules
src/netscope/cli.py           Existing CLI
 tests/                        Offline unit tests
```
