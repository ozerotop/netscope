# NetScope v0.1 — Windows 11 Network Diagnostics

Read-only Python CLI that checks IPv4 ICMP, OS DNS resolution, HTTPS availability, Windows default IPv4 routes and network adapters. It optionally runs `tracert` and exports a structured JSON report.

## Requirements
- Windows 11
- Python 3.11+ installed
- VS Code + Microsoft Python extension (recommended)

## Installation (VS Code → Terminal → PowerShell)

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m netscope --json reports\diagnostic.json
```

If `py` is unavailable, use `python` in the first two commands. Using the `.venv\Scripts\python.exe` path avoids PowerShell script-execution policy issues.

## Examples

```powershell
.\.venv\Scripts\python.exe -m netscope --help
.\.venv\Scripts\python.exe -m netscope --target 8.8.8.8 --domain example.com --json reports\test.json
.\.venv\Scripts\python.exe -m netscope --trace --json reports\trace.json
```

## Privacy & scope

- Does **not** change DNS, VPN, routes, firewall, proxy, or other settings.
- Does **not** require administrator privileges for basic checks.
- Reports can contain private IPv4 addresses, adapter names and network routes. Do not post them publicly without redaction.
- Internet access is necessary for public tests; network filters may block ICMP even while HTTPS works.
- VPN detection is only a name-based hint, not proof of a live VPN tunnel.
- A successful DNS lookup and HTTPS connection to `example.com` do not prove every service is reachable.
- RTT is based on parsed Windows `ping.exe` replies; some locales could omit parsed timing.

## Project structure

```text
src/netscope/cli.py           Console interface
src/netscope/core/ping.py     ICMP testing
src/netscope/core/dns.py      System DNS resolution
src/netscope/core/http.py     HTTPS access
src/netscope/core/routes.py   Default routes and optional tracert
src/netscope/core/adapters.py psutil network adapters
src/netscope/core/diagnose.py Aggregate report and explanations
tests/                        Unit tests (no internet required)
```

## Next milestones
- GUI with PySide6, real-time charts and cancellation controls.
- Compare diagnostics before/after VPN connection.
- Configurable DNS servers / port probes / history, with explicit user consent and no automatic network changes.
