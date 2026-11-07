# NetScope v0.4.0 — Windows 11 Network Diagnostics

Read-only Windows network diagnostics: CLI, PySide6 GUI, live ICMP monitoring, and **VPN / DNS / IPv4 route / TCP investigation**. NetScope does **not** change DNS, routes, firewall, VPN or system certificates.

## Updating an existing v0.3.0 installation (Windows CMD)

1. Commit or stash local work before replacing project files.
2. Extract `NetScope_v0.4.0_Update.zip` into the repository root with file replacement.
3. Run from the repository root:

```cmd
.\.venv\Scripts\python.exe -m pip install -e ".[dev,gui]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m netscope.gui
```

Expected automated result from the release build: **41 passed**. GUI behaviour on your Windows environment still needs a manual smoke test.

For a fresh clone, first create an environment with `py -3 -m venv .venv`.

## New: VPN / DNS / TCP tab

Open **VPN / DNS / TCP**, then run the checks with these suggested safe defaults:

| Field | Default | Meaning |
|---|---|---|
| DNS domain | `www.python.org` | Compare IPv4 A records |
| DNS servers | `1.1.1.1, 8.8.8.8` | Direct **unencrypted** UDP/53 DNS requests (up to 3 addresses) |
| Route destination | `1.1.1.1` | Estimate the best matching Windows IPv4 route |
| TCP host | `www.python.org` | Destination to test |
| TCP port | `443` | One TCP connection attempt, **not** a port scan |

Results are shown in five subtabs: Findings, DNS comparison, Route selection, VPN-like adapters, and TCP. Use **Save JSON** for a detailed report. Reports can contain sensitive details about your network: check carefully before sharing. Ignore files in `reports/` when committing.

**Caution: these are diagnostic hints, not definitive verdicts.**

- Windows system DNS resolution (`getaddrinfo`) may use cache, hosts or VPN policy and can differ from direct UDP DNS queries. UDP/53 may also be blocked or redirected. Different A records are common with CDNs and **do not prove** DNS tampering.
- The route is inferred from the active `route print -4` table, with longest-prefix match, then lowest displayed metric. Equal-cost routes are flagged. Windows interface policy and VPN adapters may affect the actual path.
- Network adapters are tagged as potential VPN/TUN based **only on their names**, not inspection of whether a VPN is carrying traffic.
- A successful TCP connection does **not** test UDP traffic, a game's voice-chat protocol, login or firewall policies for other applications.
- The tool does not disable TLS certificate verification or perform any network reconfiguration.

### New command-line investigation

```cmd
.\.venv\Scripts\python.exe -m netscope.investigate --json reports\advanced.json
```

With explicit parameters:

```cmd
.\.venv\Scripts\python.exe -m netscope.investigate --domain example.com --dns-servers 1.1.1.1,8.8.8.8 --route-ip 1.1.1.1 --tcp-host www.python.org --tcp-port 443
```

## Previous features, retained

- v0.1: ping, DNS, HTTPS, adapter inventory, route summary and optional traceroute, CLI with JSON export.
- v0.2: PySide6 dark GUI, Windows Schannel comparison when Python certificate verification fails (no TLS bypass).
- v0.3: **Мониторинг LIVE** for up to three hosts, per-target latency statistics, chart and CSV export.

To run a basic CLI scan:

```cmd
.\.venv\Scripts\python.exe -m netscope --trace --json reports\trace.json
```

## Project structure

```text
src/netscope/gui.py                Main PySide6 window and tabs
src/netscope/investigate_ui.py     VPN / DNS / route / TCP UI (QThread worker)
src/netscope/investigate.py        Advanced diagnostics CLI
src/netscope/core/investigate.py   Advanced orchestration, cautious findings
src/netscope/core/dns_compare.py   System resolver + UDP DNS (A only)
src/netscope/core/route_analysis.py   Active route parsing and estimated selection
src/netscope/core/tcp_probe.py     Single TCP connection check
src/netscope/monitor_ui.py        Live ICMP monitoring UI
src/netscope/core/monitor.py      Monitoring engine and CSV export
src/netscope/core/               Existing diagnosis modules
tests/                            Offline, mocked automated tests
```

## Diagnostic reference

- [Microsoft: Windows route metric / longest prefix](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-tcpip-interfaces-interface-routes-route-metric)
- [Microsoft: VPN name resolution and NRPT](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-name-resolution)
- [Microsoft: Resolve-DnsName vs nslookup](https://techcommunity.microsoft.com/blog/networkingblog/resolve-dnsname-vs-nslookup-in-windows/4483858)
