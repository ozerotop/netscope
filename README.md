# NetScope v0.5.0 — Windows 11 Network Diagnostics

Read-only Windows 11 network diagnostics with a PySide6 desktop interface, live ICMP monitor, VPN/DNS/TCP investigation, and a **rule-based auto-analysis** of investigation results.

NetScope does **not** change DNS, routes, firewall, VPN configuration or system certificates. It does not turn off TLS verification. No external AI model or cloud service is used for recommendations.

## Update from v0.4.0 (Windows CMD)

1. Save/commit your own modifications first and exit NetScope GUI.
2. Extract `NetScope_v0.5.0_Update.zip` **into the existing repository root**, replacing matching files (do not extract as another nested project).
3. In CMD from the repository root:

```cmd
cd /d C:\Dmitri\vs\github\netscope
.\.venv\Scripts\python.exe -m pip install -e ".[dev,gui]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m netscope.gui
```

Expected local development-suite result: **75 passed**. This suite uses mock inputs for network functions; GUI needs to be verified on Windows 11. On a fresh machine use `py -3 -m venv .venv` before pip install.

## New: «Автоанализ» tab

- Run **VPN / DNS / TCP → Проверить** as usual. The analysis tab is automatically populated with observations, confidence in the observation, *possible* explanations, and recommended checks.
- To capture a **before** snapshot, open Auto-analysis and click **Текущий → ДО**.
- Change the VPN/network manually outside NetScope, then run **VPN / DNS / TCP → Проверить** again, switch to Auto-analysis and click **Текущий → ПОСЛЕ**. Click **Сравнить**.
- Alternatively, save two investigation JSON reports from v0.4+ and load **Открыть ДО** / **Открыть ПОСЛЕ** directly.
- A comparison only compares DNS answers for the same domain and shared resolvers; route destination and TCP host/port must also match. Different tests are explicitly marked *not comparable*.

**Important:** A different route, a changed DNS response or a TCP connection appearing after changing VPN **does not prove causality**. VPN-like adapters are only identified by name/state. A very low ping via a virtual adapter may not represent RTT to the external host. DNS divergence alone is not proof of manipulation. TCP success does not verify game UDP or voice services.

## New: offline CLI auto-analysis

After exporting **VPN / DNS / TCP** JSON:

```cmd
.\.venv\Scripts\python.exe -m netscope.analyze --input reports\netscope_investigation.json
```

Compare two saved reports:

```cmd
.\.venv\Scripts\python.exe -m netscope.analyze --before reports\before.json --after reports\after.json
```

Optionally add `--json reports\analysis.json` to save analysis data. Reports are local, limited to 2 MB when imported via CLI/GUI, and never uploaded automatically. The analyzer works offline after the report is collected.

## Existing commands and features

- Basic one-time scan: `python -m netscope --trace --json reports\trace.json`.
- Advanced diagnostic CLI: `python -m netscope.investigate --json reports\advanced.json`.
- GUI: `python -m netscope.gui`.
- Live monitor: three targets, latency graph, packet loss and CSV export.
- Advanced diagnostics: Windows system DNS vs UDP/53, route-table estimate, name-based VPN candidates and one TCP connection test.
- TLS: Python OpenSSL and (upon certificate errors) Windows Schannel comparison, **without disabling certificate validation**.

## Privacy and GitHub

Diagnostic reports may contain IPs, network adapter names, domains and VPN metadata. The project's `.gitignore` excludes `reports/*.json` and `reports/*.csv`, but saved reports **elsewhere** can still be tracked: inspect `git status` before `git add .`. Do not commit `.venv` or any private reports.

## Relevant code

```text
src/netscope/gui.py               Main PySide6 desktop interface
src/netscope/analysis_ui.py       New auto-analysis and before/after tabs
src/netscope/analyze.py           New offline CLI entrypoint
src/netscope/core/insights.py     New cautious rule engine
src/netscope/core/report_diff.py  New report comparison
src/netscope/investigate_ui.py    Advanced investigation, emits report to analysis tab
src/netscope/core/investigate.py  VPN/DNS/route/TCP data collection
src/netscope/monitor_ui.py       Live ICMP UI
src/netscope/core/monitor.py     Live monitoring core
```
