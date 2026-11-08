# NetScope v0.6.0 — Windows 11 Network Diagnostics

Read-only network diagnostics with a PySide6 desktop GUI, live ping monitoring, VPN/DNS/TCP investigation, local rule-based explanations, before/after comparison, **SQLite history** and a reproducible **Windows EXE build**.

NetScope does not change DNS, firewall, Windows routing, VPN settings or TLS verification. It never uploads a diagnostic report automatically.

## Updating from v0.5.0 (Windows CMD)

Close the GUI, save any uncommitted edits, and extract `NetScope_v0.6.0_Update.zip` into the **existing repository root**, replacing same-named files. Run:

```cmd
cd /d C:\Dmitri\vs\github\netscope
.\.venv\Scripts\python.exe -m pip install -e ".[dev,gui]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m netscope.gui
```

The new **«История»** tab contains a list of the most recent 200 entries (older entries remain in the database), JSON preview, export/import and deletion. Both basic and advanced scans are saved automatically **after they finish successfully**. Import only opens NetScope report JSON up to 2 MB. For advanced records, use **«В автоанализ»**, **«В ДО»**, **«В ПОСЛЕ»** to compare historic scans. Basic reports cannot be inserted into the advanced analysis view.

**Privacy:** data is saved in `%LOCALAPPDATA%\NetScope\history.sqlite3`, *not inside Git*. Reports may contain private IPs, domains and adapter names. The database is not encrypted, so anyone with access to your Windows user account could read it. You may manually delete entries in the GUI, or remove the database file with NetScope closed if you want to erase all local history. Live monitor samples remain in RAM and are exported to CSV only if requested.

## Packaging into an executable on Windows

The archive contains a build script, but **not a precompiled .exe**. Windows packages must be built and smoke-tested on Windows 11.

```cmd
cd /d C:\Dmitri\vs\github\netscope
.\.venv\Scripts\python.exe -m pip install -e ".[dev,gui,build]"
build_windows.cmd
```

The command runs tests, then uses PyInstaller `--onedir --windowed`. The executable is `dist\NetScope\NetScope.exe`. The **entire** `dist\NetScope` folder must stay together (including `_internal`) for the application to run. Try the executable on Windows before publishing. Python does not need to be installed on a receiving Windows machine, but Windows SmartScreen may warn about an unsigned EXE. This is not an installer or a code-signed release.

The `.github/workflows/windows-build.yml` workflow runs the tests and packages Windows artifacts on GitHub Actions when pushed to `main`, for PRs, or when dispatched manually. The resulting downloadable workflow artifact is not a public GitHub Release. It must be reviewed and tested before distribution.

## Core functionality retained

- `python -m netscope --trace --json reports\trace.json` — basic scan
- `python -m netscope.gui` — desktop GUI
- `python -m netscope.investigate --json reports\advanced.json` — advanced scan
- `python -m netscope.analyze --input reports\advanced.json` — rule-based offline report analysis
- `python -m netscope.analyze --before reports\before.json --after reports\after.json` — compare two advanced reports
- Live monitoring of up to 3 hosts, running graph, ICMP loss indicators and CSV export
- HTTPS/TLS validation using Python; fallback comparison against Windows Schannel upon certificate validation errors

## Repository hygiene

`.gitignore` excludes the virtual environment, local SQLite databases, build output and the usual reports in `reports/`. Review `git status` before committing because exports saved elsewhere could still contain sensitive network information. Automatic history is stored outside the checkout. Do not add `dist/` to Git.
