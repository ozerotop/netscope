# NetScope v0.2.0 — Windows 11 Network Diagnostics

A read-only Windows desktop diagnostic app, with a preserved command-line interface. It checks ping, DNS, HTTPS certificate validation, routes, adapters, and optional traceroute. If Python rejects an HTTPS certificate, NetScope compares the result with Windows Schannel via `curl.exe` (with TLS validation ON).

## Install and run (CMD in VS Code)

Requires Windows 11 and Python 3.11+.

```cmd
.\.venv\Scripts\python.exe -m pip install -e ".[dev,gui]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m netscope.gui
```

First-time checkout: run `py -3 -m venv .venv` before the install command.
The GUI installation includes **PySide6**; it may take longer to install than the small CLI dependencies.

### CLI still works

```cmd
.\.venv\Scripts\python.exe -m netscope --trace --json reports\trace.json
.\.venv\Scripts\python.exe -m netscope --domain example.com --https-url https://example.com/
```

The GUI is stage 2's first milestone; continuous ping charts, history, automatic root-cause diagnosis and portable EXE packaging are **not implemented yet**.

## What a TLS mismatch means

`curl.exe` on Windows uses Schannel, while Python `urllib` uses Python's SSL/OpenSSL stack. Their certificate-chain handling can differ. If Python fails certificate verification for a site while Windows curl succeeds, NetScope highlights it as a mismatch, **not** as a general internet outage. A missing intermediate certificate or a proxy/VPN that handles certificates differently may be involved; that does not prove interception or tampering. Never bypass TLS validation (`-k`, unverified SSL contexts).

Windows may show different DNS responses than global resolvers. A successful DNS lookup against a named server does not prove that the request reached that resolver when a VPN or filtering rules are present.

## Privacy and safety

- Does not change DNS, VPN, firewall, routes or proxies.
- Basic checks run without administrator rights.
- Reports contain local IPs, network adapter names and routes; review before sharing.
- VPN detection is based on interface names only, not definitive proof.
- Low ICMP times do not guarantee fast communication with remote services when VPN tunneling or local redirection is active.
- For Windows 11 only; tests can run on non-Windows for development.

## Structure

```text
src/netscope/gui.py           PySide6 desktop app (worker QThread)
src/netscope/cli.py           CLI
src/netscope/core/           Shared diagnostic engine
tests/                      Unit tests, no internet required
.vscode/                    VS Code run configurations
```
