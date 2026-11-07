from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from . import __version__
from .core.diagnose import diagnose


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NetScope: read-only network diagnostics for Windows 11")
    parser.add_argument("--version", action="version", version=f"NetScope {__version__}")
    parser.add_argument("--target", default="1.1.1.1", help="IPv4 or host to ping/trace (default: 1.1.1.1)")
    parser.add_argument("--domain", default="www.python.org", help="DNS name to resolve")
    parser.add_argument("--https-url", default="https://www.python.org/", help="HTTPS URL to check")
    parser.add_argument("--trace", action="store_true", help="Run tracert (slower)")
    parser.add_argument("--json", type=Path, default=None, help="Save report to this JSON file")
    args = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("NetScope v0.1 runs on Windows only")
    if not args.https_url.lower().startswith("https://"):
        parser.error("--https-url must start with https://")
    print(f"NetScope v{__version__} | Запуск диагностики...", flush=True)
    try:
        report = diagnose(args.target, args.domain, args.https_url, args.trace)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 1
    ping = report["ping"]
    print(f"PING {ping['target']}: {ping['received']}/{ping['sent']} replies, {ping['loss_percent']}% loss, avg RTT: {ping['avg_ms'] if ping['avg_ms'] is not None else 'n/a'} ms")
    print(f"DNS: {'OK' if report['dns']['ok'] else 'FAIL'} | {report['dns']['detail']}")
    print(f"HTTPS: {'OK' if report['https']['ok'] else 'FAIL'} | {report['https']['detail']}")
    if report.get("https_windows") is not None:
        schannel = report["https_windows"]
        print(f"Windows TLS (curl): {'OK' if schannel['ok'] else 'FAIL'} | {schannel['detail']}")
    print(f"Маршруты по умолчанию (IPv4): {len(report['default_routes'])} | {report['route_note']}")
    for route in report["default_routes"]:
        print(f"  gateway={route['gateway']} interface={route['interface']} metric={route['metric']}")
    print(f"Сетевые адаптеры: {len(report['adapters'])}")
    for a in report["adapters"]:
        print(f"  {'UP' if a['is_up'] else 'DOWN'} {a['name']} | IPv4={', '.join(a['ipv4']) or '-'}{' | VPN candidate' if a['vpn_candidate'] else ''}")
    print("Выводы:")
    for finding in report["findings"]:
        print(f"  - {finding}")
    if args.trace:
        print("TRACE (raw Windows output):")
        print(report["trace"]["output"])
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Отчёт сохранён: {args.json.resolve()}")
        print("Внимание: отчёт содержит локальные IP и имена адаптеров. Проверь перед отправкой другим.")
    return 0
