"""Advanced NetScope CLI: python -m netscope.investigate --json reports/advanced.json"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path

from .core.investigate import investigate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NetScope VPN / DNS / route / TCP diagnostics (read-only)")
    parser.add_argument("--domain", default="www.python.org")
    parser.add_argument("--dns-servers", default="1.1.1.1,8.8.8.8")
    parser.add_argument("--route-ip", default="1.1.1.1")
    parser.add_argument("--tcp-host", default="www.python.org")
    parser.add_argument("--tcp-port", type=int, default=443)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("NetScope network investigation is supported on Windows 11")
    try:
        data = investigate(args.domain, args.dns_servers, args.route_ip, args.tcp_host, args.tcp_port)
    except ValueError as exc:
        parser.error(str(exc))
    print("NetScope: расширенная диагностика (read-only)")
    for row in data["dns"]["results"]:
        print(f"DNS {row['server']}: {'OK' if row['ok'] else 'FAIL'} | {', '.join(row['ipv4']) or '—'} | {row['detail']}")
    print(f"TCP: {'OK' if data['tcp']['ok'] else 'FAIL'} | {data['tcp']['detail']}")
    print(f"ROUTE: {data['route']['best'] or data['route']['error']}")
    print(f"VPN-похожие активные адаптеры: {len(data['vpn_candidates'])}")
    for finding in data["findings"]:
        print("- " + finding)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Отчёт сохранён: {args.json.resolve()}. Проверьте личные данные перед публикацией.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
