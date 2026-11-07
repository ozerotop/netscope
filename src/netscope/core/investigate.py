"""Orchestrate advanced diagnostics without modifying the host's configuration."""
from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import asdict

from netscope import __version__
from .adapters import list_adapters
from .dns_compare import compare_dns, parse_dns_servers
from .monitor import validate_target
from .route_analysis import inspect_route
from .tcp_probe import check_tcp


def investigate(domain: str = "www.python.org", dns_servers: str = "1.1.1.1, 8.8.8.8",
                route_ip: str = "1.1.1.1", tcp_host: str = "www.python.org",
                tcp_port: int = 443) -> dict:
    """Validate arguments before issuing any network traffic."""
    servers = parse_dns_servers(dns_servers)
    domain = validate_target(domain)
    tcp_host = validate_target(tcp_host)
    if not isinstance(tcp_port, int) or not 1 <= tcp_port <= 65535:
        raise ValueError("TCP-порт должен быть между 1 и 65535.")
    import ipaddress
    try:
        ipaddress.IPv4Address(route_ip)
    except ipaddress.AddressValueError as exc:
        raise ValueError("Для проверки маршрута нужен IPv4-адрес.") from exc

    dns = compare_dns(domain, servers)
    route = inspect_route(route_ip)
    tcp = check_tcp(tcp_host, tcp_port)
    adapters = [asdict(a) for a in list_adapters()]
    active_vpn_candidates = [a for a in adapters if a["is_up"] and a["vpn_candidate"]]
    findings: list[str] = []
    if active_vpn_candidates:
        findings.append(f"Активных адаптеров с VPN/TUN-подобным названием: {len(active_vpn_candidates)}. Название не доказывает активное VPN-соединение.")
    if len(active_vpn_candidates) > 1:
        findings.append("Несколько VPN-похожих интерфейсов могут сосуществовать нормально; конфликт без дополнительных проверок не установлен.")
    if dns["answers_differ"]:
        findings.append("DNS-ответы различаются. Причиной могут быть CDN, кеш, политика DNS или перенаправление; это НЕ доказательство подмены.")
    if any(not row["ok"] for row in dns["results"]):
        findings.append("Некоторые DNS-проверки не дали ответа. Прямой незашифрованный UDP/53 может блокироваться или перенаправляться VPN.")
    if route["best"] is not None:
        best = route["best"]
        findings.append(f"Предполагаемый маршрут до {route_ip}: {best['network']} через {best['gateway']} (интерфейс {best['interface']}, метрика {best['metric']}).")
        if best["gateway"] == "On-link" and best["prefix_length"] == 0:
            findings.append("Маршрут по умолчанию 'On-link' может принадлежать виртуальному туннелю; очень малый ping не доказывает задержку до внешнего сервера.")
        if route["ambiguous"]:
            findings.append("Несколько маршрутов имеют одинаковую длину префикса и метрику; выбор Windows может отличаться от этой оценки.")
    else:
        findings.append("Маршрут не определён: " + route["error"])
    if tcp["ok"]:
        findings.append(f"TCP-соединение к {tcp_host}:{tcp_port} установлено; доступность игры, UDP и авторизация этим не проверены.")
    else:
        findings.append(f"TCP-соединение к {tcp_host}:{tcp_port} не установлено. Возможны блокировка, отказ сервера, неверный порт или проблема DNS/маршрута.")
    return {"app_version": __version__, "created_utc": datetime.now(timezone.utc).isoformat(),
            "dns": dns, "route": route, "tcp": tcp, "adapters": adapters,
            "vpn_candidates": active_vpn_candidates, "findings": findings,
            "privacy_note": "Отчёт содержит имена интерфейсов, внутренние адреса, DNS-результаты и имена проверяемых серверов."}
