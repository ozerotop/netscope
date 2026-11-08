"""Offline comparisons of two NetScope advanced diagnostic reports."""
from __future__ import annotations

from datetime import datetime, timezone

from .insights import validate_investigation


def _vpn_names(report: dict) -> set[str]:
    return {str(a.get("name", "")) for a in report["adapters"]
            if a.get("vpn_candidate") and a.get("is_up") and a.get("name")}


def _dns_answers(report: dict) -> dict[str, tuple[bool, tuple[str, ...]]]:
    return {str(x.get("server", "?")): (x["ok"], tuple(sorted(str(ip) for ip in x["ipv4"])))
            for x in report["dns"]["results"]}


def compare_reports(before: dict, after: dict) -> dict:
    """Compare observations; never infer VPN caused any reported difference."""
    before = validate_investigation(before)
    after = validate_investigation(after)
    changes: list[dict] = []
    limitations = ["Изменения между двумя проверками не доказывают причинно-следственную связь с VPN."]

    def add(topic: str, status: str, text: str) -> None:
        changes.append({"topic": topic, "status": status, "description": text})

    domain_a, domain_b = before["dns"].get("domain"), after["dns"].get("domain")
    if domain_a != domain_b:
        add("DNS", "not_comparable", "Разные домены: DNS-ответы не сравниваются.")
    else:
        a, b = _dns_answers(before), _dns_answers(after)
        shared = sorted(set(a) & set(b))
        if not shared:
            add("DNS", "not_comparable", "Нет общих DNS-резолверов для сравнения.")
        else:
            for server in shared:
                if a[server] != b[server]:
                    add("DNS", "changed", f"{server}: изменились статус запроса или набор IPv4-ответов.")
            if not any(c["topic"] == "DNS" and c["status"] == "changed" for c in changes):
                add("DNS", "same", f"Ответы совпадают для {len(shared)} общих резолверов.")
            if set(a) != set(b):
                limitations.append("Часть DNS-серверов проверялась только в одном из отчётов.")

    route_a, route_b = before["route"], after["route"]
    if route_a.get("destination") != route_b.get("destination"):
        add("Маршрут", "not_comparable", "Разные IPv4-адреса назначения: маршрут не сравнивается.")
    else:
        def signature(route: dict) -> tuple:
            best = route.get("best")
            if not best:
                return (None,)
            return (best.get("network"), best.get("gateway"), best.get("interface"), best.get("metric"))
        if signature(route_a) == signature(route_b):
            add("Маршрут", "same", "Предполагаемый маршрут по таблице Windows не изменился.")
        else:
            add("Маршрут", "changed", "Изменился предполагаемый маршрут (сеть, шлюз, интерфейс или метрика).")

    tcp_a, tcp_b = before["tcp"], after["tcp"]
    if (tcp_a.get("host"), tcp_a.get("port")) != (tcp_b.get("host"), tcp_b.get("port")):
        add("TCP", "not_comparable", "Разные TCP-хост или порт: результаты не сравниваются.")
    elif tcp_a["ok"] == tcp_b["ok"]:
        add("TCP", "same", f"Статус TCP не изменился: {'успех' if tcp_b['ok'] else 'нет соединения'}.")
    else:
        add("TCP", "changed", f"TCP: {'успех' if tcp_a['ok'] else 'нет соединения'} → "
                              f"{'успех' if tcp_b['ok'] else 'нет соединения'}.")

    vpn_before, vpn_after = _vpn_names(before), _vpn_names(after)
    if vpn_before == vpn_after:
        add("Адаптеры", "same", "Набор активных VPN-подобных интерфейсов не изменился.")
    else:
        added, removed = sorted(vpn_after - vpn_before), sorted(vpn_before - vpn_after)
        text = []
        if added:
            text.append("Появились: " + ", ".join(added))
        if removed:
            text.append("Исчезли: " + ", ".join(removed))
        add("Адаптеры", "changed", "; ".join(text) + ".")

    return {"generated_utc": datetime.now(timezone.utc).isoformat(),
            "before_utc": before.get("created_utc"), "after_utc": after.get("created_utc"),
            "changes": changes, "limitations": limitations,
            "changed_count": sum(c["status"] == "changed" for c in changes)}
