"""Interpret NetScope v0.4+ advanced reports with cautious, offline rules.

Confidence relates to the strength of an *observation*, never the certainty of
its root cause. No network operations and no automatic configuration changes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def validate_investigation(report: Any) -> dict:
    """Reject malformed or unsupported report types before using them."""
    if not isinstance(report, dict):
        raise ValueError("Отчёт должен быть JSON-объектом.")
    for name, typ in (("dns", dict), ("route", dict), ("tcp", dict), ("adapters", list)):
        if not isinstance(report.get(name), typ):
            raise ValueError(f"Нужен расширенный отчёт v0.4+ с полем '{name}'.")
    if not isinstance(report["dns"].get("results"), list) or len(report["dns"]["results"]) > 20:
        raise ValueError("Некорректный список DNS-результатов.")
    for row in report["dns"]["results"]:
        if (not isinstance(row, dict) or not isinstance(row.get("server"), str)
                or not isinstance(row.get("ipv4"), list) or len(row["ipv4"]) > 128
                or not all(isinstance(ip, str) for ip in row["ipv4"])
                or type(row.get("ok")) is not bool):
            raise ValueError("Некорректная DNS-запись.")
    tcp = report["tcp"]
    if (type(tcp.get("ok")) is not bool or not isinstance(tcp.get("host"), str)
            or not isinstance(tcp.get("port"), int)):
        raise ValueError("Некорректный TCP-результат.")
    best = report["route"].get("best")
    if best is not None and (not isinstance(best, dict)
                             or not isinstance(best.get("interface"), str)):
        raise ValueError("Некорректный маршрут.")
    if (len(report["adapters"]) > 200 or
            any(not isinstance(a, dict) or not isinstance(a.get("name"), str)
                or type(a.get("is_up")) is not bool or type(a.get("vpn_candidate")) is not bool
                or not isinstance(a.get("ipv4"), list)
                or not all(isinstance(ip, str) for ip in a["ipv4"])
                for a in report["adapters"])):
        raise ValueError("Некорректный список сетевых адаптеров.")
    return report


def _item(code: str, level: str, confidence: str, title: str, observation: str,
          explanation: str, actions: list[str]) -> dict:
    return dict(code=code, level=level, confidence=confidence, title=title,
                observation=observation, explanation=explanation, actions=actions)


def analyze_report(report: dict) -> dict:
    """Return structured observations from an existing report (no active probes)."""
    report = validate_investigation(report)
    items: list[dict] = []
    dns = report["dns"]
    rows = dns["results"]
    system = next((x for x in rows if x.get("transport") == "system API"), None)
    direct = [x for x in rows if x.get("transport") != "system API"]
    successes = [x for x in rows if x["ok"]]
    failures = [x for x in rows if not x["ok"]]
    if not rows or not successes:
        items.append(_item("dns_all_failed", "warning", "high", "DNS-запросы не дали результата",
                           "Нет успешных DNS-ответов в этом запуске.",
                           "Причина не определена: возможны фильтрация, ошибка резолвера, VPN или недоступность сети.",
                           ["Проверьте DNS и HTTPS в обычном браузере.", "Сравните отчёт при другом сетевом подключении."]))
    elif system and not system["ok"] and any(x["ok"] for x in direct):
        items.append(_item("system_dns_failed", "warning", "high", "Системное DNS-разрешение не удалось",
                           "Прямой UDP/53 ответил, а системный резолвер — нет.",
                           "Различие может быть связано с кэшем, hosts, политиками VPN или правилами разрешения имён.",
                           ["Проверьте разрешение домена через браузер и Resolve-DnsName.", "Сравните с другим доменом."]))
    elif system and system["ok"] and any(not x["ok"] for x in direct):
        items.append(_item("direct_dns_failed", "info", "high", "Часть прямых DNS-запросов не удалась",
                           "Системный DNS отвечает, но один или более UDP/53-запросов не получили ожидаемый ответ.",
                           "UDP/53 может блокироваться, перехватываться или терять пакеты. Это не доказывает сбой интернета.",
                           ["Сравните ответы через системный резолвер.", "При необходимости повторите запрос через другую сеть."]))
    elif failures:
        items.append(_item("partial_dns_failed", "info", "high", "Не все DNS-проверки успешны",
                           f"Успешных результатов: {len(successes)}; неуспешных: {len(failures)}.",
                           "Один неответивший DNS-сервер не означает неисправность всей сети.",
                           ["Повторите тест с теми же серверами."]))
    else:
        items.append(_item("dns_ok", "ok", "high", "DNS-проверки успешны",
                           f"Успешных способов разрешения: {len(successes)}.",
                           "Результат относится только к выбранному домену и моменту проверки.",
                           ["При проблеме с другим сайтом проверьте именно его домен."]))
    if dns.get("answers_differ"):
        items.append(_item("dns_answers_differ", "warning", "high", "DNS-ответы отличаются",
                           "Получены разные наборы IPv4-адресов.",
                           "CDN, балансировка, кэш и политики VPN дают разные адреса без злонамеренного вмешательства.",
                           ["Повторите запросы одновременно.", "Сравните ответы для фиксированного домена и DNS-сервера."]))

    route = report["route"]
    best = route.get("best")
    if not best:
        items.append(_item("route_missing", "warning", "high", "Маршрут не определён",
                           str(route.get("error") or "Таблица Windows не дала подходящего маршрута."),
                           "Это результат анализа таблицы, а не доказательство недоступности адреса.",
                           ["Проверьте route print -4 и состояние адаптеров."]))
    else:
        items.append(_item("route_selected", "info", "medium", "Предполагаемый маршрут IPv4",
                           f"{route.get('destination', 'адрес назначения')}: {best.get('network', '?')} через "
                           f"{best.get('gateway', '?')}, интерфейс {best.get('interface', '?')}, метрика {best.get('metric', '?')}.",
                           "Расчёт сделан по таблице маршрутов; реальный путь может отличаться из-за VPN и политики Windows.",
                           ["При сомнениях проверьте трассировку и соединение по нужному протоколу."]))
        if best.get("gateway") == "On-link" and best.get("prefix_length") == 0:
            matching = [a for a in report["adapters"] if a.get("is_up") and a.get("vpn_candidate")
                        and best.get("interface") in a.get("ipv4", [])]
            if matching:
                label = str(matching[0].get("name", "VPN-подобный интерфейс"))
                items.append(_item("vpn_default_route", "info", "medium", "Маршрут по умолчанию через VPN-подобный интерфейс",
                                   f"Предполагаемый исходящий интерфейс: {label} ({best['interface']}).",
                                   "Низкий ping может отражать ответ туннеля; фактическая задержка до сервера не установлена.",
                                   ["Сравните TCP/HTTPS и ICMP до того же назначения.",
                                    "Повторите измерения до и после включения VPN."]))
        if route.get("ambiguous"):
            items.append(_item("route_ambiguous", "warning", "high", "Выбор маршрута неоднозначен",
                               "Есть маршруты с одинаковым префиксом и отображаемой метрикой.",
                               "Нельзя однозначно предсказать выбранный интерфейс по этому отчёту.",
                               ["Проверьте параметры интерфейсов и маршрут во время реального подключения."]))

    tcp = report["tcp"]
    host_port = f"{tcp.get('host', '?')}:{tcp.get('port', '?')}"
    if tcp["ok"]:
        items.append(_item("tcp_ok", "ok", "high", "TCP-соединение установлено",
                           f"Успешное соединение с {host_port}.",
                           "Это не проверяет HTTPS-сертификат, авторизацию, UDP, голосовой чат или другие порты.",
                           ["Для проблемы с игрой отдельно проверьте нужный протокол и порт."]))
    else:
        items.append(_item("tcp_failed", "warning", "high", "TCP-соединение не установлено",
                           f"Подключение к {host_port} завершилось неуспешно.",
                           "Причину нельзя определить по одному результату: возможны отказ сервера, блокировка, DNS или маршрут.",
                           ["Повторите тест для заведомо доступного хоста:443.",
                            "Сравните результат при другом подключении."]))

    active = [a for a in report["adapters"] if a.get("is_up") and a.get("vpn_candidate")]
    if len(active) >= 2:
        items.append(_item("multiple_vpn", "info", "high", "Несколько VPN-подобных интерфейсов",
                           f"Активных по признаку имени и состояния: {len(active)}.",
                           "Это не означает конфликт или даже использование каждого из них для передачи трафика.",
                           ["Для конкретного IP сравните предполагаемый маршрут и фактическое соединение."]))
    summary = {level: sum(x["level"] == level for x in items) for level in ("warning", "ok", "info")}
    return {"analysis_version": "1", "generated_utc": datetime.now(timezone.utc).isoformat(),
            "source_created_utc": report.get("created_utc"), "summary": summary, "items": items,
            "disclaimer": "Эвристические рекомендации, а не автоматическое установление причины сбоя. Настройки сети не изменяются."}
