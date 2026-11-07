"""Read-only, *estimated* IPv4 route choice from Windows `route print -4`.

Uses the active routes table and the metric displayed by route.exe. Windows may
also apply policy, source-address rules and virtual-adapter behaviour: the result
is a useful hint, never a promise about the actual path of a packet.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass

from .windows import run_windows

# Active route rows are five whitespace-delimited fields, language independent.
_ROW = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s*$")
_ON_LINK = {"on-link", "onlink", "на-канале", "на-линке", "on-link."}


@dataclass(frozen=True)
class IPv4Route:
    network: str
    gateway: str
    interface: str
    metric: int
    prefix_length: int


def parse_active_routes(output: str) -> list[IPv4Route]:
    """Read only 5-column active IPv4 route rows (not persistent route records)."""
    routes = []
    seen: set[tuple[str, str, str, int]] = set()
    for line in output.splitlines():
        match = _ROW.fullmatch(line)
        if not match:
            continue
        destination, mask, gateway, interface, metric_text = match.groups()
        try:
            network = ipaddress.IPv4Network((destination, mask), strict=False)
            ipaddress.IPv4Address(interface)
            if gateway.casefold() not in _ON_LINK:
                ipaddress.IPv4Address(gateway)
            metric = int(metric_text)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            continue
        gateway = "On-link" if gateway.casefold() in _ON_LINK else gateway
        key = (str(network), gateway, interface, metric)
        if key not in seen:
            routes.append(IPv4Route(str(network), gateway, interface, metric, network.prefixlen))
            seen.add(key)
    return routes


def matching_routes(ip: str, routes: list[IPv4Route]) -> list[IPv4Route]:
    """Longest prefix first, then lowest displayed metric. Exact tie is ambiguous."""
    address = ipaddress.IPv4Address(ip)
    return sorted(
        (route for route in routes if address in ipaddress.IPv4Network(route.network)),
        key=lambda route: (-route.prefix_length, route.metric, route.interface, route.gateway),
    )


def inspect_route(destination: str) -> dict:
    try:
        ipaddress.IPv4Address(destination)
    except ipaddress.AddressValueError as exc:
        raise ValueError("Маршрут проверяется только для IPv4-адреса, например 1.1.1.1.") from exc
    try:
        code, output = run_windows(["route.exe", "print", "-4"], timeout=12)
    except (OSError, RuntimeError, TimeoutError) as exc:
        return {"destination": destination, "ok": False, "error": str(exc), "matches": [], "best": None,
                "ambiguous": False}
    if code != 0:
        return {"destination": destination, "ok": False, "error": f"route.exe exited {code}: {output[-250:]}",
                "matches": [], "best": None, "ambiguous": False}
    candidates = matching_routes(destination, parse_active_routes(output))
    ties = len(candidates) > 1 and (candidates[0].prefix_length, candidates[0].metric) == (candidates[1].prefix_length, candidates[1].metric)
    return {"destination": destination, "ok": bool(candidates),
            "error": "" if candidates else "Для адреса не найден активный маршрут IPv4.",
            "matches": [asdict(r) for r in candidates[:20]],
            "best": asdict(candidates[0]) if candidates else None, "ambiguous": ties}
