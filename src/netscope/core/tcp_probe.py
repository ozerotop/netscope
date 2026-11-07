"""Single TCP connect probe, not a port scanner or game authentication test."""
from __future__ import annotations

import socket
from time import monotonic

from .monitor import validate_target


def check_tcp(host: str, port: int, timeout: float = 2.5) -> dict:
    host = validate_target(host)
    if not 1 <= port <= 65535:
        raise ValueError("TCP-порт должен быть в диапазоне от 1 до 65535.")
    started = monotonic()
    try:
        addresses = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if not addresses:
            raise OSError("IPv4 address not resolved")
    except (OSError, socket.gaierror) as exc:
        return {"host": host, "port": port, "ok": False, "ip": None, "duration_ms": round((monotonic()-started)*1000, 1),
                "detail": f"DNS / address resolution failed: {exc}"}
    failures: list[str] = []
    for family, sock_type, proto, _, endpoint in addresses[:4]:
        try:
            with socket.socket(family, sock_type, proto) as sock:
                sock.settimeout(timeout)
                sock.connect(endpoint)
            return {"host": host, "port": port, "ok": True, "ip": endpoint[0],
                    "duration_ms": round((monotonic()-started)*1000, 1),
                    "detail": "TCP handshake completed; no guarantee of application/game functionality"}
        except OSError as exc:
            failures.append(f"{endpoint[0]}: {exc}")
    return {"host": host, "port": port, "ok": False, "ip": None,
            "duration_ms": round((monotonic()-started)*1000, 1),
            "detail": "; ".join(failures[:3]) or "TCP did not connect"}
