from __future__ import annotations
import socket
from time import monotonic
from .models import Check


def check_dns(domain: str) -> tuple[Check, list[str]]:
    started = monotonic()
    try:
        records = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        ips = sorted({item[4][0] for item in records})
        if not ips:
            return Check(False, "No IPv4 records", round((monotonic()-started)*1000,1)), []
        return Check(True, f"Resolved {domain}: {', '.join(ips)}", round((monotonic()-started)*1000,1)), ips
    except (socket.gaierror, OSError, UnicodeError) as exc:
        return Check(False, f"Cannot resolve {domain}: {exc}", round((monotonic()-started)*1000,1)), []
