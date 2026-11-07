"""Read-only DNS comparison: Windows system resolver vs direct *unencrypted* UDP A queries.

Direct UDP tests may be intercepted, blocked or redirected. A changed A record
is not proof of DNS spoofing (CDN geolocation, caching and policy matter).
"""
from __future__ import annotations

import ipaddress
import secrets
import socket
import struct
from time import monotonic

from .monitor import validate_target

MAX_SERVERS = 3


def parse_dns_servers(text: str) -> list[str]:
    parts = [part.strip() for part in text.split(",")]
    if not 1 <= len(parts) <= MAX_SERVERS or not all(parts):
        raise ValueError("Укажите от 1 до 3 DNS IPv4-адресов через запятую.")
    try:
        servers = [str(ipaddress.IPv4Address(p)) for p in parts]
    except ipaddress.AddressValueError as exc:
        raise ValueError("DNS-сервер должен быть IPv4-адресом, например 1.1.1.1.") from exc
    if len(set(servers)) != len(servers):
        raise ValueError("DNS-серверы не должны повторяться.")
    return servers


def _skip_name(data: bytes, offset: int) -> int:
    """Skip a DNS wire-format name including a compression pointer, with bounds."""
    for _ in range(128):
        if offset >= len(data):
            raise ValueError("DNS name exceeds packet")
        label = data[offset]
        if label & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Truncated DNS pointer")
            ptr = ((label & 0x3F) << 8) | data[offset + 1]
            if ptr >= len(data):
                raise ValueError("DNS pointer outside packet")
            return offset + 2
        if label & 0xC0 or label > 63:
            raise ValueError("Invalid DNS label")
        offset += 1
        if label == 0:
            return offset
        if offset + label > len(data):
            raise ValueError("Truncated DNS label")
        offset += label
    raise ValueError("Too many DNS labels")


def make_dns_query(domain: str, transaction_id: int) -> bytes:
    domain = validate_target(domain)
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("Для DNS-проверки требуется домен, а не IP-адрес.")
    labels = domain.split(".")
    encoded = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\x00"
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + encoded + struct.pack("!HH", 1, 1)


def parse_dns_response(packet: bytes, transaction_id: int) -> tuple[list[str], str]:
    if len(packet) < 12:
        raise ValueError("DNS response too short")
    query_id, flags, qdcount, answer_count, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if query_id != transaction_id or not (flags & 0x8000):
        raise ValueError("Unexpected DNS transaction or packet type")
    if flags & 0x0200:
        raise ValueError("Truncated DNS UDP response (TCP retry not implemented)")
    rcode = flags & 0xF
    if rcode:
        return [], f"DNS server returned RCODE={rcode}"
    if qdcount != 1 or answer_count > 256:
        raise ValueError("Unexpected DNS question/answer count")
    offset = _skip_name(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("Truncated DNS question")
    offset += 4
    addresses = set()
    for _ in range(answer_count):
        offset = _skip_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("Truncated DNS record header")
        rr_type, rr_class, _ttl, length = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        if offset + length > len(packet):
            raise ValueError("Truncated DNS record data")
        if rr_type == 1 and rr_class == 1 and length == 4:
            addresses.add(str(ipaddress.IPv4Address(packet[offset:offset+4])))
        offset += length
    return sorted(addresses), "OK" if addresses else "No IPv4 A records in answer"


def query_udp_a(domain: str, server: str, timeout: float = 2.0) -> dict:
    started = monotonic()
    transaction_id = secrets.randbelow(65536)
    try:
        packet = make_dns_query(domain, transaction_id)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((server, 53))
            sock.send(packet)
            response = sock.recv(4096)
        addresses, note = parse_dns_response(response, transaction_id)
        ok = note == "OK"
    except (socket.timeout, socket.gaierror, OSError, ValueError) as exc:
        addresses, note, ok = [], f"{type(exc).__name__}: {exc}", False
    return {"server": server, "transport": "UDP/53 (unencrypted)", "ok": ok,
            "ipv4": addresses, "detail": note, "duration_ms": round((monotonic()-started)*1000, 1)}


def compare_dns(domain: str, servers: list[str]) -> dict:
    domain = validate_target(domain)
    # Reject IPs in a clear way rather than treating them as domain wire labels.
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("DNS-домен должен быть именем хоста, а не IP-адресом.")
    started = monotonic()
    try:
        records = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        system_ipv4 = sorted({item[4][0] for item in records})
        system_error = "" if system_ipv4 else "Windows resolver returned no IPv4 records"
    except (socket.gaierror, OSError, UnicodeError) as exc:
        system_ipv4, system_error = [], f"{type(exc).__name__}: {exc}"
    system = {"server": "Windows (системный резолвер)", "transport": "system API", "ok": bool(system_ipv4),
              "ipv4": system_ipv4, "detail": system_error or "OK", "duration_ms": round((monotonic()-started)*1000, 1)}
    direct = [query_udp_a(domain, server) for server in servers]
    sets = [set(item["ipv4"]) for item in [system, *direct] if item["ok"]]
    differs = len(sets) >= 2 and any(addresses != sets[0] for addresses in sets[1:])
    return {"domain": domain, "results": [system, *direct], "answers_differ": differs}
