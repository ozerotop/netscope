"""Read-only network interface inventory (no MAC addresses exported)."""
from __future__ import annotations
import socket
import psutil
from .models import Adapter

_VPN_HINTS = (
    "wireguard", "wintun", "warp", "openvpn", "tap-", "tunnel", "tun ",
    "radmin vpn", "vpn", "happ", "tailscale", "zerotier", "protonvpn", "nordlynx",
)


def list_adapters() -> list[Adapter]:
    addresses = psutil.net_if_addrs()
    statuses = psutil.net_if_stats()
    result = []
    for name in sorted(addresses, key=str.lower):
        ipv4 = sorted({a.address for a in addresses[name] if a.family == socket.AF_INET})
        status = statuses.get(name)
        result.append(Adapter(
            name=name,
            is_up=bool(status and status.isup),
            ipv4=ipv4,
            vpn_candidate=any(hint in name.casefold() for hint in _VPN_HINTS),
        ))
    return result
