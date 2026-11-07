"""Read-only summary of Windows IPv4 default routes."""
from __future__ import annotations
import re
from .windows import run_windows

_DEFAULT = re.compile(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+(\d+)\s*$", re.MULTILINE)


def get_default_routes() -> tuple[list[dict[str, str | int]], str]:
    try:
        code, output = run_windows(["route.exe", "print", "-4"], timeout=10)
    except (OSError, TimeoutError) as exc:
        return [], f"route print failed: {exc}"
    if code != 0:
        return [], f"route print returned {code}: {output[-200:]}"
    routes = [
        {"gateway": match.group(1), "interface": match.group(2), "metric": int(match.group(3))}
        for match in _DEFAULT.finditer(output)
    ]
    return routes, "OK" if routes else "No IPv4 default route found in route print output"


def trace_route(target: str, max_hops: int = 8) -> tuple[bool, str]:
    if not target or target.startswith("-") or any(c.isspace() for c in target):
        return False, "Invalid trace target"
    try:
        code, output = run_windows(
            ["tracert.exe", "-4", "-d", "-h", str(max_hops), "-w", "500", target],
            timeout=max_hops * 3 * 0.5 + 10,
        )
        return code == 0, output.strip()
    except (OSError, TimeoutError) as exc:
        return False, f"tracert failed: {exc}"
