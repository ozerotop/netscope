"""Windows ping and locale-tolerant reply parsing."""
from __future__ import annotations
import re
from .models import PingResult
from .windows import run_windows

_RTT = re.compile(r"(?:time|время)\s*([=<])\s*(\d+)\s*(?:ms|мс)", re.IGNORECASE)
_TTL = re.compile(r"\bTTL\s*=", re.IGNORECASE)


def parse_ping_replies(output: str) -> list[float | None]:
    """Identify replies by TTL=, regardless of EN/RU message text."""
    replies = []
    for line in output.splitlines():
        if not _TTL.search(line):
            continue
        match = _RTT.search(line)
        if not match:
            replies.append(None)
        else:
            value = float(match.group(2))
            replies.append(0.5 if match.group(1) == "<" and value == 1 else value)
    return replies


def ping(target: str, count: int = 4, timeout_ms: int = 1200) -> PingResult:
    if not 1 <= count <= 20:
        raise ValueError("count must be between 1 and 20")
    if not target or len(target) > 253 or target.startswith("-") or any(ch.isspace() for ch in target):
        raise ValueError("Invalid host/IP target")
    try:
        code, output = run_windows(
            ["ping.exe", "-4", "-n", str(count), "-w", str(timeout_ms), target],
            timeout=(count * timeout_ms / 1000) + 8,
        )
    except (OSError, TimeoutError) as exc:
        return PingResult(target, count, 0, None, f"Ping command failed: {exc}")
    replies = parse_ping_replies(output)
    samples = [value for value in replies if value is not None]
    avg = round(sum(samples) / len(samples), 1) if samples else None
    received = min(len(replies), count)
    if received == count:
        detail = "All probes replied"
    elif received:
        detail = f"Partial replies ({received}/{count})"
    else:
        detail = "No ICMP replies (this does NOT prove the internet is offline)"
    if code != 0 and not received:
        detail += "; ICMP may be blocked or destination unreachable"
    return PingResult(target, count, received, avg, detail)
