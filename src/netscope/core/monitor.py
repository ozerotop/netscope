"""Read-only ICMP monitoring model, independent of the Qt graphical interface.

A missing ICMP reply is recorded as *no reply*, not proof the Internet is offline.
The Windows ping executable is called without shell=True by core.ping.
"""
from __future__ import annotations

import csv
import ipaddress
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .ping import ping

MAX_TARGETS = 3
MAX_HISTORY = 10_000  # per target; bound RAM consumption on long-running sessions
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_target(value: str) -> str:
    """Accept IPv4 or ASCII DNS names, but not commands, URLs, or IPv6."""
    value = value.strip()
    if not value or len(value) > 253 or any(ch.isspace() for ch in value):
        raise ValueError("Укажите IPv4-адрес или доменное имя без пробелов.")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        domain = value.rstrip(".")
        if not domain or not all(_HOST_LABEL.fullmatch(part) for part in domain.split(".")):
            raise ValueError(f"Недопустимый адрес: {value!r}") from None
        return domain.lower()
    if addr.version != 4:
        raise ValueError("В этой версии мониторинга поддерживаются только IPv4-адреса.")
    return str(addr)


def parse_targets(text: str) -> list[str]:
    """Return 1-3 unique hosts from a comma-separated input."""
    parts = [part.strip() for part in text.split(",")]
    if not all(parts) or len(parts) > MAX_TARGETS:
        raise ValueError("Введите от 1 до 3 адресов через запятую.")
    targets = [validate_target(p) for p in parts]
    if len(set(targets)) != len(targets):
        raise ValueError("Адреса не должны повторяться.")
    return targets


@dataclass(frozen=True)
class ProbeSample:
    cycle: int
    target: str
    timestamp_utc: str
    received: bool
    rtt_ms: float | None
    detail: str


def probe_target(target: str, cycle: int, timeout_ms: int = 1000) -> ProbeSample:
    """Issue one Windows ping probe. DNS resolution is part of ping.exe's operation."""
    try:
        result = ping(target, count=1, timeout_ms=timeout_ms)
        ok = result.received > 0
        return ProbeSample(cycle, target, datetime.now(timezone.utc).isoformat(), ok,
                           result.avg_ms if ok else None, result.detail)
    except (OSError, RuntimeError, ValueError) as exc:
        return ProbeSample(cycle, target, datetime.now(timezone.utc).isoformat(),
                           False, None, f"Ошибка проверки: {exc}")


class MonitorSession:
    """Lifetime counters and a bounded sample log suitable for plotting/export."""

    def __init__(self, targets: list[str], history_limit: int = MAX_HISTORY) -> None:
        if not targets or history_limit < 1:
            raise ValueError("targets and history_limit must be non-empty and positive")
        self.targets = list(targets)
        self.history = {host: deque(maxlen=history_limit) for host in targets}
        self._count = dict.fromkeys(targets, 0)
        self._received = dict.fromkeys(targets, 0)
        self._rtt_sum = dict.fromkeys(targets, 0.0)
        self._rtt_n = dict.fromkeys(targets, 0)
        self._rtt_min: dict[str, float | None] = dict.fromkeys(targets)
        self._rtt_max: dict[str, float | None] = dict.fromkeys(targets)

    def add(self, sample: ProbeSample) -> None:
        if sample.target not in self.history:
            raise ValueError(f"Unexpected target: {sample.target}")
        self.history[sample.target].append(sample)
        self._count[sample.target] += 1
        if sample.received:
            self._received[sample.target] += 1
        if sample.received and sample.rtt_ms is not None:
            host, latency = sample.target, sample.rtt_ms
            self._rtt_sum[host] += latency
            self._rtt_n[host] += 1
            self._rtt_min[host] = latency if self._rtt_min[host] is None else min(self._rtt_min[host], latency)
            self._rtt_max[host] = latency if self._rtt_max[host] is None else max(self._rtt_max[host], latency)

    def summary(self, target: str) -> dict:
        attempts = self._count[target]
        success = self._received[target]
        latest = self.history[target][-1] if self.history[target] else None
        return {
            "target": target,
            "sent": attempts,
            "received": success,
            "loss_percent": round(100 * (attempts - success) / attempts, 1) if attempts else 0.0,
            "last_rtt_ms": latest.rtt_ms if latest and latest.received else None,
            "last_received": latest.received if latest else None,
            "min_ms": self._rtt_min[target],
            "avg_ms": round(self._rtt_sum[target] / self._rtt_n[target], 1) if self._rtt_n[target] else None,
            "max_ms": self._rtt_max[target],
        }

    def export_csv(self, filename: str | Path) -> None:
        """Write stored samples (at most MAX_HISTORY per host), UTF-8 with Excel BOM."""
        with Path(filename).open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(["timestamp_utc", "cycle", "host", "reply", "rtt_ms", "detail"])
            samples = (s for host in self.targets for s in self.history[host])
            for sample in sorted(samples, key=lambda s: (s.cycle, s.target)):
                writer.writerow([
                    sample.timestamp_utc, sample.cycle, sample.target,
                    "yes" if sample.received else "no",
                    "" if sample.rtt_ms is None else sample.rtt_ms,
                    sample.detail,
                ])
