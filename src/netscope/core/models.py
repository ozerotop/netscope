from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Check:
    ok: bool
    detail: str
    duration_ms: float | None = None


@dataclass
class PingResult:
    target: str
    sent: int
    received: int
    avg_ms: float | None
    detail: str

    @property
    def loss_percent(self) -> float:
        return round(100 * (self.sent - self.received) / self.sent, 1) if self.sent else 100.0


@dataclass
class Adapter:
    name: str
    is_up: bool
    ipv4: list[str] = field(default_factory=list)
    vpn_candidate: bool = False
