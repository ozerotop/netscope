import csv
import pytest

from netscope.core.monitor import (
    MAX_HISTORY, MonitorSession, ProbeSample, parse_targets, probe_target, validate_target,
)
from netscope.core.models import PingResult


def sample(host, cycle, ok, ms=None):
    return ProbeSample(cycle, host, f"2026-11-08T00:00:{cycle:02d}+00:00", ok, ms, "test")


def test_validate_targets():
    assert parse_targets("1.1.1.1, WWW.PYTHON.ORG, 8.8.8.8") == ["1.1.1.1", "www.python.org", "8.8.8.8"]
    assert parse_targets("localhost") == ["localhost"]


@pytest.mark.parametrize("invalid", ["", "example.com,", "1.1.1.1,1.1.1.1", "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4", "https://x.org", "x && whoami", "a..b", "::1", "-host", "under_score.com"])
def test_invalid_targets(invalid):
    with pytest.raises(ValueError):
        parse_targets(invalid)


def test_monitor_stats_and_missing_samples():
    session = MonitorSession(["1.1.1.1"])
    session.add(sample("1.1.1.1", 1, True, 10.0))
    session.add(sample("1.1.1.1", 2, False))
    session.add(sample("1.1.1.1", 3, True, 20.0))
    s = session.summary("1.1.1.1")
    assert s["sent"] == 3 and s["received"] == 2
    assert s["loss_percent"] == 33.3
    assert (s["min_ms"], s["avg_ms"], s["max_ms"]) == (10.0, 15.0, 20.0)
    assert s["last_rtt_ms"] == 20


def test_unknown_rtt_is_not_packet_loss():
    session = MonitorSession(["1.1.1.1"])
    session.add(sample("1.1.1.1", 1, True, None))
    s = session.summary("1.1.1.1")
    assert s["received"] == 1 and s["loss_percent"] == 0.0
    assert s["avg_ms"] is None


def test_history_bound_does_not_reset_counters():
    session = MonitorSession(["1.1.1.1"], history_limit=2)
    for n in range(5):
        session.add(sample("1.1.1.1", n + 1, True, 1.0 + n))
    assert len(session.history["1.1.1.1"]) == 2
    assert session.summary("1.1.1.1")["sent"] == 5
    assert session.summary("1.1.1.1")["avg_ms"] == 3.0


def test_export_utf8_csv(tmp_path):
    session = MonitorSession(["1.1.1.1"])
    session.add(sample("1.1.1.1", 1, False))
    out = tmp_path / "monitor.csv"
    session.export_csv(out)
    with out.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["host"] == "1.1.1.1"
    assert rows[0]["reply"] == "no"
    assert rows[0]["rtt_ms"] == ""


def test_probe_target_calls_one_ping(monkeypatch):
    called = []
    def fake_ping(host, count, timeout_ms):
        called.append((host, count, timeout_ms))
        return PingResult(host, 1, 1, 12.0, "ok")
    monkeypatch.setattr("netscope.core.monitor.ping", fake_ping)
    result = probe_target("1.1.1.1", cycle=7)
    assert called == [("1.1.1.1", 1, 1000)]
    assert result.received and result.rtt_ms == 12.0 and result.cycle == 7
