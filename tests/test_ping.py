from netscope.core.ping import parse_ping_replies, ping


def test_english_ping_replies():
    raw = "Reply from 1.1.1.1: bytes=32 time=12ms TTL=57\nRequest timed out.\nReply from 1.1.1.1: bytes=32 time<1ms TTL=57"
    assert parse_ping_replies(raw) == [12.0, 0.5]


def test_russian_ping_replies():
    raw = "Ответ от 1.1.1.1: число байт=32 время=13мс TTL=57\nОтвет от 1.1.1.1: число байт=32 время<1мс TTL=57"
    assert parse_ping_replies(raw) == [13.0, 0.5]


def test_ping_partial(monkeypatch):
    monkeypatch.setattr("netscope.core.ping.run_windows", lambda args, timeout: (1, "Reply from 1.1.1.1: bytes=32 time=5ms TTL=58\nRequest timed out."))
    result = ping("1.1.1.1", count=2)
    assert result.received == 1
    assert result.loss_percent == 50.0
    assert result.avg_ms == 5.0
