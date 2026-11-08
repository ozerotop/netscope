"""SQLite history regression suite; runs without Windows, Qt or internet."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from netscope.core.history import (
    MAX_REPORT_BYTES, HistoryStore, default_database_path, describe, report_type,
)


def basic(**changes):
    report = {
        "app_version": "0.6.0", "created_utc": "2026-11-08T10:00:00+00:00",
        "ping": {"target": "1.1.1.1", "received": 4, "sent": 4, "loss_percent": 0.0},
        "dns": {"ok": True, "detail": "OK"}, "https": {"ok": True},
        "adapters": [{"name": "VPN", "ipv4": ["10.0.0.1"]}],
    }
    report.update(changes)
    return report


def advanced(**changes):
    report = {
        "app_version": "0.6.0", "created_utc": "2026-11-08T10:01:00+00:00",
        "dns": {"results": [{"server": "1.1.1.1", "ok": True, "ipv4": ["1.2.3.4"]}]},
        "route": {"destination": "1.1.1.1", "best": None},
        "tcp": {"host": "www.python.org", "port": 443, "ok": True},
        "adapters": [], "findings": [],
    }
    report.update(changes)
    return report


def test_round_trip_and_persistence(tmp_path: Path):
    db = tmp_path / "private" / "history.sqlite3"
    first = HistoryStore(db)
    rid = first.add(basic())
    assert rid == 1
    assert db.exists()
    assert HistoryStore(db).get(rid) == basic()


def test_both_kinds_and_filter(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    store.add(basic())
    rid = store.add(advanced())
    assert [x.kind for x in store.list_recent()] == ["investigation", "basic"]
    assert [x.id for x in store.list_recent(kind="investigation")] == [rid]
    assert store.list_recent(kind="basic")[0].target == "1.1.1.1"
    assert store.list_recent(kind="investigation")[0].status == "DNS: OK · TCP: OK"


def test_delete_single_entry(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    first = store.add(basic())
    second = store.add(advanced())
    assert store.delete(first) is True
    assert store.delete(first) is False
    assert store.get(first) is None
    assert store.get(second) == advanced()


def test_entries_latest_first_and_limit(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    for i in range(5):
        store.add(basic(ping={"target": f"192.0.2.{i}", "received": 4}))
    assert [x.id for x in store.list_recent(limit=2)] == [5, 4]


def test_input_validation(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    with pytest.raises(ValueError):
        store.add({"unknown": "format"})
    with pytest.raises(ValueError):
        store.add("not a dictionary")
    with pytest.raises(ValueError):
        store.add(basic(ping=[]))
    with pytest.raises(ValueError):
        store.list_recent(kind="injection")
    with pytest.raises(ValueError):
        store.list_recent(limit=2001)
    for bad_id in (0, -1, True, "1 OR 1=1"):
        with pytest.raises(ValueError):
            store.get(bad_id)
        with pytest.raises(ValueError):
            store.delete(bad_id)


def test_sql_safe_string_and_unicode(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    original = basic(ping={"target": "'; DROP TABLE diagnostic_reports; --"})
    rid = store.add(original)
    assert store.get(rid) == original
    assert len(store.list_recent()) == 1


def test_oversized_and_non_finite_reports_rejected(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    with pytest.raises(ValueError, match="2 МБ"):
        store.add(basic(extra="й" * MAX_REPORT_BYTES))
    with pytest.raises(ValueError):
        store.add(basic(extra=float("nan")))
    assert store.list_recent() == []


def test_corrupt_record_rejected(tmp_path):
    db = tmp_path / "h.db"
    store = HistoryStore(db)
    rid = store.add(basic())
    with sqlite3.connect(db) as con:
        con.execute("UPDATE diagnostic_reports SET report_json=? WHERE id=?", ('{"bad":true}', rid))
    with pytest.raises(ValueError):
        store.get(rid)


def test_default_windows_profile_location(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert default_database_path() == tmp_path / "NetScope" / "history.sqlite3"


def test_fallback_profile_location(monkeypatch, tmp_path):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert default_database_path() == tmp_path / "AppData" / "Local" / "NetScope" / "history.sqlite3"


def test_description_and_types():
    assert report_type(basic()) == "basic"
    assert report_type(advanced()) == "investigation"
    assert describe(basic(), "basic") == ("1.1.1.1", "DNS: OK · HTTPS: OK")
    assert describe(advanced(tcp={"host": "test.example", "port": 443, "ok": False}), "investigation")[1] == "DNS: OK · TCP: FAIL"


def test_version_independent_history(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    report = advanced(app_version="0.4.0")
    assert store.get(store.add(report)) == report
