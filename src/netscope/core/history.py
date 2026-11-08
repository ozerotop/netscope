"""Private local SQLite history for completed NetScope diagnostic reports.

Never uploads reports, changes Windows networking, or stores secrets intentionally.
History is opt-in for exports but automatic for completed desktop diagnostics.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MAX_REPORT_BYTES = 2_000_000
DEFAULT_LIST_LIMIT = 200


@dataclass(frozen=True)
class HistoryEntry:
    id: int
    captured_at: str
    stored_at: str
    kind: str
    target: str
    status: str


def default_database_path() -> Path:
    """Store diagnostic data outside the checkout and user's Documents folder."""
    base = os.environ.get("LOCALAPPDATA")
    return (Path(base) if base else Path.home() / "AppData" / "Local") / "NetScope" / "history.sqlite3"


def report_type(report: dict) -> str:
    """Detect only known NetScope report shapes; don't trust filename or version."""
    if not isinstance(report, dict):
        raise ValueError("Отчёт должен быть JSON-объектом.")
    if all(key in report for key in ("route", "tcp", "dns", "adapters")):
        if not isinstance(report["tcp"], dict) or not isinstance(report["dns"], dict):
            raise ValueError("Неверная структура расширенного отчёта.")
        return "investigation"
    if all(key in report for key in ("ping", "dns", "https", "adapters")):
        if not isinstance(report["ping"], dict) or not isinstance(report["https"], dict):
            raise ValueError("Неверная структура базового отчёта.")
        return "basic"
    raise ValueError("Поддерживаются базовые отчёты NetScope и отчёты VPN / DNS / TCP.")


def _short(value: object, length: int = 160) -> str:
    return str(value or "—").replace("\n", " ").replace("\r", " ")[:length]


def describe(report: dict, kind: str) -> tuple[str, str]:
    if kind == "basic":
        ping, dns, https = report["ping"], report["dns"], report["https"]
        target = _short(ping.get("target"))
        status = "DNS: {} · HTTPS: {}".format(
            "OK" if dns.get("ok") else "FAIL", "OK" if https.get("ok") else "FAIL")
    else:
        tcp, dns = report["tcp"], report["dns"]
        target = _short("{}:{}".format(tcp.get("host", "—"), tcp.get("port", "—")))
        rows = dns.get("results", [])
        dns_ok = isinstance(rows, list) and bool(rows) and all(
            isinstance(r, dict) and r.get("ok") for r in rows)
        status = "DNS: {} · TCP: {}".format("OK" if dns_ok else "PARTIAL", "OK" if tcp.get("ok") else "FAIL")
    return target, status


class HistoryStore:
    """All operations use parameterized SQL. Small connections are closed promptly."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.path = Path(db_path) if db_path is not None else default_database_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as con:
            con.executescript("""
                CREATE TABLE IF NOT EXISTS diagnostic_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    captured_at TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('basic', 'investigation')),
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    report_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_reports_recent
                    ON diagnostic_reports(id DESC);
            """)
            con.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path), timeout=5.0)

    def add(self, report: dict) -> int:
        kind = report_type(report)
        payload = json.dumps(report, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(payload.encode("utf-8")) > MAX_REPORT_BYTES:
            raise ValueError("Отчёт слишком большой (максимум 2 МБ).")
        target, status = describe(report, kind)
        now = datetime.now(timezone.utc).isoformat()
        captured = _short(report.get("created_utc", now), 100)
        with closing(self._connect()) as con:
            with con:
                cursor = con.execute(
                    "INSERT INTO diagnostic_reports "
                    "(captured_at, stored_at, kind, target, status, report_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (captured, now, kind, target, status, payload),
                )
                return int(cursor.lastrowid)

    def list_recent(self, *, kind: str | None = None, limit: int = DEFAULT_LIST_LIMIT) -> list[HistoryEntry]:
        if kind not in (None, "basic", "investigation"):
            raise ValueError("Неизвестный тип отчёта.")
        if not 1 <= limit <= 1000:
            raise ValueError("Лимит истории должен быть от 1 до 1000.")
        query = ("SELECT id, captured_at, stored_at, kind, target, status "
                 "FROM diagnostic_reports")
        params: tuple = (limit,)
        if kind is not None:
            query += " WHERE kind = ?"
            params = (kind, limit)
        query += " ORDER BY id DESC LIMIT ?"
        with closing(self._connect()) as con:
            return [HistoryEntry(*row) for row in con.execute(query, params).fetchall()]

    def get(self, report_id: int) -> dict | None:
        if not isinstance(report_id, int) or isinstance(report_id, bool) or report_id < 1:
            raise ValueError("Недопустимый ID отчёта.")
        with closing(self._connect()) as con:
            row = con.execute("SELECT report_json FROM diagnostic_reports WHERE id = ?", (report_id,)).fetchone()
        if row is None:
            return None
        data = json.loads(row[0])
        report_type(data)
        return data

    def delete(self, report_id: int) -> bool:
        if not isinstance(report_id, int) or isinstance(report_id, bool) or report_id < 1:
            raise ValueError("Недопустимый ID отчёта.")
        with closing(self._connect()) as con:
            with con:
                result = con.execute("DELETE FROM diagnostic_reports WHERE id = ?", (report_id,))
                return result.rowcount == 1
