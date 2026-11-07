"""NetScope desktop: thin PySide6 client over the same diagnostic engine as CLI.

Start with ``python -m netscope.gui`` on Windows 11.
The GUI never changes routes, DNS, proxies, or VPN settings.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFrame, QGridLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPushButton, QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget,
)

from netscope import __version__
from netscope.core.diagnose import diagnose


STYLES = """
QMainWindow, QWidget { background: #111827; color: #e8edf7; font-family: 'Segoe UI'; font-size: 10pt; }
QLabel#logo { font-size: 23pt; font-weight: 750; color: #69e6ce; }
QLabel#tagline { color: #98a7ba; font-size: 10pt; }
QGroupBox { background: #182233; border: 1px solid #29374d; border-radius: 12px;
            margin-top: 13px; padding: 12px 10px 9px 10px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 7px; color: #dae5f5; }
QLineEdit { background: #101827; border: 1px solid #36475d; border-radius: 7px;
            padding: 8px 10px; selection-background-color: #2f8f88; }
QLineEdit:focus { border: 1px solid #69e6ce; }
QPushButton { background: #203046; border: 1px solid #3a4b63; border-radius: 7px;
              color: #e8edf7; padding: 9px 14px; font-weight: 600; }
QPushButton:hover { background: #2b3d55; }
QPushButton:disabled { color: #66788f; background: #1a2433; }
QPushButton#primary { background: #1e9d90; color: #071c20; border-color: #36b8a6; }
QPushButton#primary:hover { background: #52c7b3; }
QTabWidget::pane { border: 1px solid #2b3a50; border-radius: 8px; background: #141f2e; }
QTabBar::tab { background: #1c2a3b; color: #bbcadb; padding: 10px 15px;
               border: 1px solid #2b3a50; }
QTabBar::tab:selected { background: #2b4356; color: #72eed9; }
QTableWidget, QTextEdit { background: #141e2c; alternate-background-color: #19283a;
                          border: none; color: #e8edf7; padding: 6px; }
QHeaderView::section { background: #26394b; color: #d2def0; border: none; padding: 8px; }
QCheckBox { spacing: 7px; }
QStatusBar { background: #182333; color: #a5b3c7; }
"""


class ScanWorker(QThread):
    report_ready = Signal(object)
    failed = Signal(str)

    def __init__(self, target: str, domain: str, https_url: str, trace: bool) -> None:
        super().__init__()
        self.target = target
        self.domain = domain
        self.https_url = https_url
        self.trace = trace

    def run(self) -> None:
        try:
            report = diagnose(self.target, self.domain, self.https_url, self.trace)
        except Exception as exc:  # Keep errors in the UI instead of killing the thread.
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.report_ready.emit(report)


class SummaryCard(QFrame):
    def __init__(self, heading: str) -> None:
        super().__init__()
        self.setStyleSheet(
            "QFrame {background:#18283a;border:1px solid #2d4054;border-radius:11px;}"
            "QLabel {background:transparent;border:none;}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        self.heading = QLabel(heading)
        self.heading.setStyleSheet("color:#afbed1;font-size:10pt;")
        self.value = QLabel("—")
        self.value.setStyleSheet("color:#eff6ff;font-size:18pt;font-weight:700;")
        self.value.setWordWrap(True)
        layout.addWidget(self.heading)
        layout.addWidget(self.value)

    def set_value(self, value: str, ok: bool | None = None) -> None:
        color = "#eff6ff" if ok is None else ("#61dfbd" if ok else "#ff9b94")
        self.value.setText(value)
        self.value.setStyleSheet(f"color:{color};font-size:18pt;font-weight:700;")


class NetScopeWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"NetScope {__version__} | Windows 11 Network Diagnostics")
        self.resize(1140, 780)
        self.setMinimumSize(820, 620)
        self.report: dict | None = None
        self.worker: ScanWorker | None = None

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(24, 20, 24, 14)
        outer.setSpacing(14)

        top = QHBoxLayout()
        label = QLabel("NetScope")
        label.setObjectName("logo")
        subtitle = QLabel(f"v{__version__}  ·  Windows 11  ·  Read-only diagnostics")
        subtitle.setObjectName("tagline")
        top.addWidget(label)
        top.addSpacing(14)
        top.addWidget(subtitle)
        top.addStretch()
        outer.addLayout(top)

        config = QGroupBox("Параметры диагностики")
        config_layout = QGridLayout(config)
        config_layout.setHorizontalSpacing(13)
        config_layout.setVerticalSpacing(8)
        self.target = QLineEdit("1.1.1.1")
        self.domain = QLineEdit("www.python.org")
        self.https_url = QLineEdit("https://www.python.org/")
        for col, (name, field) in enumerate((
            ("PING / TRACERT", self.target), ("DNS-ДОМЕН", self.domain), ("HTTPS-URL", self.https_url)
        )):
            title = QLabel(name)
            title.setStyleSheet("color:#abbfd1;font-size:9pt;")
            config_layout.addWidget(title, 0, col)
            config_layout.addWidget(field, 1, col)
            config_layout.setColumnStretch(col, 1)
        self.trace = QCheckBox("Добавить tracert (медленнее)")
        self.start = QPushButton("Начать диагностику")
        self.start.setObjectName("primary")
        self.start.clicked.connect(self.start_scan)
        self.save = QPushButton("Сохранить JSON")
        self.save.setEnabled(False)
        self.save.clicked.connect(self.save_report)
        actions = QHBoxLayout()
        actions.addWidget(self.trace)
        actions.addStretch()
        actions.addWidget(self.save)
        actions.addWidget(self.start)
        config_layout.addLayout(actions, 2, 0, 1, 3)
        outer.addWidget(config)

        summary = QHBoxLayout()
        summary.setSpacing(12)
        self.cards = {
            "ping": SummaryCard("PING / ПОТЕРИ"),
            "dns": SummaryCard("DNS"),
            "https": SummaryCard("HTTPS / TLS"),
            "adapters": SummaryCard("АДАПТЕРЫ"),
        }
        for card in self.cards.values():
            summary.addWidget(card, 1)
        outer.addLayout(summary)

        self.tabs = QTabWidget()
        self.overview = QTextEdit()
        self.overview.setReadOnly(True)
        self.overview.setPlainText("Диагностика ещё не запущена. Нажмите «Начать диагностику».")
        self.tabs.addTab(self.overview, "Анализ")

        self.adapters_table = QTableWidget(0, 4)
        self.adapters_table.setHorizontalHeaderLabels(["Состояние", "Адаптер", "IPv4", "VPN (подозрение)"])
        self._setup_table(self.adapters_table)
        self.tabs.addTab(self.adapters_table, "Адаптеры")

        self.routes_table = QTableWidget(0, 3)
        self.routes_table.setHorizontalHeaderLabels(["Шлюз", "Интерфейс", "Метрика"])
        self._setup_table(self.routes_table)
        self.tabs.addTab(self.routes_table, "Маршруты")

        self.trace_output = QTextEdit()
        self.trace_output.setReadOnly(True)
        self.trace_output.setPlainText("Включите tracert перед запуском, чтобы увидеть результат.")
        self.tabs.addTab(self.trace_output, "Tracert")

        self.report_json = QTextEdit()
        self.report_json.setReadOnly(True)
        self.tabs.addTab(self.report_json, "JSON")
        outer.addWidget(self.tabs, 1)
        privacy = QLabel("NetScope ничего не меняет в сети. Отчёты могут содержать локальные IP-адреса и имена адаптеров.")
        privacy.setStyleSheet("color:#a5b3c7;font-size:9pt;")
        outer.addWidget(privacy)
        self.statusBar().showMessage("Готов к диагностике")

    @staticmethod
    def _setup_table(table: QTableWidget) -> None:
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False)

    @staticmethod
    def _row(table: QTableWidget, values: list[str]) -> None:
        r = table.rowCount()
        table.insertRow(r)
        for c, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            table.setItem(r, c, item)

    def start_scan(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        target, domain, url = self.target.text().strip(), self.domain.text().strip(), self.https_url.text().strip()
        if not target or not domain or not urlsplit(url).netloc or urlsplit(url).scheme.lower() != "https":
            QMessageBox.warning(self, "Неверные параметры", "Укажите ping-адрес, DNS-домен и HTTPS-URL.")
            return
        self.start.setEnabled(False)
        self.save.setEnabled(False)
        self.overview.setPlainText("Проверяем сеть… Сканирование выполняется в отдельном потоке.")
        self.statusBar().showMessage("Диагностика выполняется…")
        self.worker = ScanWorker(target, domain, url, self.trace.isChecked())
        self.worker.report_ready.connect(self.show_report)
        self.worker.failed.connect(self.scan_failed)
        self.worker.finished.connect(self.scan_finished)
        self.worker.start()

    def scan_finished(self) -> None:
        self.start.setEnabled(True)
        self.save.setEnabled(self.report is not None)
        if self.report is None:
            self.statusBar().showMessage("Диагностика завершилась с ошибкой")

    def scan_failed(self, message: str) -> None:
        self.report = None
        self.overview.setPlainText("Ошибка диагностики:\n" + message)
        self.statusBar().showMessage("Ошибка выполнения")

    def show_report(self, report: dict) -> None:
        self.report = report
        ping = report["ping"]
        self.cards["ping"].set_value(
            f"{ping['loss_percent']}% потерь",
            ping['received'] > 0 and ping['loss_percent'] == 0,
        )
        self.cards["dns"].set_value("OK" if report["dns"]["ok"] else "FAIL", report["dns"]["ok"])
        self.cards["https"].set_value("OK" if report["https"]["ok"] else "FAIL", report["https"]["ok"])
        self.cards["adapters"].set_value(str(len(report["adapters"])))
        win_https = report.get("https_windows")
        lines = [
            "РЕЗУЛЬТАТЫ ДИАГНОСТИКИ", "",
            f"PING {ping['target']}: {ping['received']}/{ping['sent']}, средний RTT: {ping['avg_ms']} мс, потери: {ping['loss_percent']}%",
            f"DNS: {report['dns']['detail']}",
            f"HTTPS (Python/OpenSSL): {report['https']['detail']}",
        ]
        if win_https:
            lines.append(f"HTTPS (Windows Schannel): {win_https['detail']}")
        lines.extend(["", "ВЫВОДЫ", *["• " + item for item in report["findings"]]])
        self.overview.setPlainText("\n".join(lines))
        self.adapters_table.setRowCount(0)
        for a in report["adapters"]:
            self._row(self.adapters_table, ["UP" if a["is_up"] else "DOWN", a["name"], ", ".join(a["ipv4"]) or "—", "Возможно" if a["vpn_candidate"] else "—"])
        self.routes_table.setRowCount(0)
        for route in report["default_routes"]:
            self._row(self.routes_table, [str(route["gateway"]), str(route["interface"]), str(route["metric"])])
        self.trace_output.setPlainText(report.get("trace", {}).get("output", "Tracert не был запущен."))
        self.report_json.setPlainText(json.dumps(report, indent=2, ensure_ascii=False))
        self.save.setEnabled(True)
        self.statusBar().showMessage("Диагностика завершена. Можно сохранить JSON-отчёт.")

    def save_report(self) -> None:
        if self.report is None:
            return
        suggested = str(Path.cwd() / "reports" / "netscope_report.json")
        filename, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", suggested, "JSON files (*.json)")
        if not filename:
            return
        try:
            path = Path(filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self.report, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Ошибка сохранения", str(exc))
            return
        self.statusBar().showMessage(f"Отчёт сохранён: {path}")


def main() -> int:
    if os.name != "nt":
        print("NetScope GUI currently supports Windows 11 only.", file=sys.stderr)
        return 2
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLES)
    window = NetScopeWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
