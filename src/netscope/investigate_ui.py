"""NetScope advanced read-only VPN/DNS/route/TCP investigation tab."""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QFileDialog, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMessageBox, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem,
    QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)

from netscope.core.investigate import investigate


class InvestigationWorker(QThread):
    ready = Signal(object)
    failed = Signal(str)

    def __init__(self, domain: str, servers: str, ip: str, tcp_host: str, tcp_port: int) -> None:
        super().__init__()
        self.args = (domain, servers, ip, tcp_host, tcp_port)

    def run(self) -> None:
        try:
            result = investigate(*self.args)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.ready.emit(result)


def make_table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setAlternatingRowColors(True)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    return table


def populate(table: QTableWidget, rows: list[list[str]]) -> None:
    table.setRowCount(len(rows))
    for r, values in enumerate(rows):
        for c, value in enumerate(values):
            table.setItem(r, c, QTableWidgetItem(str(value)))


class InvestigationPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.worker: InvestigationWorker | None = None
        self.report: dict | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(9)

        inputs = QGridLayout()
        self.domain = QLineEdit("www.python.org")
        self.domain.setPlaceholderText("Домен для A-записей")
        self.servers = QLineEdit("1.1.1.1, 8.8.8.8")
        self.servers.setPlaceholderText("До 3 DNS IPv4-адресов")
        self.ip = QLineEdit("1.1.1.1")
        self.ip.setPlaceholderText("IPv4-адрес для выбора маршрута")
        self.tcp_host = QLineEdit("www.python.org")
        self.tcp_port = QSpinBox()
        self.tcp_port.setRange(1, 65535)
        self.tcp_port.setValue(443)
        self.tcp_port.setMinimumWidth(85)
        controls = [("DNS-домен", self.domain), ("DNS-серверы (UDP/53)", self.servers),
                    ("Адрес для маршрута", self.ip), ("TCP-хост", self.tcp_host),
                    ("TCP-порт", self.tcp_port)]
        for i, (label, widget) in enumerate(controls):
            inputs.addWidget(QLabel(label), 0, i)
            inputs.addWidget(widget, 1, i)
            inputs.setColumnStretch(i, 1 if i != 4 else 0)
        layout.addLayout(inputs)

        bar = QHBoxLayout()
        self.info = QLabel("Проверки только читают настройки. DNS UDP/53 не шифруется и может перенаправляться VPN.")
        self.info.setWordWrap(True)
        self.info.setStyleSheet("color:#a4b7ca;")
        bar.addWidget(self.info, 1)
        self.export_button = QPushButton("Сохранить JSON")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_json)
        bar.addWidget(self.export_button)
        self.start_button = QPushButton("Проверить VPN / DNS / TCP")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self.start_investigation)
        bar.addWidget(self.start_button)
        layout.addLayout(bar)

        self.tabs = QTabWidget()
        self.summary = QTextEdit()
        self.summary.setReadOnly(True)
        self.summary.setPlainText("Нажмите «Проверить VPN / DNS / TCP». Это не меняет настройки сети.")
        self.tabs.addTab(self.summary, "Выводы")

        self.dns_table = make_table(["Резолвер", "Результат", "A-записи", "Время, мс", "Примечание"])
        self.tabs.addTab(self.dns_table, "Сравнение DNS")
        self.route_table = make_table(["Сеть / маска", "Шлюз", "Интерфейс IPv4", "Метрика", "Оценка"])
        self.tabs.addTab(self.route_table, "Выбор маршрута")
        self.adapter_table = make_table(["Адаптер", "Состояние", "IPv4", "VPN по названию"])
        self.tabs.addTab(self.adapter_table, "VPN-адаптеры")
        self.tcp_result = QTextEdit()
        self.tcp_result.setReadOnly(True)
        self.tabs.addTab(self.tcp_result, "TCP")
        layout.addWidget(self.tabs, 1)

        footnote = QLabel("Важно: разные DNS-ответы ≠ доказательство подмены. TCP:443 ≠ проверка игровых UDP-соединений. Маршрут — оценка по таблице Windows.")
        footnote.setWordWrap(True)
        footnote.setStyleSheet("color:#a4b7ca;font-size:9pt;")
        layout.addWidget(footnote)

    def start_investigation(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        try:
            from netscope.core.dns_compare import parse_dns_servers
            from netscope.core.monitor import validate_target
            from ipaddress import IPv4Address
            parse_dns_servers(self.servers.text())
            validate_target(self.domain.text())
            validate_target(self.tcp_host.text())
            IPv4Address(self.ip.text().strip())
        except ValueError as exc:
            QMessageBox.warning(self, "Неверные параметры", str(exc))
            return
        self.start_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.info.setText("Проверяем DNS, маршрутизацию, адаптеры и TCP…")
        self.summary.setPlainText("Диагностика выполняется в отдельном потоке…")
        self.worker = InvestigationWorker(self.domain.text().strip(), self.servers.text().strip(),
                                          self.ip.text().strip(), self.tcp_host.text().strip(),
                                          self.tcp_port.value())
        self.worker.ready.connect(self.show_report)
        self.worker.failed.connect(self.show_error)
        self.worker.finished.connect(self.scan_finished)
        self.worker.start()

    def show_error(self, message: str) -> None:
        self.report = None
        self.summary.setPlainText("Ошибка диагностики: " + message)
        self.info.setText("Ошибка. Проверьте параметры и повторите.")

    def scan_finished(self) -> None:
        self.start_button.setEnabled(True)
        self.export_button.setEnabled(self.report is not None)

    def show_report(self, report: dict) -> None:
        self.report = report
        self.summary.setPlainText("РЕЗУЛЬТАТЫ РАСШИРЕННОЙ ДИАГНОСТИКИ\n\n" + "\n\n".join("• " + f for f in report["findings"]))
        populate(self.dns_table, [[r["server"], "OK" if r["ok"] else "Нет ответа / ошибка",
                                   ", ".join(r["ipv4"]) or "—", str(r["duration_ms"]), r["detail"]]
                                  for r in report["dns"]["results"]])
        route = report["route"]
        populate(self.route_table,
                 [[r["network"], r["gateway"], r["interface"], str(r["metric"]),
                   ("Вероятный" if i == 0 else "Альтернатива") + (" (равная метрика)" if route["ambiguous"] and i < 2 else "")]
                  for i, r in enumerate(route["matches"])])
        populate(self.adapter_table, [[a["name"], "UP" if a["is_up"] else "DOWN",
                                       ", ".join(a["ipv4"]) or "—", "Возможно" if a["vpn_candidate"] else "—"]
                                      for a in report["adapters"]])
        tcp = report["tcp"]
        self.tcp_result.setPlainText(f"TCP {tcp['host']}:{tcp['port']}\n"
                                     f"Статус: {'Подключился' if tcp['ok'] else 'Не подключился'}\n"
                                     f"IP: {tcp['ip'] or '—'}\n"
                                     f"Время: {tcp['duration_ms']} мс\n\n{tcp['detail']}\n\n"
                                     "Это не проверка UDP, игрового протокола, голосового чата или логина.")
        self.export_button.setEnabled(True)
        self.info.setText("Диагностика завершена. Результаты доступны на вкладках.")

    def export_json(self) -> None:
        if self.report is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить подробный отчёт",
                                               str(Path.cwd() / "reports" / "netscope_investigation.json"),
                                               "JSON (*.json)")
        if not path:
            return
        try:
            file = Path(path)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(json.dumps(self.report, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Ошибка сохранения", str(exc))
        else:
            self.info.setText("Отчёт сохранён. Проверьте личные сетевые данные перед отправкой другим.")
