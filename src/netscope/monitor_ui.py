"""Qt live monitoring tab: three parallel ICMP targets, history and a live chart."""
from __future__ import annotations

import math
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

from PySide6.QtCore import QPointF, QRectF, Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMessageBox, QPushButton, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from netscope.core.monitor import MonitorSession, ProbeSample, parse_targets, probe_target

COLORS = ("#5fe1c1", "#82b9ff", "#ffcb79")


def latency_str(value: float | None) -> str:
    return "—" if value is None else f"{value:.1f}"


class MonitorWorker(QThread):
    sample_ready = Signal(object)
    error = Signal(str)

    def __init__(self, targets: list[str], interval_seconds: float = 1.0) -> None:
        super().__init__()
        self.targets = targets
        self.interval_seconds = interval_seconds
        self._stop = Event()

    def request_stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            with ThreadPoolExecutor(max_workers=len(self.targets), thread_name_prefix="netscope-ping") as pool:
                cycle = 0
                while not self._stop.is_set():
                    started = time.monotonic()
                    cycle += 1
                    # All probes in one cycle run concurrently, not sequentially.
                    samples = list(pool.map(lambda host: probe_target(host, cycle), self.targets))
                    if self._stop.is_set():
                        break
                    for sample in samples:
                        self.sample_ready.emit(sample)
                    # If probes take >1 second, the next cycle starts immediately.
                    self._stop.wait(max(0.0, self.interval_seconds - (time.monotonic() - started)))
        except Exception as exc:
            self.error.emit(f"{type(exc).__name__}: {exc}")


class LatencyChart(QWidget):
    """Pure Qt painter chart; no additional plotting library required."""

    def __init__(self) -> None:
        super().__init__()
        self.session: MonitorSession | None = None
        self.setMinimumHeight(245)

    def set_session(self, session: MonitorSession) -> None:
        self.session = session
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#141e2c"))
        painter.setPen(QColor("#b7c7dd"))
        painter.setFont(QFont("Segoe UI", 10))

        width, height = self.width(), self.height()
        left, right, top, bottom = 64, 22, 30, 37
        graph_w, graph_h = width - left - right, height - top - bottom
        if graph_w <= 30 or graph_h <= 30:
            return
        all_samples = []
        if self.session:
            for host in self.session.targets:
                all_samples.extend(list(self.session.history[host])[-120:])

        last_cycle = max((s.cycle for s in all_samples), default=1)
        first_cycle = max(1, last_cycle - 119)
        visible = [s for s in all_samples if s.cycle >= first_cycle]
        max_rtt = max((s.rtt_ms for s in visible if s.rtt_ms is not None), default=0)
        max_y = max(20, math.ceil((max_rtt * 1.18) / 10) * 10)

        # Chart grid and axes (RTT is NOT zero on a lost packet).
        grid_pen = QPen(QColor("#2b3c51"), 1)
        painter.setPen(grid_pen)
        for i in range(5):
            y = top + graph_h * i / 4
            painter.drawLine(QPointF(left, y), QPointF(left + graph_w, y))
            painter.setPen(QColor("#a2b4cc"))
            painter.drawText(QRectF(3, y - 10, left - 12, 20),
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                             f"{max_y * (4-i)/4:.0f}")
            painter.setPen(grid_pen)
        painter.setPen(QColor("#9eb3c9"))
        painter.drawText(8, 17, "мс")
        painter.drawText(QRectF(left, top + graph_h + 10, graph_w, 25),
                         Qt.AlignmentFlag.AlignCenter, "Последние 120 циклов · пропуски = нет ответа ICMP")

        if not visible or not self.session:
            painter.drawText(QRectF(left, top, graph_w, graph_h),
                             Qt.AlignmentFlag.AlignCenter,
                             "Нажмите «Старт мониторинга», чтобы увидеть график")
            return

        # All hosts share the same X coordinate per monitoring cycle.
        def xy(sample: ProbeSample) -> QPointF:
            x = left + graph_w * (sample.cycle - first_cycle) / 119
            y = top + graph_h * (1 - (sample.rtt_ms or 0) / max_y)
            return QPointF(x, y)

        for idx, host in enumerate(self.session.targets):
            color = QColor(COLORS[idx % len(COLORS)])
            samples = [s for s in self.session.history[host] if s.cycle >= first_cycle]
            painter.setPen(QPen(color, 2))
            last_point: QPointF | None = None
            last_sample_cycle: int | None = None
            for sample in samples:
                if sample.received and sample.rtt_ms is not None:
                    p = xy(sample)
                    if last_point is not None and last_sample_cycle == sample.cycle - 1:
                        painter.drawLine(last_point, p)
                    painter.setBrush(color)
                    painter.drawEllipse(p, 2.4, 2.4)
                    last_point = p
                    last_sample_cycle = sample.cycle
                else:
                    x = left + graph_w * (sample.cycle - first_cycle) / 119
                    y = top + graph_h - 6
                    painter.setPen(QPen(QColor("#ff8282"), 2))
                    painter.drawLine(QPointF(x - 4, y - 4), QPointF(x + 4, y + 4))
                    painter.drawLine(QPointF(x - 4, y + 4), QPointF(x + 4, y - 4))
                    painter.setPen(QPen(color, 2))
                    last_point = None
                    last_sample_cycle = None

        # Legend across the upper right side.
        painter.setFont(QFont("Segoe UI", 9))
        legend_x = left + 10
        for idx, host in enumerate(self.session.targets):
            painter.setPen(QColor(COLORS[idx % len(COLORS)]))
            painter.drawText(legend_x, top - 12, host)
            legend_x += painter.fontMetrics().horizontalAdvance(host) + 26


class MonitorPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.worker: MonitorWorker | None = None
        self.session: MonitorSession | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("IPv4 / домены:"))
        self.hosts_input = QLineEdit("1.1.1.1, 8.8.8.8, www.python.org")
        self.hosts_input.setPlaceholderText("До 3 адресов через запятую")
        controls.addWidget(self.hosts_input, 1)
        self.start_button = QPushButton("Старт мониторинга")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self.start_monitor)
        controls.addWidget(self.start_button)
        self.stop_button = QPushButton("Стоп")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_monitor)
        controls.addWidget(self.stop_button)
        self.save_button = QPushButton("Экспорт CSV")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_csv)
        controls.addWidget(self.save_button)
        layout.addLayout(controls)

        self.message = QLabel("Интервал: не чаще раза в секунду на адрес; при задержках может быть дольше.")
        self.message.setStyleSheet("color:#a8bbd1;")
        layout.addWidget(self.message)

        self.chart = LatencyChart()
        layout.addWidget(self.chart, 1)

        self.stats = QTableWidget(0, 7)
        self.stats.setHorizontalHeaderLabels(["Хост", "Последний, мс", "Отправлено", "Потери", "Мин, мс", "Сред, мс", "Макс, мс"])
        self.stats.setAlternatingRowColors(True)
        self.stats.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.stats.verticalHeader().setVisible(False)
        self.stats.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.stats.setMinimumHeight(125)
        self.stats.setMaximumHeight(190)
        layout.addWidget(self.stats)
        privacy = QLabel("ICMP может блокироваться, а VPN может изменять маршрут. История хранится в памяти: до 10 000 проб на адрес.")
        privacy.setWordWrap(True)
        privacy.setStyleSheet("color:#a8bbd1;font-size:9pt;")
        layout.addWidget(privacy)

    def start_monitor(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        try:
            targets = parse_targets(self.hosts_input.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Некорректные адреса", str(exc))
            return
        self.session = MonitorSession(targets)
        self.chart.set_session(self.session)
        self.stats.setRowCount(len(targets))
        for idx, host in enumerate(targets):
            for col, value in enumerate([host, "—", "0", "0.0%", "—", "—", "—"]):
                self.stats.setItem(idx, col, QTableWidgetItem(value))
        self.hosts_input.setEnabled(False)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.save_button.setEnabled(False)
        self.message.setText("Мониторинг запущен · ICMP · 1 проба/цикл на адрес")
        self.worker = MonitorWorker(targets)
        self.worker.sample_ready.connect(self.on_sample)
        self.worker.error.connect(self.on_error)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

    def on_sample(self, sample: ProbeSample) -> None:
        if self.session is None:
            return
        self.session.add(sample)
        row = self.session.targets.index(sample.target)
        data = self.session.summary(sample.target)
        values = [
            sample.target,
            latency_str(data["last_rtt_ms"]) if data["last_received"] else "Нет ответа",
            str(data["sent"]),
            f"{data['loss_percent']:.1f}%",
            latency_str(data["min_ms"]), latency_str(data["avg_ms"]), latency_str(data["max_ms"]),
        ]
        for col, val in enumerate(values):
            self.stats.item(row, col).setText(val)
        self.chart.update()
        self.save_button.setEnabled(True)

    def stop_monitor(self) -> None:
        if self.worker and self.worker.isRunning():
            self.worker.request_stop()
            self.stop_button.setEnabled(False)
            self.message.setText("Останавливаем мониторинг после текущей пробы…")

    def on_finished(self) -> None:
        self.hosts_input.setEnabled(True)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.save_button.setEnabled(bool(self.session and any(self.session.history.values())))
        if not self.message.text().startswith("Ошибка"):
            self.message.setText("Мониторинг остановлен. Можно сохранить CSV или начать новую сессию.")

    def on_error(self, description: str) -> None:
        self.message.setText("Ошибка мониторинга: " + description)

    def save_csv(self) -> None:
        if self.session is None:
            return
        suggested = str(Path.cwd() / "reports" / "netscope_monitor.csv")
        filename, _ = QFileDialog.getSaveFileName(self, "Сохранить историю мониторинга", suggested, "CSV (*.csv)")
        if not filename:
            return
        try:
            path = Path(filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            self.session.export_csv(path)
        except OSError as exc:
            QMessageBox.critical(self, "Ошибка сохранения CSV", str(exc))
        else:
            self.message.setText(f"История сохранена: {path}")
