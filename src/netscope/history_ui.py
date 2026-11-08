"""Qt history browser for local SQLite scans (basic and advanced)."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget,
)

from .analyze import load_report
from .core.history import HistoryStore, report_type


class HistoryPanel(QWidget):
    analysis_requested = Signal(object)
    snapshot_requested = Signal(str, object)

    def __init__(self, store: HistoryStore | None, error: str = "") -> None:
        super().__init__()
        self.store = store
        self.current_id: int | None = None
        self.current_kind: str | None = None
        self._busy_refresh = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        top = QHBoxLayout()
        self.info = QLabel("Последние 200 отчётов. История хранится локально вне Git-репозитория.")
        self.info.setWordWrap(True)
        top.addWidget(self.info, 1)
        self.filter = QComboBox()
        self.filter.addItem("Все проверки", None)
        self.filter.addItem("Обычная диагностика", "basic")
        self.filter.addItem("VPN / DNS / TCP", "investigation")
        self.filter.currentIndexChanged.connect(self.refresh)
        top.addWidget(self.filter)
        refresh = QPushButton("Обновить")
        refresh.clicked.connect(self.refresh)
        top.addWidget(refresh)
        layout.addLayout(top)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Дата (UTC)", "Тип", "Адрес", "Результат", "ID"])
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self.selection_changed)
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setPlainText("Выберите отчёт, чтобы просмотреть его JSON.")
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.preview)
        splitter.setSizes([340, 240])
        layout.addWidget(splitter, 1)

        buttons = QHBoxLayout()
        self.open_analysis = QPushButton("В автоанализ")
        self.open_analysis.clicked.connect(self.send_to_analysis)
        self.before = QPushButton("В ДО")
        self.before.clicked.connect(lambda: self.send_snapshot("before"))
        self.after = QPushButton("В ПОСЛЕ")
        self.after.clicked.connect(lambda: self.send_snapshot("after"))
        self.import_button = QPushButton("Импорт JSON")
        self.import_button.clicked.connect(self.import_json)
        self.export_button = QPushButton("Экспорт JSON")
        self.export_button.clicked.connect(self.export_json)
        self.delete_button = QPushButton("Удалить запись")
        self.delete_button.clicked.connect(self.delete_selected)
        for btn in (self.open_analysis, self.before, self.after,
                    self.import_button, self.export_button, self.delete_button):
            buttons.addWidget(btn)
        layout.addLayout(buttons)
        self.privacy = QLabel("Локальная история содержит проверяемые адреса, внутренние IP и имена VPN-адаптеров. Не публикуйте базу данных или отчёты без проверки.")
        self.privacy.setWordWrap(True)
        self.privacy.setStyleSheet("color:#a4b7ca;font-size:9pt;")
        layout.addWidget(self.privacy)
        self.import_button.setEnabled(store is not None)
        if store is None:
            self.info.setText("История недоступна: " + error)
        self.refresh()

    def refresh(self) -> None:
        self._busy_refresh = True
        self.table.setRowCount(0)
        self.current_id = None
        self.current_kind = None
        try:
            entries = self.store.list_recent(kind=self.filter.currentData()) if self.store else []
            for entry in entries:
                row = self.table.rowCount()
                self.table.insertRow(row)
                fields = [entry.captured_at, "VPN / DNS / TCP" if entry.kind == "investigation" else "Обычная",
                          entry.target, entry.status, str(entry.id)]
                for col, field in enumerate(fields):
                    item = QTableWidgetItem(field)
                    if col == 0:
                        item.setData(Qt.ItemDataRole.UserRole, (entry.id, entry.kind))
                    self.table.setItem(row, col, item)
            if self.store:
                self.info.setText(f"Локальная история: {len(entries)} последних записей (максимум 200 в списке).")
        except (OSError, ValueError, sqlite3.Error) as exc:
            self.info.setText("Не удалось прочитать историю: " + str(exc))
        finally:
            self._busy_refresh = False
        self.preview.setPlainText("Выберите запись для просмотра.")
        self._toggle_actions()

    def _toggle_actions(self) -> None:
        selected = self.current_id is not None and self.store is not None
        for button in (self.export_button, self.delete_button):
            button.setEnabled(selected)
        advanced = selected and self.current_kind == "investigation"
        for button in (self.open_analysis, self.before, self.after):
            button.setEnabled(advanced)

    def selection_changed(self) -> None:
        if self._busy_refresh or self.store is None:
            return
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        record = item.data(Qt.ItemDataRole.UserRole) if item else None
        self.current_id, self.current_kind = record if record else (None, None)
        if self.current_id is not None:
            try:
                report = self.store.get(self.current_id)
                self.preview.setPlainText(json.dumps(report, ensure_ascii=False, indent=2)
                                          if report is not None else "Запись не найдена.")
            except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
                self.preview.setPlainText("Ошибка чтения: " + str(exc))
        self._toggle_actions()

    def _selected(self) -> dict | None:
        if self.store is None or self.current_id is None:
            return None
        try:
            return self.store.get(self.current_id)
        except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
            QMessageBox.warning(self, "Ошибка истории", str(exc))
            return None

    def record_report(self, report: dict) -> None:
        if self.store is None:
            return
        try:
            self.store.add(report)
            self.refresh()
        except (OSError, ValueError, sqlite3.Error) as exc:
            self.info.setText("Не удалось сохранить результат в историю: " + str(exc))

    def send_to_analysis(self) -> None:
        report = self._selected()
        if report is not None and report_type(report) == "investigation":
            self.analysis_requested.emit(report)

    def send_snapshot(self, name: str) -> None:
        report = self._selected()
        if report is not None and report_type(report) == "investigation":
            self.snapshot_requested.emit(name, report)

    def import_json(self) -> None:
        if self.store is None:
            return
        filename, _ = QFileDialog.getOpenFileName(self, "Импортировать отчёт", str(Path.home()), "JSON (*.json)")
        if not filename:
            return
        try:
            report = load_report(Path(filename))
            self.store.add(report)
            self.refresh()
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError, sqlite3.Error) as exc:
            QMessageBox.warning(self, "Ошибка импорта", str(exc))

    def export_json(self) -> None:
        report = self._selected()
        if report is None:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Экспортировать JSON", str(Path.home() / "netscope_report.json"), "JSON (*.json)")
        if not filename:
            return
        try:
            Path(filename).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        except (OSError, sqlite3.Error) as exc:
            QMessageBox.warning(self, "Ошибка экспорта", str(exc))

    def delete_selected(self) -> None:
        if self.current_id is None or self.store is None:
            return
        answer = QMessageBox.question(self, "Удалить запись?", "Удалить выбранный отчёт из локальной истории?",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                      QMessageBox.StandardButton.No)
        if answer == QMessageBox.StandardButton.Yes:
            try:
                self.store.delete(self.current_id)
                self.refresh()
            except (OSError, sqlite3.Error) as exc:
                QMessageBox.warning(self, "Ошибка удаления", str(exc))
