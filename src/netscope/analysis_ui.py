"""Rule-based, offline diagnostic explanation and before/after comparisons."""
from __future__ import annotations

from html import escape
from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton,
    QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from .analyze import load_report
from .core.insights import analyze_report, validate_investigation
from .core.report_diff import compare_reports

_COLORS = {"warning": "#ffbe75", "ok": "#69e6ce", "info": "#a1caff",
           "changed": "#ffbe75", "same": "#69e6ce", "not_comparable": "#a1caff"}
_CONFIDENCE = {"high": "высокая", "medium": "средняя", "low": "низкая"}


def _p(value: object) -> str:
    return escape(str(value))


def _heading(label: str, color: str) -> str:
    return f'<h3 style="color:{color};margin-bottom:4px">{_p(label)}</h3>'


def render_analysis(data: dict) -> str:
    parts = ['<div style="color:#e8edf7;font-family:Segoe UI,Arial;">',
             '<h2>Автоматический разбор результатов</h2>',
             '<p>Правила проверяют только содержимое отчёта. Они не устанавливают причину с полной уверенностью.</p>']
    for item in data["items"]:
        color = _COLORS[item["level"]]
        parts.append(_heading(item["title"], color))
        parts.append(f'<p style="color:#a4b7ca;margin:2px 0">Уверенность в наблюдении: '
                     f'{_p(_CONFIDENCE.get(item["confidence"], item["confidence"]))}</p>')
        parts.append(f'<p><b>Наблюдение:</b> {_p(item["observation"])}<br>'
                     f'<b>Что это может означать:</b> {_p(item["explanation"])}</p>')
        if item["actions"]:
            parts.append('<ul>' + ''.join(f'<li>{_p(action)}</li>' for action in item["actions"]) + '</ul>')
    parts.append(f'<hr><p style="color:#a4b7ca">{_p(data["disclaimer"])}</p></div>')
    return ''.join(parts)


def render_comparison(data: dict) -> str:
    parts = ['<div style="color:#e8edf7;font-family:Segoe UI,Arial;">',
             f'<h2>Сравнение «До / После»</h2><p>Обнаружено отличий: {data["changed_count"]}</p>']
    for change in data["changes"]:
        parts.append(_heading(change["topic"] + ' — ' +
                              {"changed": "изменилось", "same": "без изменений", "not_comparable": "несопоставимо"}[change["status"]],
                              _COLORS[change["status"]]))
        parts.append(f'<p>{_p(change["description"])}</p>')
    for note in data["limitations"]:
        parts.append(f'<p style="color:#a4b7ca">{_p(note)}</p>')
    return ''.join(parts) + '</div>'


class AnalysisPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.latest: dict | None = None
        self.before: dict | None = None
        self.after: dict | None = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(10)

        intro = QLabel("Разбор выполняется локально, без интернета и без изменения настроек Windows. "
                       "Сначала запустите «VPN / DNS / TCP» или импортируйте отчёт JSON.")
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#a4b7ca;")
        outer.addWidget(intro)

        top = QHBoxLayout()
        self.latest_label = QLabel("Текущий отчёт: не выбран")
        top.addWidget(self.latest_label, 1)
        load_current = QPushButton("Открыть JSON")
        load_current.clicked.connect(self.load_current)
        top.addWidget(load_current)
        outer.addLayout(top)

        actions = QHBoxLayout()
        self.before_label = QLabel("ДО: —")
        self.after_label = QLabel("ПОСЛЕ: —")
        before_current = QPushButton("Текущий → ДО")
        before_current.clicked.connect(lambda: self.capture("before"))
        after_current = QPushButton("Текущий → ПОСЛЕ")
        after_current.clicked.connect(lambda: self.capture("after"))
        before_file = QPushButton("Открыть ДО")
        before_file.clicked.connect(lambda: self.load_snapshot("before"))
        after_file = QPushButton("Открыть ПОСЛЕ")
        after_file.clicked.connect(lambda: self.load_snapshot("after"))
        compare = QPushButton("Сравнить")
        compare.setObjectName("primary")
        compare.clicked.connect(self.show_diff)
        for widget in (before_current, before_file, after_current, after_file, compare):
            actions.addWidget(widget)
        outer.addLayout(actions)
        labels = QHBoxLayout()
        labels.addWidget(self.before_label, 1)
        labels.addWidget(self.after_label, 1)
        outer.addLayout(labels)

        self.tabs = QTabWidget()
        self.analysis_view = QTextBrowser()
        self.analysis_view.setOpenExternalLinks(False)
        self.analysis_view.setHtml("<p>Пока нет результатов. Выполните VPN / DNS / TCP диагностику.</p>")
        self.tabs.addTab(self.analysis_view, "Выводы и рекомендации")
        self.diff_view = QTextBrowser()
        self.diff_view.setOpenExternalLinks(False)
        self.diff_view.setHtml("<p>Сохраните снимки «ДО» и «ПОСЛЕ», затем нажмите «Сравнить».</p>")
        self.tabs.addTab(self.diff_view, "Сравнение")
        outer.addWidget(self.tabs, 1)
        note = QLabel("Не публикуйте отчёты без проверки: они содержат имена адаптеров, IP и проверяемые адреса.")
        note.setWordWrap(True)
        note.setStyleSheet("color:#a4b7ca;font-size:9pt;")
        outer.addWidget(note)

    def set_latest_report(self, report: dict) -> None:
        try:
            data = analyze_report(report)
        except ValueError as exc:
            QMessageBox.warning(self, "Неподдерживаемый отчёт", str(exc))
            return
        self.latest = report
        self.latest_label.setText("Текущий отчёт: " + str(report.get("created_utc", "в памяти")))
        self.analysis_view.setHtml(render_analysis(data))
        self.tabs.setCurrentIndex(0)

    def _choose_report(self) -> dict | None:
        filename, _ = QFileDialog.getOpenFileName(self, "Выбрать расширенный отчёт NetScope", str(Path.cwd() / "reports"), "JSON (*.json)")
        if not filename:
            return None
        try:
            report = load_report(Path(filename))
            validate_investigation(report)
            return report
        except (OSError, ValueError, UnicodeError) as exc:
            QMessageBox.warning(self, "Невозможно открыть отчёт", str(exc))
            return None

    def load_current(self) -> None:
        data = self._choose_report()
        if data is not None:
            self.set_latest_report(data)

    def capture(self, target: str) -> None:
        if self.latest is None:
            QMessageBox.information(self, "Нет отчёта", "Сначала выполните расширенную диагностику или откройте JSON.")
            return
        self._set_snapshot(target, self.latest)

    def load_snapshot(self, target: str) -> None:
        data = self._choose_report()
        if data is not None:
            self._set_snapshot(target, data)

    def _set_snapshot(self, target: str, data: dict) -> None:
        label = str(data.get("created_utc", "время неизвестно"))
        if target == "before":
            self.before = data
            self.before_label.setText("ДО: " + label)
        else:
            self.after = data
            self.after_label.setText("ПОСЛЕ: " + label)
        self.diff_view.setPlainText("Снимки обновлены. Нажмите «Сравнить».")

    def show_diff(self) -> None:
        if self.before is None or self.after is None:
            QMessageBox.information(self, "Недостаточно данных", "Нужны оба снимка: «ДО» и «ПОСЛЕ».")
            return
        try:
            result = compare_reports(self.before, self.after)
        except ValueError as exc:
            QMessageBox.warning(self, "Ошибка сравнения", str(exc))
            return
        self.diff_view.setHtml(render_comparison(result))
        self.tabs.setCurrentIndex(1)
