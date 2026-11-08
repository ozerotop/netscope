"""Offline auto-analysis: python -m netscope.analyze --input reports\\scan.json"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from .core.insights import analyze_report
from .core.report_diff import compare_reports

MAX_BYTES = 2_000_000


def load_report(path: Path) -> dict:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("JSON слишком большой (максимум 2 МБ).")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NetScope: offline rule-based analysis of advanced JSON reports")
    parser.add_argument("--input", type=Path, help="One v0.4+ investigation JSON")
    parser.add_argument("--before", type=Path, help="Report before changing connection")
    parser.add_argument("--after", type=Path, help="Report after changing connection")
    parser.add_argument("--json", type=Path, help="Optional path to save analysis JSON")
    args = parser.parse_args(argv)
    if bool(args.input) == bool(args.before or args.after) or (not args.input and not (args.before and args.after)):
        parser.error("Используйте --input ФАЙЛ либо оба параметра --before ФАЙЛ --after ФАЙЛ.")
    try:
        result = analyze_report(load_report(args.input)) if args.input else compare_reports(load_report(args.before), load_report(args.after))
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Ошибка чтения/анализа: {exc}", file=sys.stderr)
        return 2
    if args.input:
        for item in result["items"]:
            print(f"[{item['level']}] {item['title']} | уверенность в наблюдении: {item['confidence']}")
            print("  ", item["observation"])
            print("  ", item["explanation"])
            for action in item["actions"]:
                print("   •", action)
        print(result["disclaimer"])
    else:
        for change in result["changes"]:
            print(f"[{change['status']}] {change['topic']}: {change['description']}")
        for note in result["limitations"]:
            print("Ограничение:", note)
    if args.json:
        try:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc:
            print(f"Не удалось сохранить отчёт: {exc}", file=sys.stderr)
            return 2
        print(f"Анализ сохранён: {args.json}. Проверьте сетевые данные перед публикацией.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
