"""Wspólne funkcje dla skryptów analizy pliku time,user,computer."""

import argparse
import csv
from pathlib import Path

ANALYSIS_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT = ANALYSIS_DIR / "data" / "lanl_auth_modified_1.csv"
RESULTS_DIR = ANALYSIS_DIR / "results"


def read_events(path):
    """Zwraca kolejne zdarzenia jako (time, user, computer). Pomija nagłówek."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) != 3 or not row[0].isdigit():
                continue
            yield int(row[0]), row[1], row[2]


def make_parser(description):
    """Parser argumentów z opcjami wspólnymi dla wszystkich skryptów."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("input", nargs="?", default=DEFAULT_INPUT, help="plik CSV time,user,computer")
    parser.add_argument("--top", type=int, default=15, help="ile wyników wypisać")
    return parser


def fmt_time(t):
    """Sekundy od początku zbioru -> 'dD HH:MM:SS'."""
    day, rest = divmod(t, 86400)
    hour, rest = divmod(rest, 3600)
    minute, second = divmod(rest, 60)
    return f"d{day} {hour:02d}:{minute:02d}:{second:02d}"


def median(values):
    values = sorted(values)
    if not values:
        return 0
    mid = len(values) // 2
    if len(values) % 2:
        return values[mid]
    return (values[mid - 1] + values[mid]) / 2


def print_table(headers, rows):
    """Wypisuje prostą tabelę tekstową."""
    rows = [[str(value) for value in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(value))
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(v.ljust(w) for v, w in zip(row, widths)))


def save_csv(name, headers, rows):
    """Zapisuje wyniki do analysis/results/<name>."""
    RESULTS_DIR.mkdir(exist_ok=True)
    path = RESULTS_DIR / name
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"\nZapisano: {path}")
