#!/usr/bin/env python3
"""Analyze LANL authentication events and produce a Markdown report.

The script uses only the Python standard library so it can be run on the
provided sample without installing additional packages.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO


FIELD_NAMES = (
    "time",
    "source_user",
    "destination_user",
    "source_computer",
    "destination_computer",
    "authentication_type",
    "logon_type",
    "orientation",
    "result",
)
HUMAN_USER = re.compile(r"^U\d+@")
FAILURE_VALUES = {"Fail", "Failure"}


@dataclass(frozen=True)
class Event:
    time: int
    source_user: str
    destination_user: str
    source_computer: str
    destination_computer: str
    authentication_type: str
    logon_type: str
    orientation: str
    result: str


@dataclass
class Analysis:
    event_count: int = 0
    invalid_count: int = 0
    result_counts: Counter[str] = field(default_factory=Counter)
    auth_counts: Counter[str] = field(default_factory=Counter)
    logon_counts: Counter[str] = field(default_factory=Counter)
    user_counts: Counter[str] = field(default_factory=Counter)
    destination_counts: Counter[str] = field(default_factory=Counter)
    lateral_pairs: Counter[tuple[str, str]] = field(default_factory=Counter)
    lateral_users: set[str] = field(default_factory=set)
    lateral_destinations: set[str] = field(default_factory=set)
    failed_users: Counter[str] = field(default_factory=Counter)
    failed_sources: Counter[str] = field(default_factory=Counter)
    minimum_time: int | None = None
    maximum_time: int | None = None

    def add(self, event: Event) -> None:
        self.event_count += 1
        self.result_counts[event.result] += 1
        self.auth_counts[event.authentication_type] += 1
        self.logon_counts[event.logon_type] += 1
        self.destination_counts[event.destination_computer] += 1
        self.minimum_time = (
            event.time if self.minimum_time is None else min(self.minimum_time, event.time)
        )
        self.maximum_time = (
            event.time if self.maximum_time is None else max(self.maximum_time, event.time)
        )

        principal = human_principal(event)
        if principal is not None:
            self.user_counts[principal] += 1
            if is_failure(event.result):
                self.failed_users[principal] += 1
        if is_failure(event.result):
            self.failed_sources[event.source_computer] += 1
        if (
            principal is not None
            and event.source_computer != event.destination_computer
            and event.result == "Success"
        ):
            self.lateral_pairs[(principal, event.destination_computer)] += 1
            self.lateral_users.add(principal)
            self.lateral_destinations.add(event.destination_computer)


def open_input(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, mode="rt", newline="", encoding="utf-8")
    return path.open(newline="", encoding="utf-8")


def analyze_file(
    path: Path,
    *,
    max_events: int | None = None,
    start_time: int | None = None,
    end_time: int | None = None,
) -> Analysis:
    analysis = Analysis()
    with open_input(path) as handle:
        reader = csv.reader(handle)
        for line_number, row in enumerate(reader, start=1):
            if not row or all(not value.strip() for value in row):
                continue
            if len(row) != len(FIELD_NAMES):
                analysis.invalid_count += 1
                continue
            try:
                event = Event(int(row[0]), *row[1:])
            except ValueError:
                analysis.invalid_count += 1
                continue
            if start_time is not None and event.time < start_time:
                continue
            if end_time is not None and event.time > end_time:
                continue
            analysis.add(event)
            if max_events is not None and analysis.event_count >= max_events:
                break
    if analysis.event_count == 0:
        raise ValueError(f"{path}: no valid events found")
    return analysis


def human_principal(event: Event) -> str | None:
    for candidate in (event.source_user, event.destination_user):
        if HUMAN_USER.match(candidate):
            return candidate
    return None


def is_failure(result: str) -> bool:
    return result in FAILURE_VALUES


def human_lateral_events(
    pairs: Counter[tuple[str, str]],
) -> list[tuple[str, str, str, int]]:
    """Return human-account logons to other computers, ranked by frequency."""
    return [
        (user, computer, "success", count)
        for (user, computer), count in pairs.most_common()
    ]


def make_report(analysis: Analysis, input_path: Path) -> str:
    lateral = human_lateral_events(analysis.lateral_pairs)
    duration = analysis.maximum_time - analysis.minimum_time
    repeated_destinations = sum(
        1 for count in analysis.destination_counts.values() if count > 1
    )

    lines = [
        "# Authentication Event Analysis",
        "",
        f"Source: `{input_path}`.",
        "",
        "## 1. Data Scope and Quality",
        "",
        f"- Number of valid events: **{analysis.event_count}**.",
        f"- Time range: **{analysis.minimum_time}–{analysis.maximum_time}** "
        f"(span: {duration} s).",
        f"- Unique user accounts (`U...@...`): **{len(analysis.user_counts)}**.",
        f"- Unique destination computers: **{len(analysis.destination_counts)}**.",
        f"- User-account events (`U...@...`): **{sum(analysis.user_counts.values())}** "
        f"({len(analysis.user_counts)} accounts, {len(analysis.lateral_destinations)} destination "
        "computer(s)).",
        f"- Successful events: **{analysis.result_counts['Success']}**; "
        f"failures: **{sum(analysis.result_counts[value] for value in FAILURE_VALUES)}**.",
        f"- Invalid records skipped: **{analysis.invalid_count}**.",
        "",
        "The selected fragment may not represent the full time range. "
        "Time-series conclusions should therefore be treated as local to this "
        "fragment and validated against a longer baseline.",
        "",
        "## 2. Descriptive Statistics",
        "",
        "| Feature | Distribution |",
        "|---|---|",
        f"| Authentication type | {format_counter(analysis.auth_counts)} |",
        f"| Logon type | {format_counter(analysis.logon_counts)} |",
        f"| Result | {format_counter(analysis.result_counts)} |",
        "",
        f"Repeated destination computers: **{repeated_destinations}**. "
        "Most frequent destinations:",
        "",
        "| Computer | Events |",
        "|---|---:|",
    ]
    lines.extend(
        f"| `{computer}` | {count} |"
        for computer, count in analysis.destination_counts.most_common(10)
    )

    lines.extend(
        [
            "",
            "## 3. Detected Anomalies",
            "",
            "Successful user-account logons (`U...@...`, regardless of the "
            "column) from one computer to another are treated as potentially "
            "suspicious. Service accounts and computer accounts (`C...$`) are "
            "excluded because they are common operational noise in LANL data.",
            "",
            f"- Potential lateral-movement records detected: **{len(lateral)}**.",
            f"- Affected user accounts: **{len(analysis.lateral_users)}**; "
            f"destination computers: **{len(analysis.lateral_destinations)}**.",
            "",
            "| User | Destination computer | Result | Count |",
            "|---|---|---|---:|",
        ]
    )
    lines.extend(f"| `{user}` | `{computer}` | {result} | {count} |" for user, computer, result, count in lateral[:15])

    suspicious = sum(analysis.lateral_pairs.values())
    failed_attempts = sum(analysis.failed_users.values())
    lines.extend(
        [
            "",
            "### Failed-login indicators",
            "",
            f"- Failed authentication events: **{sum(analysis.result_counts[value] for value in FAILURE_VALUES)}**.",
            f"- Failed events involving user accounts: **{failed_attempts}**.",
            f"- User accounts with failures: **{len(analysis.failed_users)}**.",
            "",
            "A high concentration of failures for one account or source "
            "computer would be consistent with brute force or password "
            "spraying. This fragment should be compared with a longer "
            "baseline before treating it as a confirmed attack.",
            "",
            "| User | Failed attempts |",
            "|---|---:|",
        ]
    )
    lines.extend(
        f"| `{user}` | {count} |"
        for user, count in analysis.failed_users.most_common(15)
    )
    lines.extend(
        [
            "",
            "## 4. Conclusion",
            "",
            "The analysis tests two attack hypotheses: **credential attacks** "
            "(brute force/password spraying) and **lateral movement using a "
            "compromised user account**.",
            "",
            f"1. The fragment contains {sum(analysis.result_counts[value] for value in FAILURE_VALUES)} "
            "failed authentication event(s).",
            f"2. It contains {suspicious} successful user-account logon(s) "
            "between different computers.",
            "3. Reuse of one account across multiple hosts is consistent "
            "with lateral movement; repeated failures would support a "
            "credential-attack hypothesis.",
            "",
            "The specific technique and event order cannot be confirmed from "
            "authentication data alone. To validate this hypothesis, correlate "
            "the results with `proc`, `flows`, `dns`, and `redteam` data.",
        ]
    )
    return "\n".join(lines) + "\n"


def format_counter(counter: Counter[str]) -> str:
    return ", ".join(f"{key}: {value}" for key, value in counter.most_common())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="CSV file with auth events")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("analysis_report.md"),
        help="Markdown report path (default: analysis_report.md)",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        help="Stop after this many valid events (useful for a reproducible fragment)",
    )
    parser.add_argument("--start-time", type=int, help="Include events from this timestamp")
    parser.add_argument("--end-time", type=int, help="Include events up to this timestamp")
    args = parser.parse_args()
    if args.max_events is not None and args.max_events <= 0:
        parser.error("--max-events must be positive")
    if (
        args.start_time is not None
        and args.end_time is not None
        and args.start_time > args.end_time
    ):
        parser.error("--start-time cannot be greater than --end-time")
    report = make_report(
        analyze_file(
            args.input,
            max_events=args.max_events,
            start_time=args.start_time,
            end_time=args.end_time,
        ),
        args.input,
    )
    args.output.write_text(report, encoding="utf-8")
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
