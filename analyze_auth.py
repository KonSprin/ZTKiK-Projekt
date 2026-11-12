#!/usr/bin/env python3
"""Analyze LANL authentication events and produce a Markdown report.

The script uses only the Python standard library so it can be run on the
provided sample without installing additional packages.
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


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


def read_events(path: Path) -> list[Event]:
    events: list[Event] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for line_number, row in enumerate(reader, start=1):
            if not row or all(not value.strip() for value in row):
                continue
            if len(row) != len(FIELD_NAMES):
                raise ValueError(
                    f"{path}:{line_number}: expected 9 columns, got {len(row)}"
                )
            try:
                time = int(row[0])
            except ValueError as error:
                raise ValueError(f"{path}:{line_number}: invalid time {row[0]!r}") from error
            events.append(Event(time, *row[1:]))
    if not events:
        raise ValueError(f"{path}: no events found")
    return events


def human_principal(event: Event) -> str | None:
    for candidate in (event.source_user, event.destination_user):
        if HUMAN_USER.match(candidate):
            return candidate
    return None


def human_lateral_events(events: list[Event]) -> list[tuple[str, str, str, int]]:
    """Return human-account logons to other computers, ranked by rarity."""
    pairs = Counter(
        (human_principal(event), event.destination_computer)
        for event in events
        if human_principal(event)
        and event.source_computer != event.destination_computer
        and event.result == "Success"
    )
    return [
        (user, computer, "success", count)
        for (user, computer), count in pairs.most_common()
    ]


def make_report(events: list[Event], input_path: Path) -> str:
    result_counts = Counter(event.result for event in events)
    auth_counts = Counter(event.authentication_type for event in events)
    logon_counts = Counter(event.logon_type for event in events)
    source_users = Counter(
        principal for event in events if (principal := human_principal(event))
    )
    destinations = Counter(event.destination_computer for event in events)
    human_events = [event for event in events if human_principal(event)]
    lateral = human_lateral_events(events)
    human_users = {human_principal(event) for event in human_events}
    human_destinations = {
        event.destination_computer
        for event in human_events
        if event.source_computer != event.destination_computer
    }
    times = [event.time for event in events]
    duration = max(times) - min(times)
    repeated_destinations = sum(1 for count in destinations.values() if count > 1)

    lines = [
        "# Authentication Event Analysis",
        "",
        f"Source: `{input_path}`.",
        "",
        "## 1. Data Scope and Quality",
        "",
        f"- Number of events: **{len(events)}**.",
        f"- Time range: **{min(times)}–{max(times)}** (span: {duration} s).",
        f"- Unique user accounts (`U...@...`): **{len(source_users)}**.",
        f"- Unique destination computers: **{len(destinations)}**.",
        f"- User-account events (`U...@...`): **{len(human_events)}** "
        f"({len(human_users)} accounts, {len(human_destinations)} destination "
        "computer(s)).",
        f"- Successful events: **{result_counts['Success']}**; "
        f"failures: **{result_counts['Failure']}**.",
        "",
        "All records in the sample have timestamp `1`, so time-series analysis "
        "and burst detection are inconclusive. The results below describe "
        "cross-sectional patterns rather than changes over time.",
        "",
        "## 2. Descriptive Statistics",
        "",
        "| Feature | Distribution |",
        "|---|---|",
        f"| Authentication type | {format_counter(auth_counts)} |",
        f"| Logon type | {format_counter(logon_counts)} |",
        f"| Result | {format_counter(result_counts)} |",
        "",
        f"Repeated destination computers: **{repeated_destinations}**. "
        "Most frequent destinations:",
        "",
        "| Computer | Events |",
        "|---|---:|",
    ]
    lines.extend(
        f"| `{computer}` | {count} |"
        for computer, count in destinations.most_common(10)
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
            f"- Affected user accounts: **{len({user for user, _, _, _ in lateral})}**; "
            f"destination computers: **{len({computer for _, computer, _, _ in lateral})}**.",
            "",
            "| User | Destination computer | Result | Count |",
            "|---|---|---|---:|",
        ]
    )
    lines.extend(f"| `{user}` | `{computer}` | {result} | {count} |" for user, computer, result, count in lateral[:15])

    suspicious = [
        event
        for event in human_events
        if event.source_computer != event.destination_computer
        and event.result == "Success"
    ]
    lines.extend(
        [
            "",
            "## 4. Conclusion",
            "",
            "The most likely simulated attack is **lateral movement using a "
            "compromised user account**, potentially involving **pass-the-hash "
            "or credential reuse**. Evidence:",
            "",
            f"1. {len(suspicious)} successful user-account logon(s) connect "
            "different source and destination computers.",
            "2. This pattern differs from local service and machine logons, "
            "which dominate normal activity.",
            "3. Reusing the same account across multiple hosts is consistent "
            "with an attacker moving through the network.",
            "",
            "The specific technique and event order cannot be confirmed because "
            "the sample does not contain all 58 days and every record has the "
            "same timestamp. To validate this hypothesis, analyze the full "
            "`auth.txt.gz` file and correlate it with `proc`, `flows`, `dns`, "
            "and `redteam` data.",
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
    args = parser.parse_args()
    report = make_report(read_events(args.input), args.input)
    args.output.write_text(report, encoding="utf-8")
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
