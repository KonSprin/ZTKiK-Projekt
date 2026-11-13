#!/usr/bin/env python3
"""Inject reproducible attack patterns into a bounded LANL auth fragment.

The original input is never modified. The output contains the selected
baseline records followed by synthetic records representing two attacks:
password spraying and lateral movement.
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

from analyze_auth import Event, open_input


def read_fragment(path: Path, max_events: int) -> list[Event]:
    events: list[Event] = []
    with open_input(path) as handle:
        reader = csv.reader(handle)
        for line_number, row in enumerate(reader, start=1):
            if not row:
                continue
            if len(row) != 9:
                raise ValueError(f"{path}:{line_number}: expected 9 columns")
            try:
                event = Event(int(row[0]), *row[1:])
            except ValueError as error:
                raise ValueError(f"{path}:{line_number}: invalid event") from error
            events.append(event)
            if len(events) == max_events:
                break
    if not events:
        raise ValueError(f"{path}: no events found")
    return events


def simulate(events: list[Event], seed: int) -> list[Event]:
    random_generator = random.Random(seed)
    users = sorted(
        {
            candidate
            for event in events
            for candidate in (event.source_user, event.destination_user)
            if candidate.startswith("U") and "@" in candidate
        }
    )
    computers = sorted(
        {
            computer
            for event in events
            for computer in (event.source_computer, event.destination_computer)
            if computer.startswith("C")
        }
    )
    if len(users) < 2 or len(computers) < 5:
        raise ValueError("The baseline fragment does not contain enough entities")

    attack_user = random_generator.choice(users)
    spray_targets = random_generator.sample(users, min(10, len(users)))
    lateral_targets = random_generator.sample(computers, min(20, len(computers)))
    first_time = max(event.time for event in events) + 1
    synthetic: list[Event] = []

    # Password spraying: one source attempts the same account set and fails.
    for offset, target_user in enumerate(spray_targets):
        for attempt in range(5):
            synthetic.append(
                Event(
                    first_time + offset,
                    f"C{90000 + attempt}@DOM1",
                    target_user,
                    f"C{90000 + attempt}",
                    f"C{90000 + attempt}",
                    "Kerberos",
                    "Network",
                    "LogOn",
                    "Fail",
                )
            )

    # Lateral movement: one account successfully authenticates to many hosts.
    for offset, destination in enumerate(lateral_targets):
        synthetic.append(
            Event(
                first_time + 100 + offset,
                attack_user,
                attack_user,
                "C99999",
                destination,
                "Kerberos",
                "Network",
                "LogOn",
                "Success",
            )
        )
    return events + synthetic


def write_events(path: Path, events: list[Event]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerows(
            (
                event.time,
                event.source_user,
                event.destination_user,
                event.source_computer,
                event.destination_computer,
                event.authentication_type,
                event.logon_type,
                event.orientation,
                event.result,
            )
            for event in events
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Original auth/auth.gz file")
    parser.add_argument("output", type=Path, help="Synthetic auth CSV output")
    parser.add_argument("--max-events", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()
    if args.max_events <= 0:
        parser.error("--max-events must be positive")
    write_events(args.output, simulate(read_fragment(args.input, args.max_events), args.seed))
    print(f"Generated {args.output}")


if __name__ == "__main__":
    main()
