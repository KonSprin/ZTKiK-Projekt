#!/usr/bin/env python3
"""Brute force: długa, nieprzerwana seria logowań jednego konta na jeden komputer.

Kolejne zdarzenia pary (użytkownik, komputer) łączone są w serię, jeżeli
przerwa między nimi nie przekracza --max-gap sekund. Podejrzane są serie
o dużej liczbie zdarzeń i dużej gęstości (zdarzeń na sekundę).
"""

from collections import Counter, defaultdict

from common import fmt_time, make_parser, median, print_table, read_events, save_csv


def find_series(path, max_gap):
    """Zwraca listę serii [user, computer, start, end, events] i statystyki pomocnicze."""
    series = []
    open_series = {}  # (user, computer) -> [start, last, events]
    user_hour = Counter()
    computer_users = defaultdict(set)

    for t, user, computer in read_events(path):
        user_hour[(user, t // 3600)] += 1
        computer_users[computer].add(user)

        current = open_series.get((user, computer))
        if current and t - current[1] <= max_gap:
            current[1] = t
            current[2] += 1
        else:
            if current:
                series.append([user, computer] + current)
            open_series[(user, computer)] = [t, t, 1]

    for (user, computer), current in open_series.items():
        series.append([user, computer] + current)
    return series, user_hour, computer_users


def percentile(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def main():
    parser = make_parser(__doc__)
    parser.add_argument("--max-gap", type=int, default=5, help="maks. przerwa w serii [s]")
    parser.add_argument("--min-events", type=int, default=120, help="min. liczba zdarzeń w serii")
    parser.add_argument("--min-density", type=float, default=0.5, help="min. zdarzeń na sekundę")
    args = parser.parse_args()

    series, user_hour, computer_users = find_series(args.input, args.max_gap)

    sizes = [s[4] for s in series]
    print(f"Serii: {len(series)}")
    for q in (0.5, 0.99, 0.999, 0.9999):
        print(f"  percentyl {q * 100:g}: {percentile(sizes, q)} zdarzeń")
    print(f"  maksimum: {max(sizes)} zdarzeń\n")

    # Mediana godzinowej aktywności każdego użytkownika (tylko godziny z aktywnością).
    hours = defaultdict(list)
    for (user, _), count in user_hour.items():
        hours[user].append(count)
    user_median = {user: median(values) for user, values in hours.items()}

    candidates = []
    for user, computer, start, end, events in series:
        duration = end - start + 1
        density = events / duration
        if events < args.min_events or density < args.min_density:
            continue
        peak = max(user_hour[(user, h)] for h in range(start // 3600, end // 3600 + 1))
        candidates.append([user, computer, start, end, duration, events, density,
                           peak / user_median[user], len(computer_users[computer])])

    # Inne intensywne serie tego samego konta w tym samym czasie na innych hostach.
    for c in candidates:
        c.append(sum(1 for o in candidates
                     if o[0] == c[0] and o[1] != c[1] and o[2] <= c[3] and c[2] <= o[3]))

    # Ranking: liczba zdarzeń x skok aktywności, kara za równoległe serie.
    candidates.sort(key=lambda c: c[5] * c[7] / (1 + c[9]), reverse=True)

    headers = ["user", "computer", "start", "end", "duration_s", "events", "density",
               "hour_jump", "computer_users", "parallel"]
    rows = [[c[0], c[1], fmt_time(c[2]), fmt_time(c[3]), c[4], c[5], f"{c[6]:.2f}",
             f"{c[7]:.0f}", c[8], c[9]] for c in candidates]
    print(f"Kandydaci (>= {args.min_events} zdarzeń, gęstość >= {args.min_density}/s): {len(rows)}")
    print_table(headers, rows[:args.top])
    save_csv("bruteforce.csv", headers, rows)


if __name__ == "__main__":
    main()
