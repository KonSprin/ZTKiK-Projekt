#!/usr/bin/env python3
"""Lateral movement: jedno konto w krótkim czasie loguje się na wiele nowych komputerów.

Dla każdego użytkownika zapamiętywane są komputery, na których już się logował.
Po okresie rozgrzewki (--warmup, domyślnie pierwsza doba = profil bazowy)
każde logowanie na komputer, którego konto wcześniej nie używało, jest
"nowym hostem". Szukamy okien czasowych (--window) z największą liczbą nowych
hostów dla jednego konta.
"""

from collections import defaultdict, deque

from common import fmt_time, make_parser, median, print_table, read_events, save_csv


def main():
    parser = make_parser(__doc__)
    parser.add_argument("--warmup", type=int, default=86400, help="okres bazowy [s]")
    parser.add_argument("--window", type=int, default=3600, help="długość okna [s]")
    parser.add_argument("--min-new", type=int, default=10, help="min. nowych hostów w oknie")
    args = parser.parse_args()

    known_hosts = defaultdict(set)      # user -> komputery już używane
    computer_users = defaultdict(set)   # computer -> użytkownicy (do oceny, czy host jest rzadki)
    recent_new = defaultdict(deque)     # user -> (czas, komputer) nowych hostów w oknie
    best = {}                           # user -> [liczba, start, end, lista hostów]
    new_per_user = defaultdict(int)     # user -> łączna liczba nowych hostów po rozgrzewce

    for t, user, computer in read_events(args.input):
        computer_users[computer].add(user)
        if computer in known_hosts[user]:
            continue
        known_hosts[user].add(computer)
        if t < args.warmup:
            continue

        new_per_user[user] += 1
        window = recent_new[user]
        window.append((t, computer))
        while t - window[0][0] > args.window:
            window.popleft()
        if len(window) > best.get(user, [0])[0]:
            best[user] = [len(window), window[0][0], t, [c for _, c in window]]

    counts = list(new_per_user.values())
    print(f"Użytkownicy z nowymi hostami po rozgrzewce: {len(counts)}")
    print(f"  mediana nowych hostów na użytkownika: {median(counts)}, maksimum: {max(counts)}\n")

    rows = []
    for user, (count, start, end, hosts) in best.items():
        if count < args.min_new:
            continue
        rare = sum(1 for c in hosts if len(computer_users[c]) <= 2)
        rows.append([user, count, fmt_time(start), fmt_time(end), end - start,
                     rare, new_per_user[user], len(known_hosts[user]), " ".join(hosts[:8])])
    rows.sort(key=lambda r: r[1], reverse=True)

    headers = ["user", "new_hosts_in_window", "start", "end", "span_s", "rare_hosts",
               "new_hosts_total", "hosts_total", "first_hosts"]
    print(f"Konta z >= {args.min_new} nowymi hostami w oknie {args.window} s: {len(rows)}")
    print_table(headers, rows[:args.top])
    save_csv("lateral_movement.csv", headers, rows)


if __name__ == "__main__":
    main()
