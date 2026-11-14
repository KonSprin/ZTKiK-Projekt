#!/usr/bin/env python3
"""Przejęte konto: aktywność w nocy u konta, które normalnie pracuje w dzień.

Noc to godziny --night-start..--night-end (domyślnie 0-5). Dla każdego konta
liczone są zdarzenia nocne i dzienne w każdej dobie. Podejrzana jest doba,
w której konto ma dużo zdarzeń nocnych, a w pozostałe noce prawie nic,
mimo regularnej aktywności dziennej.
"""

from collections import Counter

from common import make_parser, print_table, read_events, save_csv


def main():
    parser = make_parser(__doc__)
    parser.add_argument("--night-start", type=int, default=0, help="początek nocy (godzina)")
    parser.add_argument("--night-end", type=int, default=5, help="koniec nocy (godzina, włącznie)")
    parser.add_argument("--min-night", type=int, default=30, help="min. zdarzeń nocnych w dobie")
    args = parser.parse_args()

    night = Counter()      # (user, day) -> zdarzenia nocne
    day_time = Counter()   # user -> zdarzenia dzienne
    hosts = {}             # (user, day) -> komputery użyte w nocy

    for t, user, computer in read_events(args.input):
        day, hour = t // 86400, (t // 3600) % 24
        if args.night_start <= hour <= args.night_end:
            night[(user, day)] += 1
            hosts.setdefault((user, day), set()).add(computer)
        else:
            day_time[user] += 1

    night_total = Counter()
    for (user, _), count in night.items():
        night_total[user] += count

    rows = []
    for (user, day), count in night.items():
        if count < args.min_night:
            continue
        other_nights = night_total[user] - count
        # Udział tej jednej nocy we wszystkich nocnych zdarzeniach konta.
        share = count / night_total[user]
        rows.append([user, day, count, other_nights, day_time[user], f"{share:.2f}",
                     len(hosts[(user, day)]), " ".join(sorted(hosts[(user, day)])[:6])])
    # Najpierw konta z aktywnością nocną skupioną w jednej dobie i z dużą aktywnością dzienną.
    rows.sort(key=lambda r: (float(r[5]), r[2] * r[4]), reverse=True)

    headers = ["user", "day", "night_events", "other_nights_events", "day_events",
               "night_share", "night_hosts", "hosts"]
    print(f"Doby z >= {args.min_night} zdarzeniami nocnymi jednego konta: {len(rows)}")
    print_table(headers, rows[:args.top])
    save_csv("off_hours.csv", headers, rows)


if __name__ == "__main__":
    main()
