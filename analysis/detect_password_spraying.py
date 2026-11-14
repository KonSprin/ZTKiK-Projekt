#!/usr/bin/env python3
"""Password spraying: wiele różnych kont loguje się na jeden komputer w krótkim czasie.

Dla każdego komputera liczona jest liczba różnych użytkowników w każdej minucie.
Minuta jest podejrzana, gdy ta liczba wielokrotnie przekracza typową wartość
dla tego komputera (mediana z aktywnych minut) i gdy większość kont nigdy
wcześniej nie logowała się na ten komputer.
"""

from collections import Counter, defaultdict

from common import fmt_time, make_parser, median, print_table, read_events, save_csv


def main():
    parser = make_parser(__doc__)
    parser.add_argument("--min-users", type=int, default=30, help="min. różnych kont w minucie")
    args = parser.parse_args()

    minute_users = defaultdict(set)       # (computer, minute) -> użytkownicy
    new_users = Counter()                 # (computer, minute) -> konta pierwszy raz na hoście
    computer_users = defaultdict(set)     # computer -> wszyscy użytkownicy dotychczas
    events_per_second = Counter()

    for t, user, computer in read_events(args.input):
        key = (computer, t // 60)
        minute_users[key].add(user)
        if user not in computer_users[computer]:
            computer_users[computer].add(user)
            new_users[key] += 1
        events_per_second[t] += 1

    # Typowa liczba kont na minutę dla każdego komputera.
    per_computer = defaultdict(list)
    for (computer, _), users in minute_users.items():
        per_computer[computer].append(len(users))
    typical = {c: median(values) for c, values in per_computer.items()}

    rows = []
    for (computer, minute), users in minute_users.items():
        if len(users) < args.min_users:
            continue
        rows.append([computer, fmt_time(minute * 60), len(users), new_users[(computer, minute)],
                     typical[computer], round(len(users) / typical[computer], 1),
                     len(computer_users[computer])])
    rows.sort(key=lambda r: r[5], reverse=True)

    headers = ["computer", "minute", "users_in_minute", "new_users", "typical_users",
               "ratio", "computer_users_total"]
    print(f"Minuty z >= {args.min_users} różnymi kontami na jednym komputerze: {len(rows)}")
    print_table(headers, rows[:args.top])
    save_csv("password_spraying.csv", headers, rows)

    # Kontekst: sekundy z największą liczbą zdarzeń w całej sieci.
    mean = sum(events_per_second.values()) / len(events_per_second)
    print(f"\nŚrednio {mean:.1f} zdarzeń/s. Najbardziej obciążone sekundy:")
    print_table(["time", "events", "x_mean"],
                [[fmt_time(t), n, round(n / mean, 1)] for t, n in events_per_second.most_common(5)])


if __name__ == "__main__":
    main()
