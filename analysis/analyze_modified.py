from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

DEFAULT_INPUT = Path(__file__).resolve().parent / "data" / "lanl_auth_modified_1.csv"

Pair = Tuple[str, str]


# --------------------------------------------------------------------------- #
# Wczytywanie danych
# --------------------------------------------------------------------------- #


def read_events(path: Path, stats: "Stats") -> Iterator[Tuple[int, str, str]]:
    """Strumieniowo zwraca (time, user, computer); waliduje rekordy."""
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        header = next(reader, None)
        if header is None:
            raise ValueError(f"{path}: pusty plik")
        if [h.strip().lower() for h in header] != ["time", "user", "computer"]:
            # Brak nagłówka - traktujemy pierwszy wiersz jako dane.
            reader = _prepend(header, reader)
        previous = -1
        for row in reader:
            if len(row) != 3:
                stats.invalid += 1
                continue
            try:
                t = int(row[0])
            except ValueError:
                stats.invalid += 1
                continue
            if t < previous:
                stats.unsorted += 1
            previous = t
            yield t, row[1], row[2]


def _prepend(first: List[str], rest: Iterator[List[str]]) -> Iterator[List[str]]:
    yield first
    yield from rest


# --------------------------------------------------------------------------- #
# Struktury pomocnicze
# --------------------------------------------------------------------------- #


@dataclass
class Session:
    user: str
    computer: str
    start: int
    end: int
    events: int

    @property
    def duration(self) -> int:
        return self.end - self.start + 1

    @property
    def density(self) -> float:
        return self.events / self.duration


@dataclass
class Stats:
    events: int = 0
    invalid: int = 0
    unsorted: int = 0
    t_min: Optional[int] = None
    t_max: Optional[int] = None
    per_minute: Counter = field(default_factory=Counter)
    pair_total: Counter = field(default_factory=Counter)
    user_total: Counter = field(default_factory=Counter)
    computer_total: Counter = field(default_factory=Counter)
    user_hour: Counter = field(default_factory=Counter)
    computer_users: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    user_computers: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    session_sizes: Counter = field(default_factory=Counter)
    candidates: List[Session] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Analiza (jedno przejście po pliku)
# --------------------------------------------------------------------------- #


def analyze(path: Path, max_gap: int, keep_min_events: int) -> Stats:
    stats = Stats()
    open_sessions: Dict[Pair, List[int]] = {}  # pair -> [start, last, count]

    def close(pair: Pair, s: List[int]) -> None:
        stats.session_sizes[s[2]] += 1
        if s[2] >= keep_min_events:
            stats.candidates.append(Session(pair[0], pair[1], s[0], s[1], s[2]))

    for t, user, computer in read_events(path, stats):
        stats.events += 1
        if stats.t_min is None:
            stats.t_min = t
        stats.t_max = t if stats.t_max is None else max(stats.t_max, t)
        stats.per_minute[t // 60] += 1
        pair = (user, computer)
        stats.pair_total[pair] += 1
        stats.user_total[user] += 1
        stats.computer_total[computer] += 1
        stats.user_hour[(user, t // 3600)] += 1
        stats.computer_users[computer].add(user)
        stats.user_computers[user].add(computer)

        s = open_sessions.get(pair)
        if s is not None and t - s[1] <= max_gap:
            s[1] = t
            s[2] += 1
        else:
            if s is not None:
                close(pair, s)
            open_sessions[pair] = [t, t, 1]

    for pair, s in open_sessions.items():
        close(pair, s)
    if stats.events == 0:
        raise ValueError(f"{path}: brak poprawnych zdarzeń")
    return stats


# --------------------------------------------------------------------------- #
# Statystyki rozkładu i ocena kandydatów
# --------------------------------------------------------------------------- #


def counter_percentile(counter: Counter, q: float) -> int:
    """Percentyl q (0-1) z histogramu {wartość: liczność}."""
    total = sum(counter.values())
    threshold = q * total
    running = 0
    for value in sorted(counter):
        running += counter[value]
        if running >= threshold:
            return value
    return max(counter)


def share_below(counter: Counter, value: int) -> float:
    total = sum(counter.values())
    return sum(c for v, c in counter.items() if v < value) / total


def robust_log_params(counter: Counter) -> Tuple[float, float]:
    """Mediana i MAD (skalowane 1.4826) dla log(liczby zdarzeń w sesji)."""
    values = sorted(counter)
    total = sum(counter.values())

    def weighted_median(pairs: List[Tuple[float, int]]) -> float:
        pairs.sort()
        half = total / 2
        acc = 0
        for v, c in pairs:
            acc += c
            if acc >= half:
                return v
        return pairs[-1][0]

    med = weighted_median([(math.log(v), counter[v]) for v in values])
    mad = weighted_median([(abs(math.log(v) - med), counter[v]) for v in values])
    return med, max(mad * 1.4826, 0.1)  # dolne ograniczenie: MAD bywa 0


@dataclass
class Finding:
    session: Session
    robust_z: float
    percentile: float
    pair_share: float
    hour_ratio: float
    computer_users: int
    parallel: int
    verdict: str
    score: float


def evaluate(stats: Stats, min_events: int, min_density: float) -> List[Finding]:
    med, mad = robust_log_params(stats.session_sizes)

    # Mediana godzinowej aktywności użytkownika (tylko godziny z aktywnością).
    hours_by_user: Dict[str, List[int]] = defaultdict(list)
    for (user, _hour), count in stats.user_hour.items():
        hours_by_user[user].append(count)
    user_median = {u: statistics.median(v) for u, v in hours_by_user.items()}

    strong = [
        s for s in stats.candidates
        if s.events >= min_events and s.density >= min_density
    ]
    by_user: Dict[str, List[Session]] = defaultdict(list)
    for s in strong:
        by_user[s.user].append(s)

    findings = []
    for s in strong:
        parallel = sum(
            1 for o in by_user[s.user]
            if o is not s and o.computer != s.computer
            and o.start <= s.end and s.start <= o.end
        )
        z = (math.log(s.events) - med) / mad
        pair_share = s.events / stats.pair_total[(s.user, s.computer)]
        peak_hour = max(
            range(s.start // 3600, s.end // 3600 + 1),
            key=lambda h: stats.user_hour[(s.user, h)],
        )
        hour_ratio = stats.user_hour[(s.user, peak_hour)] / user_median[s.user]
        n_users = len(stats.computer_users[s.computer])

        if parallel == 0:
            verdict = "brute force (1 konto -> 1 host)"
        else:
            verdict = "równoległe serie na wielu hostach (automat/usługa?)"
        # Wynik łączny:
        score = (
            z
            * s.density
            * (1 + math.log10(max(hour_ratio, 1)))
            * (1.5 if n_users == 1 else 1.0)
            / (1 + parallel)
        )
        findings.append(Finding(
            s, z, share_below(stats.session_sizes, s.events), pair_share,
            hour_ratio, n_users, parallel, verdict, score,
        ))
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("input", type=Path, nargs="?", default=DEFAULT_INPUT,
                        help="plik CSV time,user,computer")
    parser.add_argument("-o", "--output", type=Path,
                        default=Path(__file__).resolve().parent / "report_bruteforce.md",
                        help="ścieżka raportu Markdown")
    parser.add_argument("--csv", type=Path,
                        default=Path(__file__).resolve().parent / "bruteforce_candidates.csv",
                        help="ścieżka CSV z kandydatami")
    parser.add_argument("--max-gap", type=int, default=5,
                        help="maks. przerwa [s] między zdarzeniami jednej sesji (domyślnie 5)")
    parser.add_argument("--min-events", type=int, default=120,
                        help="min. liczba zdarzeń w sesji kandydata (domyślnie 120)")
    parser.add_argument("--min-density", type=float, default=0.5,
                        help="min. gęstość zdarzeń/s w sesji (domyślnie 0.5)")
    parser.add_argument("--top", type=int, default=15, help="liczba wierszy w raporcie")
    args = parser.parse_args()
    if args.max_gap < 1 or args.min_events < 2:
        parser.error("--max-gap >= 1 oraz --min-events >= 2")

    stats = analyze(args.input, args.max_gap, keep_min_events=min(args.min_events, 30))
    findings = evaluate(stats, args.min_events, args.min_density)
    print(f"Kandydaci CSV: {args.csv} ({len(findings)} sesji)")
    for f in findings[:5]:
        s = f.session
        print(f"  {s.user} -> {s.computer}: {s.events} zdarzeń w {s.duration}s, "
              f"ocena {f.score:.1f}, {f.verdict}")


if __name__ == "__main__":
    main()
