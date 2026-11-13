# Analiza danych dotyczących bezpieczeństwa systemów komputerowych

## Cel

Celem projektu jest przeanalizowanie danych, spreparowanych uprzednio w taki sposób, aby symulować wybrany ataki na bezpieczeństwo systemu komputerowego.

- Wynikiem analizy ma być propozycja typu ataków, które zostały zasymulowane, wraz z uzasadnieniem.
- Metody analizy: analiza statystyczna, analiza szeregu czasowego, analiza anomalii, klasyfikacja wzorców, klastrowanie, metody automatycznego podejmowania decyzji - wybrane przez analizujących.

Możliwe do użycia środki typu: testy statystyczne, metody sztucznej inteligencji, algorytmy uczenia 
maszynowego itp.

## Organizacja pracy
Podział na zespoły 2 osobowe, które zostaną losowo połączone w czwórki: 2+2 

- W pierwszym etapie każda dwuosobowa grupa wybiera rodzaj ataków, które następnie symuluje poprzez modyfikację wybranej tablicy z danymi. Po zakończeniu zadania każda dwójka przekazuje zmodyfikowane dane przypisanej do niej drugiej grupie. W zamian otrzymuje od niej dane, które zostały w tym samym czasie zmodyfikowane w ramach analogicznej symulacji. Żadna z grup nie ujawnia drugiej, jaki rodzaj ataków zasymulowała.
- Oba zespoły dwuosobowe analizują osobno otrzymane dane, na podstawie wybranych metod i środków, przygotowują propozycję, jakie ataki mogły zostać zasymulowane i dlaczego.
- Celem jest sformułowanie wniosków, popartych analizą i obliczeniami.
- Analizy te można wykonać w dowolnym środowisku, Mathematica, Matlab, Wolfram, Python - z użyciem dowolnych języków programowania i bibliotek wybranych do obsługi algorytmów, które zostały zaproponowane

## Dane do analizy

https://csr.lanl.gov/data/cyber1/

**58 kolejnych dni** rejestrowania aktywności w wewnętrznej sieci komputerowej LANL.
**Ponad 1,6 mld zdarzeń** (~12 GB skompresowanych danych).
**12 425 użytkowników, 17 684 komputerów i 62 974 procesy.**

Rodzaje danych:
- Zdarzenia uwierzytelniania Windows i Active Directory
- Uruchamianie i zatrzymywanie procesów
- Zapytania DNS
- Przepływy ruchu sieciowego

Anonimizacja: identyfikatory użytkowników, komputerów i procesów są zanonimizowane, ale pozostają spójne w całym zbiorze.

Rozdzielczość czasowa: 1 sekunda.

Do realizacji zadania można wykorzystać wybrany fragment zbioru danych.

## Dane do analizy otrzymane

https://csr.lanl.gov/data/auth/

Zbiór danych – Uwierzytelnianie użytkowników (LANL)
9 kolejnych miesięcy rejestrowania aktywności w sieci komputerowej Los Alamos National Laboratory (LANL).
Ponad 708 mln zdarzeń pomyślnego uwierzytelniania użytkowników.
Rodzaj danych: informacje o logowaniach użytkowników na komputerach w sieci firmowej.
Struktura danych: każde zdarzenie zapisane jest w osobnym wierszu w formacie: czas, użytkownik, komputer
Anonimizacja: dane użytkowników i komputerów zostały pozbawione informacji identyfikujących.
Format pliku: CSV (wartości rozdzielane przecinkami).

Zbiór umożliwia analizę powiązań między użytkownikami a komputerami oraz zmian aktywności logowania w czasie

## Sample Data Analysis

Authentication event analysis can be run without additional dependencies:

```bash
python3 analyze_auth.py sample_data.csv -o analysis_report.md
```

The script validates records, calculates distribution statistics, and detects
potential lateral movement by user accounts between computers. Results for the
included sample are available in [analysis_report.md](analysis_report.md).
Every sample record has the same timestamp (`1`), so the sample does not
support reliable time-series analysis. For the complete dataset, provide the
appropriate `auth.txt` or extracted `auth.txt.gz` file.

The complete authentication file is very large, so a reproducible fragment can
be analyzed without loading the entire file into memory:

```bash
python3 analyze_auth.py "/path/to/auth" \
  --max-events 1000000 \
  -o analysis_report_auth_1m.md
```

The script also supports `--start-time` and `--end-time`. The report evaluates
two attack hypotheses: credential attacks (brute force/password spraying)
through failed logins, and lateral movement through successful logons between
different computers.

## Analiza otrzymanych danych (`time,user,computer`)

Skrypt `analysis/analyze_modified.py` (tylko biblioteka standardowa) analizuje
`analysis/data/lanl_auth_modified_1.csv` strumieniowo. Etap 1 wykrywa brute
force jako nieprzerwane serie zdarzeń jednej pary użytkownik–komputer:

```bash
python3 analysis/analyze_modified.py
# opcje: --max-gap 5 --min-events 120 --min-density 0.5 --top 15
```

Wyniki: `analysis/report_bruteforce.md` oraz `analysis/bruteforce_candidates.csv`.

## Attack Simulation

To prepare data for the second group, do not modify the original LANL files.
Create a bounded working fragment and inject reproducible synthetic events:

```bash
python3 simulate_attacks.py \
  "$HOME/Desktop/ZTKIK/DANE 1/auth" \
  simulated_auth.csv \
  --max-events 100000 \
  --seed 2026
```

The simulator adds two attack patterns:

1. **Password spraying**: repeated failed logons against several user accounts.
2. **Lateral movement**: successful logons by one user account from one source
   computer to many destination computers.

The output contains the baseline fragment followed by synthetic records and
can be handed to the other group without revealing the attack types. Keep the
command, seed, and attack description private until the other group finishes
its analysis. The original `auth` file is never changed.
