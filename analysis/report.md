# Analiza otrzymanych danych LANL auth – wnioski

## 1. Dane

Plik `analysis/data/lanl_auth_modified_1.csv`, format `time,user,computer`.

| Cecha | Wartość |
|---|---|
| Zdarzenia | 8 985 009 (0 błędnych wierszy, posortowane po czasie) |
| Zakres czasu | 1–259 200 s, czyli 3 doby |
| Użytkownicy / komputery | 9 171 / 11 611 |
| Pary użytkownik–komputer | 58 980 |
| Średnio zdarzeń na sekundę | 34,7 |

Ograniczenia danych:

- nie ma wyniku logowania (sukces/porażka) ani komputera źródłowego, więc ataków nie da się potwierdzić wprost; wnioski opierają się na intensywności, czasie i relacjach użytkownik–komputer,
- para (użytkownik, komputer) ma najwyżej jedno zdarzenie na sekundę,
- identyfikatory `U` i `C` są numerowane w kolejności pierwszego pojawienia się w pliku, więc numer mówi, kiedy dane konto lub komputer pojawiły się po raz pierwszy,
- aktywność ma wyraźny rytm dobowy: około 65 tys. zdarzeń na godzinę w nocy i około 200 tys. w dzień.

## 2. Metody

Każdy skrypt sprawdza jedną hipotezę (`python3 analysis/<skrypt>.py`, wyniki w `analysis/results/`).

| Skrypt | Hipoteza | Metoda |
|---|---|---|
| `detect_bruteforce.py` | Brute force | Kolejne zdarzenia pary użytkownik–komputer łączone w serie (przerwa ≤ 5 s). Kandydat: ≥ 120 zdarzeń i ≥ 0,5 zdarzenia/s. Porównanie z rozkładem długości serii i z typową godzinną aktywnością konta. |
| `detect_lateral_movement.py` | Lateral movement | Pierwsza doba jako profil bazowy. Potem liczba komputerów nowych dla konta w oknie 1 h. |
| `detect_password_spraying.py` | Password spraying | Liczba różnych kont na jednym komputerze w ciągu minuty w porównaniu z medianą dla tego komputera. |
| `detect_off_hours.py` | Przejęte konto używane w nocy | Zdarzenia konta w godzinach 0–5 w danej dobie w porównaniu z pozostałymi nocami i aktywnością dzienną. |

## 3. Wyniki

### 3.1 Brute force – wykryty

Najsilniejsza anomalia w zbiorze: **`U3366` → `C3778`, doba 0, 18:44:47–20:03:48**.

- 4 735 zdarzeń w 4 742 s, czyli logowanie co sekundę przez prawie 80 minut.
- Rozkład długości serii w całym zbiorze: mediana 1, percentyl 99,99 = 81 zdarzeń. Ta seria jest około 60 razy dłuższa.
- W godzinie szczytu konto miało 617 razy więcej zdarzeń niż w swojej typowej godzinie (4 316 wobec mediany 7).
- Z `C3778` korzysta tylko `U3366` (5 988 zdarzeń), a ta jedna seria to 79% ruchu tej pary.

Inne długie serie wyglądają na zwykłą pracę automatów:

- `U1407` → `C174`: rzadsze zdarzenia (0,6/s), które powtarzają się w różnych dobach,
- `U4148`: wiele godzin aktywności na kilku komputerach jednocześnie,
- `U3844`: serie na dwóch komputerach zaczynają się i kończą w tej samej sekundzie.

### 3.2 Lateral movement – wykryty

Najsilniejszy kandydat: **`U4258`, doba 1, 04:40:58–04:55:31**.

- W 873 s konto zalogowało się na **115 komputerów**, na których wcześniej nie było (łącznie 123 nowe komputery po pierwszej dobie).
- Typowe konto ma po pierwszej dobie medianę 2 nowych komputerów. Drugie i trzecie konto w rankingu mają 34 (`U4075`) i 32 (`U713`).
- Do 53 zdarzeń na sekundę, w dwóch falach (około 04:41 i 04:55). To tempo automatycznego narzędzia, a nie pracy człowieka.
- 77 z tych komputerów ma najwyżej 2 użytkowników, czyli są to stacje robocze, a nie serwery współdzielone.
- 39 komputerów (`C10016`, `C10017`, …) pojawia się w zbiorze po raz pierwszy właśnie w tej serii. Numery są kolejne, a każdy taki komputer odwiedzono kilka razy w ciągu kilku sekund. Wygląda to na zdarzenia dopisane do danych.
- Wcześniej `U4258` pracowało w zwykłych godzinach na kilku komputerach, więc wzorzec pasuje do przejętego konta, które posłużyło do skanowania i przejścia po sieci.

### 3.3 Password spraying – nie wykryty

Najwyższy wynik: `C670`, doba 1, 07:22 – 190 różnych kont w minucie przy typowej wartości 1. Nie uznajemy tego za atak:

- w tym samym czasie skok obejmuje całą sieć: ponad 2,2 tys. kont, ponad 2,3 tys. komputerów i do 1 025 zdarzeń/s (29 razy więcej niż średnio), a potem spada stopniowo przez około 20 s,
- tylko 43 ze 190 kont nie logowało się wcześniej na `C670`,
- `C443` ma podobne skoki w kilku dobach (do 258 kont/min), co pasuje do zwykłego serwera,
- przy password sprayingu spodziewalibyśmy się wielu kont na jednym komputerze, a nie wszystkich kont na wszystkich komputerach.

Ten skok najpewniej jest zdarzeniem całej sieci (np. restartem usługi albo masowym odświeżeniem uwierzytelnień o 7:22 rano).

### 3.4 Aktywność nocna (przejęte konto) – nie wykryta

Skrypt znalazł 4 842 doby, w których konto ma co najmniej 30 zdarzeń w nocy. Najwyższe wyniki (`U4114`, `U6481`, `U8575`, …) mają po 1–2,5 tys. zdarzeń w jedną noc i prawie nic w pozostałe noce. To jednak:

- dziesiątki podobnych kont bez wyraźnego lidera,
- głównie konta, które pojawiają się dopiero w dobie 1 (`U85xx`, `U86xx`), więc mają tylko jedną noc w danych,
- konta z dużą aktywnością dzienną (5–12 tys. zdarzeń), czyli najpewniej konta usługowe i zadania nocne.

Nie znaleźliśmy pojedynczego konta, które wyraźnie odstaje od pozostałych.

## 4. Wnioski

Zbiór zawiera 2 zasymulowane ataki. Na podstawie analizy wskazujemy:

1. **Brute force** – konto `U3366` atakuje komputer `C3778` (doba 0, 18:44–20:03): około 4,7 tys. logowań co sekundę, jeden cel, z którego nie korzysta nikt inny, i nagły wzrost aktywności konta.
2. **Lateral movement** – konto `U4258` w 15 minut (doba 1, 04:41–04:55) loguje się na 115 komputerów, na których wcześniej nie było. Część z nich pojawia się w zbiorze po raz pierwszy właśnie w tej serii.

Pozostałe hipotezy (password spraying i nocna aktywność przejętego konta) nie dały wyniku, który wyraźnie odróżnia się od zwykłego ruchu w sieci. Pasuje to do informacji, że dodano tylko dwa ataki.

Zastrzeżenia: nie mamy etykiet ani potwierdzenia od drugiego zespołu, a pozycje w rankingach zależą od przyjętych progów (`--max-gap`, `--min-events`, `--window` itd.). Wnioski są hipotezami opartymi na wzorcach w danych.
