# Analiza zmodyfikowanych danych LANL auth – etap 1: brute force

Plik: `analysis/data/lanl_auth_modified_1.csv`

## 1. Zakres i jakość danych

- Zdarzenia: **8,985,009**
- Zakres czasu: **1–259200 s** (~3 doby).
- Użytkownicy: **9,171**, komputery: **11,611**, pary użytkownik–komputer: **58,980**.
- Zdarzenia na minutę: średnia **2079.4**, mediana **1641**, maksimum **8569**.

Zbiór nie zawiera wyniku uwierzytelnienia ani komputera źródłowego. Każda para (użytkownik, komputer) ma co najwyżej jedno zdarzenie na sekundę, dlatego atak brute force przejawia się jako **ciągła seria zdarzeń jednej pary z gęstością bliską 1 zdarzenia/s**.

## 2. Rozkład bazowy długości sesji

Sesja = kolejne zdarzenia tej samej pary z przerwą ≤ 5 s. Liczba sesji: **5,668,716**.

| Percentyl | Zdarzeń w sesji |
|---|---:|
| 50 | 1 |
| 90 | 3 |
| 99 | 5 |
| 99.9 | 16 |
| 99.99 | 81 |
| max | 5732 |

Kryteria kandydata: ≥ **120** zdarzeń w sesji i gęstość ≥ **0.5** zdarzeń/s. Odporny z-score liczony na log(liczby zdarzeń) względem mediany i MAD wszystkich sesji.

## 3. Kandydaci na brute force

| # | Użytkownik | Komputer | Start | Koniec | Czas [s] | Zdarzeń | Gęstość [/s] | z (log) | Percentyl | Udział w parze | Skok godz. ×med. | Użytk. komputera | Równoległe | Ocena | Werdykt |
|---:|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | `U3366` | `C3778` | d0 18:44:47 | d0 20:03:48 | 4742 | 4735 | 1.00 | 84.6 | 100.0000% | 79% | 617 | 1 | 0 | 480.4 | brute force (1 konto -> 1 host) |
| 2 | `U1407` | `C174` | d0 17:08:32 | d0 19:41:30 | 9179 | 5732 | 0.62 | 86.5 | 100.0000% | 65% | 376 | 5 | 0 | 193.2 | brute force (1 konto -> 1 host) |
| 3 | `U2989` | `C3326` | d1 09:23:46 | d1 09:28:36 | 291 | 197 | 0.68 | 52.8 | 99.9975% | 32% | 135 | 1 | 0 | 167.9 | brute force (1 konto -> 1 host) |
| 4 | `U1407` | `C174` | d2 07:14:54 | d2 07:59:09 | 2656 | 1591 | 0.60 | 73.7 | 99.9999% | 18% | 275 | 5 | 0 | 151.9 | brute force (1 konto -> 1 host) |
| 5 | `U3844` | `C4393` | d1 17:15:59 | d1 17:18:44 | 166 | 165 | 0.99 | 51.1 | 99.9964% | 21% | 167 | 1 | 1 | 122.7 | równoległe serie na wielu hostach (automat/usługa?) |
| 6 | `U3844` | `C4393` | d2 22:43:18 | d2 22:45:49 | 152 | 152 | 1.00 | 50.2 | 99.9958% | 19% | 154 | 1 | 1 | 120.2 | równoległe serie na wielu hostach (automat/usługa?) |
| 7 | `U1091` | `C1248` | d0 11:56:13 | d0 11:58:28 | 136 | 121 | 0.89 | 48.0 | 99.9942% | 9% | 7 | 1 | 0 | 119.7 | brute force (1 konto -> 1 host) |
| 8 | `U3844` | `C4393` | d2 03:15:57 | d2 03:18:43 | 167 | 160 | 0.96 | 50.8 | 99.9962% | 20% | 162 | 1 | 1 | 117.0 | równoległe serie na wielu hostach (automat/usługa?) |
| 9 | `U3844` | `C4393` | d0 22:00:48 | d0 22:03:30 | 163 | 157 | 0.96 | 50.6 | 99.9960% | 20% | 160 | 1 | 1 | 117.0 | równoległe serie na wielu hostach (automat/usługa?) |
| 10 | `U4148` | `C116` | d0 08:51:52 | d0 08:54:24 | 153 | 143 | 0.93 | 49.6 | 99.9955% | 1% | 29 | 7 | 0 | 114.1 | brute force (1 konto -> 1 host) |
| 11 | `U4148` | `C132` | d0 06:30:08 | d0 06:37:44 | 457 | 385 | 0.84 | 59.5 | 99.9991% | 3% | 17 | 32 | 0 | 111.2 | brute force (1 konto -> 1 host) |
| 12 | `U4148` | `C132` | d0 10:20:19 | d0 10:32:19 | 721 | 549 | 0.76 | 63.1 | 99.9993% | 5% | 19 | 32 | 0 | 110.0 | brute force (1 konto -> 1 host) |
| 13 | `U4148` | `C132` | d0 06:40:10 | d0 06:57:48 | 1059 | 757 | 0.71 | 66.3 | 99.9995% | 7% | 17 | 32 | 0 | 105.1 | brute force (1 konto -> 1 host) |
| 14 | `U1407` | `C174` | d0 19:41:36 | d0 19:45:21 | 226 | 131 | 0.58 | 48.8 | 99.9950% | 1% | 273 | 5 | 0 | 97.1 | brute force (1 konto -> 1 host) |
| 15 | `U5244` | `C5999` | d0 08:48:40 | d0 08:54:45 | 366 | 188 | 0.51 | 52.4 | 99.9972% | 22% | 21 | 1 | 0 | 93.4 | brute force (1 konto -> 1 host) |

Objaśnienia: *Udział w parze* – jaka część wszystkich zdarzeń tej pary przypada na sesję; *Skok godz.* – aktywność użytkownika w najaktywniejszej godzinie sesji podzielona przez medianę jego aktywnych godzin; *Użytk. komputera* – liczba różnych kont logujących się na komputer docelowy w całym zbiorze; *Równoległe* – liczba nakładających się w czasie intensywnych sesji tego samego konta na innych hostach.

## 4. Najsilniejszy kandydat

`U3366` → `C3778`: **4735** zdarzeń w **4742 s** (d0 18:44:47 – d0 20:03:48), gęstość 1.00/s.
- Najdłuższa sesja w całym zbiorze ma 5732 zdarzeń; percentyl 99.99 wynosi 81.
- Komputer `C3778` jest używany przez 1 kont(a); para ma łącznie 5988 zdarzeń, 79% z nich w tej jednej sesji.
- Konto `U3366` łącznie: 7551 zdarzeń na 10 komputerach.

| Godzina | Zdarzenia użytkownika |
|---|---:|
| 14 (d0 14:00:00) | 8 |
| 15 (d0 15:00:00) | 9 |
| 16 (d0 16:00:00) | 0 |
| 17 (d0 17:00:00) | 9 |
| 18 (d0 18:00:00) | 1158 |
| 19 (d0 19:00:00) | 4316 |
| 20 (d0 20:00:00) | 314 |
| 21 (d0 21:00:00) | 2 |
| 22 (d0 22:00:00) | 5 |

## 5. Wniosek (etap 1)

Dane zawierają wzorzec zgodny z atakiem **brute force**: konto `U3366` uwierzytelnia się na `C3778` nieprzerwanie co ~1 s przez 4742 s. Seria wielokrotnie przekracza rozkład bazowy, dotyczy jednego konta i jednego hosta i stanowi gwałtowny skok względem normalnej aktywności tego konta. Ponieważ zbiór zawiera wyłącznie (deklaratywnie) udane logowania i nie ma kolumny wyniku, nie można rozróżnić prób nieudanych; wniosek opiera się na intensywności i regularności serii.

Sesje z równoległymi seriami na kilku hostach (identyczny start/koniec) wyglądają raczej na zautomatyzowane zadania i wymagają osobnej weryfikacji w kolejnych etapach (np. password spraying: wiele kont → jeden host, lateral movement: jedno konto → wiele nowych hostów).
