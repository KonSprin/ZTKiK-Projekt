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
