# Contributing to Multi-Guard

Dziękujemy za zainteresowanie rozwojem projektu **Multi-Guard**! 🎉

## 📋 Spis treści

- [Kodeks postępowania](#kodeks-postępowania)
- [Zgłaszanie błędów (Bug Reports)](#zgłaszanie-błędów)
- [Propozycje nowych funkcji (Feature Requests)](#propozycje-nowych-funkcji)
- [Współpraca programistyczna](#współpraca-programistyczna)
- [Baza sygnatur](#baza-sygnatur)
- [Środowisko deweloperskie](#środowisko-deweloperskie)

---

## Kodeks postępowania

Projekt przestrzega zasad otwartej, merytorycznej i bezpiecznej współpracy. Szczegóły znajdują się w dokumencie [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## Zgłaszanie błędów

1. Upewnij się w [GitHub Issues](https://github.com/kacperjelinski1/multi-guard/issues), że problem nie został już zgłoszony.
2. Zgłoszenie błędu powinno zawierać:
   - Wersję systemu operacyjnego (Windows 10/11, build)
   - Wersję Multi-Guard oraz aktywny plan licencyjny
   - Kroki do odtworzenia problemu
   - Oczekiwane vs rzeczywiste zachowanie
   - Zrzuty ekranu lub fragmenty logów z folderu `%ProgramData%\Multi-Guard\logs`

---

## Propozycje nowych funkcji

Przed otwarciem PR na dużą funkcjonalność zalecamy utworzenie zgłoszenia w [GitHub Issues](https://github.com/kacperjelinski1/multi-guard/issues) z opisem architektury i uzasadnieniem biznesowym.

---

## Współpraca programistyczna

1. Sforkuj repozytorium `https://github.com/kacperjelinski1/multi-guard.git`.
2. Stwórz dedykowaną gałąź (`git checkout -b feature/nazwa-funkcji`).
3. Wprowadź zmiany i upewnij się, że kod kompiluje się z Qt 5.14+ (MinGW 32/64-bit).
4. Przetestuj funkcjonalność na systemie Windows.
5. Wykonaj commit z czytelnym opisem (`git commit -m 'feat: dodano obsługę nowego modułu'`).
6. Wypchnij gałąź (`git push origin feature/nazwa-funkcji`) i utwórz Pull Request.

---

## Baza sygnatur

Baza sygnatur znajduje się w `resources/signatures/seed.json`. Każdy nowy wpis musi posiadać poprawny hash SHA-256, zdefiniowaną rodzinę malware oraz poziom istotności (*Critical*, *High*, *Medium*, *Low*).

---

## Środowisko deweloperskie

- **Kompilator:** MinGW 7.3.0 lub nowszy (C++17)
- **Framework:** Qt 5.14.2 / 5.15+ Static
- **System docelowy:** Windows 7 SP1, 8.1, 10, 11 (x86 & x64)
- **Kontakt techniczny:** Multi-Servis (`kontakt@multi-servis.pl`, tel. `505 012 914`)
