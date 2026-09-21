# Changelog — Multi-Guard

Wszystkie istotne zmiany i wydania projektu **Multi-Guard** są dokumentowane w tym pliku.

Format opiera się na [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
a projekt stosuje [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-21

### 🎉 Oficjalne Wydanie Multi-Guard

#### Silnik Antywirusowy i Ochrona Endpoint
- Baza sygnatur SHA-256 z weryfikacją integralności w SQLite/JSON.
- Skaner wzorców bajtowych (Byte-Pattern Scanner) z obsługą masek.
- Analiza strukturalna nagłówków Portable Executable (PE).
- Chirurgiczna naprawa zainfekowanych plików EXE/DLL (PE Repair Engine).
- Ochrona w czasie rzeczywistym (`RealTimeShield`) monitorująca filesystem.
- Tarcza Ransomware Sentinel (`RansomwareShield`) z mechanizmem plików-pułapek Canary Guard.
- Ochrona sieciowa (`WebShield`) z blokowaniem złośliwych domen i audytem pliku `hosts`.

#### Licencjonowanie i Integracja KeyGate
- Pełna integracja z serwerem **KeyGate** (`https://license.multi-servis.pl`) dla Product ID `9843d5fd-f090-4534-9d32-d66b64999acb`.
- Kryptograficzna weryfikacja podpisów **Ed25519** (TweetNaCl, bez obcych bibliotek DLL).
- Obsługa 17 planów produkcyjnych (Multi-Guard AV 3/6/9/12m, Secure 3/6/9/12m, Assist 3/6/9/12m, Assist PRO 3/6/9/12m, ADMIN FULL perpetual).
- Dynamiczne przeliczanie dni do końca subskrypcji i prezentacja na Pulpicie, w Ustawieniach oraz na pasku tytułowym.
- Płynna zmiana klucza licencyjnego z modalnym powiadomieniem i automatycznym restartem programu.
- Blokada po wygaśnięciu licencji (`pageLicenseLocked`) z natychmiastowym odnowieniem online lub telefonicznym (`505 012 914`).

#### Integracja z Windows Security Center
- Rejestracja instancji `AntiVirusProduct` w przestrzeni WMI `root\SecurityCenter2`.
- Integracja z aplikacją Zabezpieczenia Windows (Defender): Multi-Guard jest zgłaszany jako aktywny i włączony dostawca antywirusa.
- Kooperacyjne wygaszanie podwójnego skanowania Microsoft Defender (`Set-MpPreference -DisableRealtimeMonitoring $true`).

#### Interfejs Użytkownika i Doświadczenie (UX)
- Nowoczesny interfejs z motywami ciemnym i jasnym oraz obsługą języka polskiego.
- Przycisk `X` chowa aplikację do zasobnika systemowego (`system tray`), a `-` minimalizuje do paska zadań.
- Pakiet narzędzi dodatkowych: Naprawa Windows, Monitor sprzętu, Niszczarka plików (DoD 5220.22-M), Menedżer autostartu, Raporty serwisowe HTML oraz Zdalna pomoc techniczna Multi-Servis.
