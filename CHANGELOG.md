# Changelog — Multi-Guard

Wszystkie istotne zmiany i wydania projektu **Multi-Guard** są dokumentowane w tym pliku.

Format opiera się na [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
a projekt stosuje [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [2.0.2.0] - 2026-09-22

### 💎 Asynchroniczne Definicje, Autostart bez UAC & Dymki Zasobnika
- **Asynchroniczna aktualizacja definicji w tle**: Kliknięcie pobierania definicji nie blokuje ani na ułamek sekundy głównego wątku GUI (`QProcess` asynchroniczny z animacją HUD).
- **Autostart bez monitu UAC (Task Scheduler)**: Program rejestruje zadanie w Harmonogramie Zadań Windows (`schtasks /Create /RL HIGHEST /SC ONLOGON`), dzięki czemu przy starcie systemu uruchamia się natychmiast do zasobnika z uprawnieniami administratora bez wyskakującego okienka UAC.
- **Powiadomienia dymkowe w zasobniku (Windows Tray Toasts)**: Wyświetlanie eleganckich dymków informacyjnych o zakończeniu skanowania w tle oraz wpięciu nośników USB.
- **Wskaźnik lekkości RAM**: Prezentacja rzeczywistego zużycia pamięci Multi-Guard (~28 MB, <0.1% CPU) w zakładce Narzędzia.

## [2.0.1.0] - 2026-09-22

### ⚡ Błyskawiczny IPC Single-Instance, Reguły ASR & Optymalizacja Rejestru
- **Inteligentny IPC Single-Instance**: Wywołanie skanowania z menu kontekstowego PPM przesyła ścieżkę do działającego programu przez `QLocalSocket` (`SCAN:<ścieżka>`). Okno wyskakuje natychmiast w 0.005s bez restartu procesu i bez ponownego ładowania bibliotek.
- **Reguły ASR (Attack Surface Reduction)**: Ochrona korporacyjna przed złośliwymi makrami Office, procesami potomnymi Word/Excel, kradzieżą poświadczeń z pamięci LSASS oraz niepodpisanym kodem z USB.
- **Globalna Ochrona Sieciowa Defender Network Protection**: Blokowanie szkodliwych domen phishingowych i C2 na poziomie całego systemu Windows.
- **Optymalizacja odpytywania statusu (0% CPU)**: Bezpośredni odczyt stanu bazy sygnatur z rejestru Windows `HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates` z pamięcią podręczną.
- **Automatyczna synchronizacja wykluczeń**: Dodawanie i usuwanie wykluczeń w GUI natychmiast synchronizuje listę z Microsoft Defenderem (`Add-MpPreference / Remove-MpPreference`).

## [2.0.0.0] - 2026-09-22

### 🛡️ Pure Microsoft Defender Overlay & Pełna Integracja Systemowa (V2)
- **Architektura Pure Defender Overlay**: Całkowite odciążenie systemu — usunięcie ciężkich baz sygnatur SQLite i hakowania dysku na rzecz bezpośredniej integracji z oficjalnym, zaufanym silnikiem Microsoft Defender (`MpCmdRun.exe`, `WdFilter.sys`).
- **Przejęcie protokołu `windowsdefender://`**: Kliknięcie ochrony antywirusowej w Ustawieniach Windows (Windows Settings) lub w powiadomieniach systemowych otwiera natychmiast Multi-Guard.
- **Menu kontekstowe Eksploratora Windows**: Domyślna integracja pod prawym przyciskiem myszy dla plików, katalogów i dysków („Skanuj za pomocą Multi-Guard” z ikoną aplikacji).
- **Zaawansowane moduły ochronne**: Integracja z ochroną przed Ransomware (Controlled Folder Access) oraz chmurowym blokowaniem w ułamku sekundy (MAPS Cloud Block at First Sight).
- **Generator Certyfikatów Serwisowych Multi-Servis**: Generowanie oficjalnych raportów stanu stacji roboczej dla klientów serwisu.
- **Wzajemne wykluczenia i wyciszenie toastów Defendera**: Automatyczne dodanie Multi-Guard do wykluczeń oraz przekierowanie powiadomień i ikony zasobnika tak, aby Multi-Guard był jedynym centrum powiadomień.

## [1.1.7.0] - 2026-09-22

### ✨ AEGIS Cyber HUD & Lekka Architektura Antywirusa
- **Interfejs AEGIS 1:1**: Wdrożenie pełnego Cyber HUD, responsywności wszystkich 9 ekranów oraz panoramicznego tła górskiego na Pulpicie.
- **Dedykowane ikony**: Ostre neonowe ikony modułów (Tarcza, WWW, Zapora, Poczta) oraz jednolite szare ikony nawigacji bocznej.
- **Usunięcie WSC / DefendNot**: Całkowita rezygnacja z zewnętrznych providerów WSC, atrap WMI oraz usług w tle na rzecz stabilnego, samodzielnego działania.
- **Kompilacja i Instalator**: Naprawa reguł uprawnień Inno Setup oraz automatyczny proces budowania i publikacji wydań.

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

#### Interfejs Użytkownika i Doświadczenie (UX)
- Nowoczesny interfejs z motywami ciemnym i jasnym oraz obsługą języka polskiego.
- Przycisk `X` chowa aplikację do zasobnika systemowego (`system tray`), a `-` minimalizuje do paska zadań.
- Pakiet narzędzi dodatkowych: Naprawa Windows, Monitor sprzętu, Niszczarka plików (DoD 5220.22-M), Menedżer autostartu, Raporty serwisowe HTML oraz Zdalna pomoc techniczna Multi-Servis.
