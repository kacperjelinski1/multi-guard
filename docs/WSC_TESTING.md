# Procedura Testowania Integracji z Windows Security (Windows 10 i 11)

Dokument zawiera zestaw 10 scenariuszy testowych do przeprowadzenia na czystej maszynie wirtualnej z systemem **Windows 10** lub **Windows 11** w celu weryfikacji stabilności, bezpieczeństwa i integracji programu **Multi-Guard Antivirus**.

---

## Środowisko testowe
* **System operacyjny:** Windows 10 (22H2) oraz Windows 11 (23H2 / 24H2) na maszynie wirtualnej (Hyper-V / VirtualBox / VMware).
* **Stan początkowy:** Włączony Microsoft Defender Antivirus, włączona funkcja Tamper Protection (Ochrona przed naruszeniami), czyste konto administratora.
* **Narzędzia diagnostyczne:** PowerShell (jako Administrator), narzędzie wbudowane `Multi-Guard.exe --diag`.

---

## Scenariusze testowe

### Scenariusz 1: Instalacja programu Multi-Guard
* **Krok:** Uruchom instalator `Multi-Guard-Setup.exe` jako Administrator.
* **Oczekiwany rezultat:**
  - Instalator kopiuje pliki do `{autopf}\Multi-Guard`.
  - Rejestruje usługę systemową `MultiGuardAV` w Windows SCM.
  - Ustawia prawidłowe uprawnienia do katalogów (`[Dirs]`).
  - **Nie wykonuje** żadnych modyfikacji w `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`.
  - Nie pojawia się ostrzeżenie Defendera o próbie manipulacji systemem (`DefenderTampering`).

---

### Scenariusz 2: Uruchomienie usługi systemowej Multi-Guard
* **Krok:** Sprawdź stan usługi w PowerShell:
  ```powershell
  Get-Service -Name MultiGuardAV
  ```
* **Oczekiwany rezultat:**
  - Usługa ma stan `Status: Running`, `StartType: Automatic`.
  - Usługa działa w Session 0 na koncie `LocalSystem`.
  - W podglądzie zdarzeń Windows brak błędów startu usługi.

---

### Scenariusz 3: Działanie ochrony w czasie rzeczywistym (RealTimeShield)
* **Krok:**
  1. Pobierz lub utwórz standardowy ciąg testowy **EICAR Standard Anti-Virus Test File**:
     ```
     X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
     ```
  2. Zapisz go jako `eicar.com` na Pulpicie lub w Pobranych.
* **Oczekiwany rezultat:**
  - `RealTimeShield` natychmiast wykrywa utworzenie pliku.
  - Plik zostaje zablokowany i przeniesiony do szyfrowanego magazynu kwarantanny (`Quarantine`).
  - W dzienniku audytu (`AuditLogger`) pojawia się wpis o neutralizacji zagrożenia.
  - Ochrona działa również wtedy, gdy okno Multi-Guard UI jest całkowicie zamknięte.

---

### Scenariusz 4: Aktualizacja bazy sygnatur (SignatureDb)
* **Krok:**
  Uruchom w wierszu poleceń diagnostykę:
  ```powershell
  .\Multi-Guard.exe --diag
  ```
  Następnie w programie kliknij „Aktualizuj sygnatury w chmurze”.
* **Oczekiwany rezultat:**
  - Status sygnatur przechodzi płynnie: `UP_TO_DATE` (lub `UPDATE_IN_PROGRESS` podczas pobierania).
  - Data ostatniej aktualizacji zostaje odświeżona.
  - Zmiana stanu jest natychmiast przekazywana do dostawcy WSC (`WindowsSecurityCenterProvider`).

---

### Scenariusz 5: Zatrzymanie ochrony przez użytkownika
* **Krok:** W zasobniku systemowym (tray) lub w Ustawieniach wyłącz przełącznik „Ochrona w czasie rzeczywistym”.
* **Oczekiwany rezultat:**
  - `RealTimeShield::stop()` zatrzymuje pętlę monitorującą.
  - Provider WSC otrzymuje stan `WscNormalizedState::Snoozed`.
  - Usługa Multi-Guard nadal działa stabilnie w tle (nie ulega awarii).

---

### Scenariusz 6: Ponowne uruchomienie ochrony
* **Krok:** Włącz ponownie przełącznik „Ochrona w czasie rzeczywistym”.
* **Oczekiwany rezultat:**
  - `RealTimeShield::start()` wznawia monitorowanie katalogów.
  - Provider WSC raportuje stan `WscNormalizedState::Active`.

---

### Scenariusz 7: Restart systemu operacyjnego (Reboot Test)
* **Krok:** Zrestartuj maszynę testową z systemem Windows. Nie loguj się natychmiast.
* **Oczekiwany rezultat:**
  - Usługa `MultiGuardAV` startuje automatycznie przed zalogowaniem użytkownika.
  - Tarcza w czasie rzeczywistym chroni system w sesji logowania.
  - Po zalogowaniu ikona w zasobniku systemowym natychmiast łączy się z usługą poprzez potok IPC `MultiGuard_Service_IPC`.

---

### Scenariusz 8: Odinstalowanie programu Multi-Guard
* **Krok:** Otwórz *Ustawienia -> Aplikacje -> Zainstalowane aplikacje* i odinstaluj Multi-Guard.
* **Oczekiwany rezultat:**
  - Deinstalator zatrzymuje i usuwa usługę `MultiGuardAV` (`--stop-service`, `--uninstall-service`).
  - Wywołuje `WindowsSecurityCenterProvider::unregisterProduct()` czyszcząc wszelkie rejestracje.
  - Wszystkie pliki programu zostają usunięte bez blokad i błędów.

---

### Scenariusz 9: Weryfikacja stanu w Windows Security (GUI i PowerShell)
* **Krok:**
  1. Otwórz: *Ustawienia -> Prywatność i zabezpieczenia -> Zabezpieczenia Windows -> Ochrona przed wirusami i zagrożeniami*.
  2. W PowerShell wykonaj odczyt:
     ```powershell
     Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
     ```
* **Oczekiwany rezultat:**
  - Windows Security wyświetla prawidłowy stan dostawców.
  - Brak fałszywych lub uszkodzonych wpisów.
  - W podglądzie zdarzeń brak błędów usługi `wscsvc`.

---

### Scenariusz 10: Rzeczywisty stan Microsoft Defender Antivirus
* **Krok:** Sprawdź stan Defendera w PowerShell:
  ```powershell
  Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, AMServiceEnabled
  ```
* **Oczekiwany rezultat:**
  - **Stan przed oficjalną certyfikacją MVI:** Microsoft Defender pozostaje w pełni sprawny i aktywny (`RealTimeProtectionEnabled: True`). Multi-Guard nie próbuje go siłowo wyłączać ani uszkadzać jego usług.
  - **Stan po oficjalnej certyfikacji MVI:** System Windows samoczynnie decyduje o przełączeniu Defendera w tryb pasywny (*Periodic Scanning*) w momencie wykrycia autoryzowanego dostawcy zewnętrznego.
