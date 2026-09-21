# Multi-Guard — Przykłady Skanowania i Weryfikacja Detekcji

Przewodnik weryfikacji skuteczności wykrywania, kwarantanny i naprawy zagrożeń w programie **Multi-Guard**.

---

## 1. Test detekcji ciągiem EICAR

EICAR to standardowy, bezpieczny ciąg testowy dla silników antywirusowych. Jego hash SHA-256 znajduje się w bazie sygnatur Multi-Guard (`resources/signatures/seed.json`).

### Kroki testowe:
1. Otwórz program Notatnik.
2. Wklej dokładnie poniższy ciąg znaków w pojedynczej linii (bez spacji na początku/końcu):
   ```text
   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
   ```
3. Zapisz plik jako `eicar.com` na Pulpicie (plik ma rozmiar 68 bajtów i SHA-256: `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`).
4. W programie Multi-Guard kliknij **Szybkie skanowanie** lub **Skanuj wybrany plik**.
5. W ciągu sekundy na liście pojawi się karta zagrożenia:
   - Nazwa: `EICAR-Test-Signature`
   - Rodzina: `TestFile`
   - Poziom istotności: `Low`
   - Wynik: `Score: 100`
   - Dostępne akcje: *Kwarantanna (AES-256)*, *Usuń trwale*, *Otwórz lokalizację*.

---

## 2. Test Tarczy Ransomware (Canary Guard)

W wersji **Multi-Guard Secure** oraz **ADMIN FULL** aktywna jest tarcza ochrony przed ransomware:
1. W Ustawieniach upewnij się, że opcja *Ochrona folderów przed Ransomware* jest włączona.
2. System tworzy w monitorowanych katalogach specjalne pliki-strażniki (`.mg_canary_*`).
3. Każda nieautoryzowana próba modyfikacji lub zaszyfrowania pliku-strażnika natychmiast wyzwala alert, loguje zdarzenie w audycie i blokuje proces sprawcy.

---

## 3. Test Odświeżania i Zmiany Licencji KeyGate

1. Wejdź w zakładkę **Ustawienia** (`cardLicenseSettings`).
2. Sprawdź widoczną liczbę pozostałych dni subskrypcji.
3. Kliknij **Odśwież online** — aplikacja skomunikuje się z `https://license.multi-servis.pl/api/v1/license/verify` i zaktualizuje stan tokena.
4. Aby zmienić klucz: wklej nowy klucz licencyjny i kliknij **Zmień klucz i zrestartuj**. Program wyświetli okno informujące o restarcie i uruchomi się ponownie z nową licencją.

W razie pytań lub potrzeby przedłużenia licencji:
📞 **Infolinia / Serwis:** `505 012 914`
