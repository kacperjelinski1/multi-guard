# Audyt Gotowości do Programu Microsoft Virus Initiative (MVI)

Dokument zawiera szczegółową checklistę wymagań programu **Microsoft Virus Initiative (MVI)** oraz analizę stanu przygotowania projektu **Multi-Guard Antivirus**.

Kategorie statusów:
* **[READY]** – W pełni zaimplementowane, zweryfikowane w kodzie projektu.
* **[PARTIAL]** – Przygotowana architektura/interfejs, wymaga podłączenia komponentu zewnętrznego.
* **[MISSING]** – Wymaganie niezaimplementowane w projekcie.
* **[REQUIRES MICROSOFT]** – Wymaga bezpośredniego udziału, umowy lub weryfikacji ze strony firmy Microsoft.
* **[REQUIRES EXTERNAL CERTIFICATION]** – Wymaga certyfikacji w zewnętrznym laboratorium lub urzędzie certyfikacji.

---

## 1. Architektura Silnika Ochrony i Komponenty Lokalne

| Wymaganie MVI / Windows Security | Status | Stan w projekcie Multi-Guard |
| :--- | :--- | :--- |
| **Ochrona w czasie rzeczywistym (RTP)** | **[READY]** | Zaimplementowane w `RealTimeShield` (monitorowanie tworzenia i edycji plików, ochrona przed ransomware Canary Guard, asynchroniczna inspekcja). |
| **Baza sygnatur wirusów (Signature DB)** | **[READY]** | Zaimplementowane w `SignatureDb` (baza SQLite + JSON, sprawdzanie hashy SHA-256 oraz wzorców bajtowych). |
| **Jawne stany bazy sygnatur** | **[READY]** | Zaimplementowane: `UP_TO_DATE`, `OUT_OF_DATE`, `UPDATE_REQUIRED`, `UPDATE_IN_PROGRESS`, `UPDATE_FAILED`. |
| **Silnik skanujący na żądanie (Scanner Engine)** | **[READY]** | Zaimplementowane w `Scanner` (skanowanie pamięci procesów, plików PE, heurystyka, skanowanie USB i dysków). |
| **Kwarantanna i remediacja (Quarantine)** | **[READY]** | Zaimplementowane w `Quarantine` (kryptograficzny magazyn AES-256-CBC, bezpieczne usuwanie, przywracanie, rejestr zdarzeń). |
| **Niezależna usługa systemowa (Windows Service)** | **[READY]** | Zaimplementowane w `AntivirusService` (praca w tle Session 0, auto-start w Windows SCM, ochrona działa bez otwartego GUI). |
| **Komunikacja GUI ↔ Silnik AV (IPC)** | **[READY]** | Zaimplementowane w `AntivirusService::setupIpcServer` na potoku `MultiGuard_Service_IPC`. |
| **Architektura integracji WSC (Provider Layer)** | **[READY]** | Zaimplementowane w `WindowsSecurityCenterProvider` (oddzielenie stanu wewnętrznego od formatu raportowania WSC). |
| **Narzędzie diagnostyczne developera** | **[READY]** | Zaimplementowane: flaga `--wsc-diag` / `--diag` raportująca stan silnika, sygnatur, PPL, podpisów i usług. |
| **Brak manipulacji Defenderem** | **[READY]** | Kod w 100% oczyszczony z prób modyfikowania `DisableAntiSpyware`, `Set-MpPreference` i wykluczeń. |

---

## 2. Podpisywanie i Ochrona Integralności Procesu

| Wymaganie MVI / Windows Security | Status | Stan w projekcie Multi-Guard |
| :--- | :--- | :--- |
| **Certyfikat Authenticode EV** | **[REQUIRES EXTERNAL CERTIFICATION]** | Wymaga zakupu komercyjnego certyfikatu Code Signing EV na sprzętowym tokenie USB (HSM) przez firmę Multi-Servis. |
| **Podpisywanie wszystkich binariów (`.exe`, `.dll`)** | **[PARTIAL]** | Skrypty i proces przygotowane w dokumentacji `docs/SIGNING_AND_RELEASE.md`. Wymaga podłączenia certyfikatu w procesie CI/CD. |
| **Poziom ochrony procesu PPL (Antimalware-Light)** | **[PARTIAL]** | Architektura usługi `AntivirusService` przygotowana pod flagę PPL. Wymaga autoryzacji przez podpisany sterownik ELAM. |
| **Certyfikowany sterownik ELAM (WHQL)** | **[REQUIRES EXTERNAL CERTIFICATION]** | Sterownik wczesnego startu wymaga przeprowadzenia testów w Windows HLK i uzyskania podpisu Microsoft Hardware Dev Center. |

---

## 3. Wymagania Formalne i Partnerskie Microsoft

| Wymaganie MVI / Windows Security | Status | Stan w projekcie Multi-Guard |
| :--- | :--- | :--- |
| **Podmiot prawny i weryfikacja tożsamości** | **[REQUIRES MICROSOFT]** | Multi-Servis musi posiadać aktywny numer D-U-N-S powiązany z kontem w Microsoft Partner Center. |
| **Akredytacja w laboratorium testowym** | **[REQUIRES EXTERNAL CERTIFICATION]** | Wymagane pozytywne przejście testów detekcji i fałszywych alarmów w AV-TEST, AV-Comparatives lub Virus Bulletin. |
| **Członkostwo w programie MVI** | **[REQUIRES MICROSOFT]** | Wymaga złożenia formalnego wniosku w firmie Microsoft, podpisania umowy MVI NDA i uzyskania Provider GUID. |
| **Dostęp do oficjalnego SDK WSC (`wscapi.dll`)** | **[REQUIRES MICROSOFT]** | Prywatne nagłówki COM `IWscProduct` są udostępniane przez Microsoft wyłącznie po podpisaniu umowy MVI. |
| **Podłączenie produkcyjnego backendu WSC** | **[PARTIAL]** | W projekcie istnieje interfejs `IWscRegistrationBackend`. Klasa `MviWscStubBackend` posiada oznaczenie `TODO(MVI)` oczekujące na certyfikowane SDK. |

---

## 4. Podsumowanie Gotowości

* **Architektura kodu źródłowego Multi-Guard:** **100% GOTOWA** (kod jest czysty, modułowy, bez nielegalnych obejść i spełnia wymogi separacji usługi od GUI).
* **Ścieżka formalno-certyfikacyjna:** **OCZEKUJE NA DZIAŁANIA PRODUCENTA** (zakup certyfikatu EV, testy laboratoryjne, zgłoszenie do MVI i WHQL).
