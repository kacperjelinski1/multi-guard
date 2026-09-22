# Procedura Podpisywania Cyfrowego i Wydawania Wersji (Signing & Release)

Niniejszy dokument opisuje procedurę bezpiecznego podpisywania plików binarnych antywirusa **Multi-Guard** oraz przygotowania pakietu instalacyjnego do dystrybucji produkcyjnej.

> [!CAUTION]
> **BEZWZGLĘDNA ZASADA BEZPIECZEŃSTWA:**  
> W repozytorium kodu źródłowego **nigdy nie wolno umieszczać żadnych prywatnych kluczy kryptograficznych, certyfikatów (`.pfx`, `.p12`) ani haseł do tokenów HSM**. Wszystkie klucze muszą być przechowywane na fizycznych tokenach sprzętowych lub w bezpiecznych magazynach chmurowych (Azure Key Vault, AWS CloudHSM, DigiCert KeyLocker).

---

## 1. Wymogi dotyczące podpisu cyfrowego Authenticode

Do poprawnego działania na systemach **Windows 10** i **Windows 11** wszystkie pliki wykonywalne programu muszą być podpisane zaufanym certyfikatem:
1. **Algorytm skrótu:** Wyłącznie **SHA-256** (SHA-1 jest odrzucany przez SmartScreen i jądro Windows).
2. **Znacznik czasu (RFC 3161 Timestamp):** Obowiązkowy, zapewniający ważność podpisu po wygaśnięciu samego certyfikatu.
3. **Certyfikat EV (Extended Validation):** Wymagany dla natychmiastowego budowania reputacji w Microsoft Defender SmartScreen oraz dla sterowników ELAM.

---

## 2. Kolejność podpisywania komponentów

Pliki muszą być podpisywane w ściśle określonej kolejności (od bibliotek zależnych do głównego instalatora):

1. Wszystkie pliki bibliotek dynamicznych: `Qt*.dll`, `plugins\*.dll`, `*.dll`.
2. Główny plik wykonywalny: `Multi-Guard.exe`.
3. Skompilowany sterownik (jeśli dotyczy): `*.sys` (wymaga podpisu WHQL).
4. Gotowy instalator wygenerowany przez Inno Setup: `Multi-Guard-Setup-*.exe`.

---

## 3. Przykładowy skrypt produkcyjnego podpisywania (PowerShell)

Skrypt uruchamiany na maszynie budującej z podłączonym tokenem HSM lub skonfigurowanym Azure Key Vault:

```powershell
<#
    Sign-MultiGuard.ps1
    Skrypt podpisywania binariów Multi-Guard za pomocą signtool.exe
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$TargetDirectory,

    [string]$TimestampServer = "http://timestamp.digicert.com"
)

$SigntoolPath = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"

if (-not (Test-Path $SigntoolPath)) {
    Write-Error "Nie odnaleziono narzędzia signtool.exe w ścieżce: $SigntoolPath"
    exit 1
}

Write-Host "Rozpoczynanie podpisywania bibliotek DLL w: $TargetDirectory"
Get-ChildItem -Path $TargetDirectory -Filter "*.dll" -Recurse | ForEach-Object {
    Write-Host "Podpisywanie: $($_.FullName)"
    & $SigntoolPath sign /fd SHA256 /tr $TimestampServer /td SHA256 /a $_.FullName
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Błąd podpisywania pliku: $($_.FullName)"
        exit $LASTEXITCODE
    }
}

Write-Host "Podpisywanie głównego pliku wykonywalnego Multi-Guard.exe"
$ExePath = Join-Path $TargetDirectory "Multi-Guard.exe"
if (Test-Path $ExePath) {
    & $SigntoolPath sign /fd SHA256 /tr $TimestampServer /td SHA256 /d "Multi-Guard Antivirus" /du "https://multi-servis.pl" /a $ExePath
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Błąd podpisywania Multi-Guard.exe"
        exit $LASTEXITCODE
    }
}

Write-Host "Weryfikacja podpisu binariów..."
& $SigntoolPath verify /pa /v $ExePath
if ($LASTEXITCODE -eq 0) {
    Write-Host "Wszystkie pliki zostały pomyślnie podpisane i zweryfikowane." -ForegroundColor Green
}
```

---

## 4. Integracja z procesem CI/CD (GitHub Actions)

W procesie zautomatyzowanego budowania (GitHub Actions / Azure Pipelines) do podpisywania zaleca się użycie usługi **Azure Trusted Signing** (dawniej Microsoft Artifact Signing) lub **DigiCert Software Trust Manager**:

```yaml
name: Build and Sign Multi-Guard

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Multi-Guard Release
        run: |
          qmake Verax.pro CONFIG+=release
          nmake

      - name: Azure Trusted Signing
        uses: azure/trusted-signing-action@v0.4.1
        with:
          azure-tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          azure-client-id: ${{ secrets.AZURE_CLIENT_ID }}
          azure-client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
          endpoint: https://eus.codesigning.azure.net/
          code-signing-account-name: MultiServisSigning
          certificate-profile-name: MultiGuardProfile
          files-folder: ./RELEASED
          files-folder-filter: exe,dll
          file-digest: SHA256
          timestamp-rfc3161: http://timestamp.digicert.com
          timestamp-digest: SHA256
```

---

## 5. Weryfikacja poprawności w systemie Windows

Po skompilowaniu i podpisaniu instalatora można zweryfikować podpis na dowolnej maszynie z Windows:
1. Kliknij prawym przyciskiem myszy na `Multi-Guard-Setup.exe` -> **Właściwości** -> zakładka **Podpisy cyfrowe**.
2. Podpis powinien wskazywać firmę wydawcy (np. `Multi-Servis`), algorytm `sha256` oraz znacznik czasu.
3. Narzędziem wewnętrznym:
   ```powershell
   .\Multi-Guard.exe --diag
   ```
   Sekcja `[5] PODPIS CYFROWY BINARIÓW` powinna wskazać stan `SIGNED`.
