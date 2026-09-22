// WindowsSecurityCenterProvider.cpp
// Official integration layer for Windows Security Center (MVI compliant)
#include "WindowsSecurityCenterProvider.h"
#include "RealTimeShield.h"
#include "SignatureDb.h"
#include "LicenseManager.h"
#include "AntivirusService.h"
#include "Scanner.h"
#include "Logger.h"
#include "AuditLogger.h"
#include "../../Version.h"

#include <QCoreApplication>
#include <QDir>
#include <QProcess>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QDateTime>

#ifdef _WIN32
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#endif

namespace verax {

const QString WindowsSecurityCenterProvider::PRODUCT_GUID = QStringLiteral("{9843D5FD-F090-4534-9D32-D66B64999ACB}");
const QString WindowsSecurityCenterProvider::DISPLAY_NAME = QStringLiteral("Multi-Guard Antivirus");

quint32 WscReportedState::calculateStandardProductStateBitmask() const
{
    // Specyfikacja 32-bitowej bitmaski Windows Security Center:
    // Bajt 2 (0x060000): Typ dostawcy (0x06 = AntiVirus)
    // Bajt 1 (0x001100): Stan ochrony w czasie rzeczywistym
    //                    0x10 = RTP aktywny
    //                    0x01 = Silnik skanera aktywny
    //                    0x00 = Ochrona wyłączona
    // Bajt 0 (0x000010): Stan bazy sygnatur
    //                    0x00 = Sygnatury aktualne
    //                    0x10 = Sygnatury przestarzałe (> 7 dni)
    quint32 state = 0x060000;

    switch (normalizedState) {
    case WscNormalizedState::Active:
        state |= 0x001100; // RTP on + AV on
        if (!areSignaturesUpToDate) state |= 0x000010;
        break;
    case WscNormalizedState::OutOfDate:
        state |= 0x001110; // RTP on, ale sygnatury przestarzałe
        break;
    case WscNormalizedState::AttentionRequired:
        state |= 0x000100; // Wymaga uwagi użytkownika
        if (!areSignaturesUpToDate) state |= 0x000010;
        break;
    case WscNormalizedState::Snoozed:
    case WscNormalizedState::Stopped:
        state |= 0x000000; // Całkowicie wyłączony
        break;
    }
    return state;
}

/**
 * @brief Domyślny backend stub dla oficjalnej integracji Microsoft Virus Initiative (MVI).
 * 
 * TODO(MVI): Official Microsoft AV provider integration required here.
 * Po uzyskaniu akredytacji MVI i certyfikacji WHQL ELAM, ten backend zostanie zastąpiony
 * przez implementację wywołującą oficjalne interfejsy COM IWscProduct/IWscProduct2 w wscapi.dll.
 * Nie stosujemy żadnych sztucznych zapisów do WMI ani obejść jądra.
 */
class MviWscStubBackend : public IWscRegistrationBackend {
public:
    MviWscStubBackend() = default;
    ~MviWscStubBackend() override = default;

    bool isAvailable() const override {
        // Wymaga autoryzacji MVI, certyfikatu Authenticode EV oraz sterownika ELAM z PPL
        return false;
    }

    bool isStub() const override {
        return true;
    }

    bool registerProvider(const QString &exePath, const WscReportedState &state) override {
        Q_UNUSED(exePath);
        Logger::info(QStringLiteral("WindowsSecurityCenterProvider [MviStub]: Rejestracja WSC (stan: %1). "
                                    "Oczekiwanie na oficjalną certyfikację MVI/ELAM (brak sztucznych wpisów WMI).")
                     .arg(state.calculateStandardProductStateBitmask(), 6, 16, QLatin1Char('0')));
        return false;
    }

    bool updateState(const WscReportedState &state) override {
        Logger::info(QStringLiteral("WindowsSecurityCenterProvider [MviStub]: Aktualizacja stanu dostawcy -> %1 "
                                    "(Bitmaska: 0x%2, Sygnatury: %3)")
                     .arg(state.normalizedState == WscNormalizedState::Active ? "ACTIVE" : "INACTIVE")
                     .arg(state.calculateStandardProductStateBitmask(), 6, 16, QLatin1Char('0'))
                     .arg(state.areSignaturesUpToDate ? "UP_TO_DATE" : "OUT_OF_DATE"));
        return true;
    }

    bool unregisterProvider() override {
        Logger::info("WindowsSecurityCenterProvider [MviStub]: Wyrejestrowanie dostawcy WSC.");
        return true;
    }

    QString backendDescription() const override {
        return QStringLiteral("Microsoft Virus Initiative (MVI) COM Provider [Stub / Uncertified]");
    }
};

WindowsSecurityCenterProvider& WindowsSecurityCenterProvider::instance()
{
    static WindowsSecurityCenterProvider s_instance;
    return s_instance;
}

WindowsSecurityCenterProvider::WindowsSecurityCenterProvider(QObject *parent)
    : QObject(parent)
    , m_backend(std::make_unique<MviWscStubBackend>())
{
    connect(qApp, &QCoreApplication::aboutToQuit, this, [this]() {
        notifyShutdown();
    });
}

WindowsSecurityCenterProvider::~WindowsSecurityCenterProvider()
{
    notifyShutdown();
}

void WindowsSecurityCenterProvider::setBackend(std::unique_ptr<IWscRegistrationBackend> backend)
{
    if (backend) {
        m_backend = std::move(backend);
        Logger::info(QStringLiteral("WindowsSecurityCenterProvider: Zainstalowano nowy backend WSC: %1")
                     .arg(m_backend->backendDescription()));
    }
}

AvEngineInternalState WindowsSecurityCenterProvider::collectInternalState() const
{
    AvEngineInternalState state;
    state.isEngineRunning       = true;
    state.isRtpActive           = RealTimeShield::instance().isRunning();
    state.isRtpEnabled          = RealTimeShield::instance().isEnabled();
    state.sigStatus             = SignatureDb::instance().status();
    state.sigCount              = SignatureDb::instance().totalSignatures();
    state.lastSigUpdateIso      = SignatureDb::instance().lastUpdate();
    state.isLicenseValid        = LicenseManager::instance().isValid();
    state.licenseTier           = LicenseManager::instance().tierName();
    state.isUpdatingSignatures  = (state.sigStatus == SignatureStatus::UPDATE_IN_PROGRESS);

    if (!state.isLicenseValid) {
        state.hasComponentFailure = true;
        state.failureReason = QStringLiteral("Wymagana aktywacja licencji.");
        state.isAttentionRequired = true;
    } else if (state.sigStatus == SignatureStatus::UPDATE_REQUIRED || state.sigStatus == SignatureStatus::UPDATE_FAILED) {
        state.isAttentionRequired = true;
    }

    return state;
}

WscReportedState WindowsSecurityCenterProvider::mapToWscState(const AvEngineInternalState &internal) const
{
    WscReportedState wsc;
    wsc.displayName            = DISPLAY_NAME;
    wsc.executablePath         = QCoreApplication::applicationFilePath();
    wsc.engineVersion          = QStringLiteral(APP_VERSION_STR);
    wsc.isRtpEnabled           = internal.isRtpEnabled && internal.isRtpActive;
    wsc.areSignaturesUpToDate  = (internal.sigStatus == SignatureStatus::UP_TO_DATE);

    if (!internal.isLicenseValid || internal.hasComponentFailure) {
        wsc.normalizedState = WscNormalizedState::AttentionRequired;
    } else if (!wsc.isRtpEnabled) {
        wsc.normalizedState = WscNormalizedState::Snoozed;
    } else if (!wsc.areSignaturesUpToDate) {
        wsc.normalizedState = WscNormalizedState::OutOfDate;
    } else {
        wsc.normalizedState = WscNormalizedState::Active;
    }

    return wsc;
}

bool WindowsSecurityCenterProvider::refreshStatus()
{
    AvEngineInternalState internal = collectInternalState();
    WscReportedState wsc = mapToWscState(internal);

    if (m_backend) {
        return m_backend->updateState(wsc);
    }
    return false;
}

bool WindowsSecurityCenterProvider::unregisterProduct()
{
    if (m_backend) {
        return m_backend->unregisterProvider();
    }
    return true;
}

bool WindowsSecurityCenterProvider::notifyShutdown()
{
    if (m_backend) {
        AvEngineInternalState internal = collectInternalState();
        WscReportedState wsc = mapToWscState(internal);
        wsc.normalizedState = WscNormalizedState::Stopped;
        wsc.isRtpEnabled    = false;
        return m_backend->updateState(wsc);
    }
    return true;
}

void WindowsSecurityCenterProvider::onRtpStatusChanged(bool active)
{
    Q_UNUSED(active);
    refreshStatus();
}

void WindowsSecurityCenterProvider::onSignaturesUpdated(int added, int total, const QString &error)
{
    Q_UNUSED(added);
    Q_UNUSED(total);
    Q_UNUSED(error);
    refreshStatus();
}

bool WindowsSecurityCenterProvider::verifyBinarySignature(const QString &filePath, QString &detailsOut)
{
#ifndef _WIN32
    Q_UNUSED(filePath);
    detailsOut = QStringLiteral("Weryfikacja Authenticode dostępna na platformie Windows.");
    return false;
#else
    const std::wstring widePath = QDir::toNativeSeparators(filePath).toStdWString();

    HMODULE hWinTrust = LoadLibraryW(L"wintrust.dll");
    if (!hWinTrust) {
        detailsOut = QStringLiteral("Błąd ładowania biblioteki wintrust.dll.");
        return false;
    }

    typedef LONG (WINAPI *pfnWinVerifyTrust_t)(HWND, GUID*, LPVOID);
    pfnWinVerifyTrust_t pfnWinVerifyTrust = reinterpret_cast<pfnWinVerifyTrust_t>(
        GetProcAddress(hWinTrust, "WinVerifyTrust"));

    if (!pfnWinVerifyTrust) {
        FreeLibrary(hWinTrust);
        detailsOut = QStringLiteral("Nie odnaleziono procedury WinVerifyTrust.");
        return false;
    }

    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = widePath.c_str();

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData;
    memset(&trustData, 0, sizeof(trustData));
    trustData.cbStruct            = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice          = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice       = WTD_CHOICE_FILE;
    trustData.pFile               = &fileInfo;
    trustData.dwStateAction       = WTD_STATEACTION_IGNORE;

    LONG lStatus = pfnWinVerifyTrust(NULL, &actionGuid, &trustData);
    FreeLibrary(hWinTrust);

    if (lStatus == ERROR_SUCCESS) {
        detailsOut = QStringLiteral("Prawidłowy, zaufany podpis cyfrowy Authenticode.");
        return true;
    } else if (lStatus == static_cast<LONG>(TRUST_E_NOSIGNATURE)) {
        detailsOut = QStringLiteral("Brak podpisu cyfrowego Authenticode (plik niepodpisany).");
        return false;
    } else if (lStatus == static_cast<LONG>(TRUST_E_EXPLICIT_DISTRUST) || lStatus == static_cast<LONG>(CERT_E_UNTRUSTEDROOT)) {
        detailsOut = QStringLiteral("Certyfikat testowy / self-signed (niezaufany główny urząd certyfikacji).");
        return false;
    } else {
        detailsOut = QStringLiteral("Kod błędu weryfikacji podpisu: 0x%1")
                     .arg(static_cast<quint32>(lStatus), 8, 16, QLatin1Char('0'));
        return false;
    }
#endif
}

bool WindowsSecurityCenterProvider::checkProcessProtectionLevel(bool &isPpl, QString &statusString)
{
    isPpl = false;
    statusString = QStringLiteral("NOT_AVAILABLE");
#ifndef _WIN32
    return false;
#else
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return false;

    typedef struct _PROCESS_PROTECTION_LEVEL_INFORMATION {
        DWORD ProtectionLevel;
    } PROCESS_PROTECTION_LEVEL_INFORMATION;

    typedef BOOL (WINAPI *pfnGetProcessInformation_t)(HANDLE, int, PVOID, DWORD);
    pfnGetProcessInformation_t pfnGetProcessInfo = reinterpret_cast<pfnGetProcessInformation_t>(
        GetProcAddress(hKernel32, "GetProcessInformation"));

    if (pfnGetProcessInfo) {
        PROCESS_PROTECTION_LEVEL_INFORMATION info;
        memset(&info, 0, sizeof(info));
        if (pfnGetProcessInfo(GetCurrentProcess(), 3, &info, sizeof(info))) {
            if (info.ProtectionLevel != 0) {
                isPpl = true;
                statusString = QStringLiteral("ENABLED (Level: 0x%1)").arg(info.ProtectionLevel, 2, 16, QLatin1Char('0'));
            } else {
                statusString = QStringLiteral("NOT_CERTIFIED (Zwykły proces bez PPL)");
            }
            return true;
        }
    }
    statusString = QStringLiteral("NOT_AVAILABLE (API niedostępne na tym systemie)");
    return false;
#endif
}

bool WindowsSecurityCenterProvider::checkElamStatus(bool &installed, QString &statusString)
{
    installed = false;
    statusString = QStringLiteral("NOT_INSTALLED / NOT_CERTIFIED (Brak zarejestrowanego sterownika ELAM WHQL)");
#ifdef _WIN32
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        // Sprawdzenie czy istnieje zarejestrowany sterownik ELAM o nazwie MultiGuardElam
        SC_HANDLE hElam = OpenServiceW(hSCM, L"MultiGuardElam", SERVICE_QUERY_STATUS);
        if (hElam) {
            installed = true;
            statusString = QStringLiteral("INSTALLED (Sterownik wykryty)");
            CloseServiceHandle(hElam);
        }
        CloseServiceHandle(hSCM);
    }
#endif
    return installed;
}

void WindowsSecurityCenterProvider::queryWscStateReadOnly(WscDiagnosticReport &report)
{
#ifndef _WIN32
    report.isVisibleInWsc = false;
    report.systemAvSummary = QStringLiteral("Brak weryfikacji (platforma inna niż Windows).");
#else
    // Wyłącznie bezpieczny odczyt z root\SecurityCenter2 (bez Put, bez CreateInstance)
    const QString psScript = QStringLiteral(
        "try { "
        "  $items = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop; "
        "  if ($items) { "
        "    $arr = @(); "
        "    foreach ($it in $items) { "
        "      $arr += @{ "
        "        name = $it.displayName; "
        "        guid = $it.instanceGuid; "
        "        path = $it.pathToSignedProductExe; "
        "        state = $it.productState "
        "      }; "
        "    } "
        "    $arr | ConvertTo-Json -Compress; "
        "  } else { Write-Output '[]'; } "
        "} catch { "
        "  try { "
        "    $items = Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop; "
        "    if ($items) { "
        "      $arr = @(); "
        "      foreach ($it in $items) { "
        "        $arr += @{ "
        "          name = $it.displayName; "
        "          guid = $it.instanceGuid; "
        "          path = $it.pathToSignedProductExe; "
        "          state = $it.productState "
        "        }; "
        "      } "
        "      $arr | ConvertTo-Json -Compress; "
        "    } else { Write-Output '[]'; } "
        "  } catch { Write-Output 'ERROR:' $_.Exception.Message; } "
        "}"
    );

    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000; /* CREATE_NO_WINDOW */
    });

    QStringList procArgs;
    procArgs << QStringLiteral("-NoProfile")
             << QStringLiteral("-NonInteractive")
             << QStringLiteral("-ExecutionPolicy") << QStringLiteral("Bypass")
             << QStringLiteral("-WindowStyle") << QStringLiteral("Hidden")
             << QStringLiteral("-Command") << psScript;

    proc.start(QStringLiteral("powershell.exe"), procArgs);
    if (!proc.waitForStarted(4000) || !proc.waitForFinished(10000)) {
        report.systemAvSummary = QStringLiteral("Nie udało się odpytać root\\SecurityCenter2 (timeout lub brak dostępu).");
        return;
    }

    const QString output = QString::fromUtf8(proc.readAllStandardOutput()).trimmed();
    if (output.startsWith(QStringLiteral("ERROR:"))) {
        report.systemAvSummary = QStringLiteral("Błąd odczytu root\\SecurityCenter2: %1").arg(output);
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(output.toUtf8());
    QJsonArray array;
    if (doc.isArray()) {
        array = doc.array();
    } else if (doc.isObject()) {
        array.append(doc.object());
    }

    QStringList detectedAvs;
    report.isVisibleInWsc = false;

    for (const QJsonValue &val : array) {
        if (!val.isObject()) continue;
        QJsonObject obj = val.toObject();
        QString name = obj.value(QStringLiteral("name")).toString();
        QString guid = obj.value(QStringLiteral("guid")).toString();
        QString path = obj.value(QStringLiteral("path")).toString();
        quint32 state = static_cast<quint32>(obj.value(QStringLiteral("state")).toDouble());

        detectedAvs.append(QStringLiteral("%1 (Stan: 0x%2)").arg(name).arg(state, 6, 16, QLatin1Char('0')));

        if (guid.compare(PRODUCT_GUID, Qt::CaseInsensitive) == 0 ||
            name.contains(QStringLiteral("Multi-Guard"), Qt::CaseInsensitive)) {
            report.isVisibleInWsc      = true;
            report.wscDisplayName      = name;
            report.wscReportedState    = state;
            report.wscReportedExePath  = path;
        }
    }

    report.systemAvSummary = detectedAvs.isEmpty()
        ? QStringLiteral("Brak zarejestrowanych produktów antywirusowych w root\\SecurityCenter2.")
        : detectedAvs.join(QStringLiteral(", "));
#endif
}

WscDiagnosticReport WindowsSecurityCenterProvider::runDiagnostics()
{
    WscDiagnosticReport rep;

    // 1. Multi-Guard Engine
    AvEngineInternalState internal = collectInternalState();
    rep.engineRunning = internal.isEngineRunning;

    // 2. Real-Time Protection
    if (internal.isRtpActive && internal.isRtpEnabled) {
        rep.rtpStatusString = QStringLiteral("RUNNING (Ochrona aktywna)");
    } else if (!internal.isRtpEnabled) {
        rep.rtpStatusString = QStringLiteral("STOPPED (Wyłączona w konfiguracji)");
    } else {
        rep.rtpStatusString = QStringLiteral("ERROR / NOT_RUNNING");
    }

    // 3. Signatures
    rep.signatureCount          = internal.sigCount;
    rep.lastSignatureUpdateIso  = internal.lastSigUpdateIso;
    rep.signatureStatusString   = SignatureDb::instance().statusString();

    // 4. Windows Security Center (odczyt z root\SecurityCenter2)
    queryWscStateReadOnly(rep);

    // 5. Backend WSC
    rep.isOfficialBackendAvailable = (m_backend && m_backend->isAvailable());
    rep.isBackendStub              = (!m_backend || m_backend->isStub());
    rep.backendDescription         = m_backend ? m_backend->backendDescription() : QStringLiteral("Brak backendu");

    // 6. Binary Signing
    rep.isBinarySigned = verifyBinarySignature(QCoreApplication::applicationFilePath(), rep.signatureDetails);

    // 7. Usługa systemowa (Windows Service)
    rep.isServiceInstalled = AntivirusService::isServiceInstalled();
    rep.isServiceRunning   = AntivirusService::isServiceRunning();

    // 8. PPL
    checkProcessProtectionLevel(rep.isPplActive, rep.pplStatusString);

    // 9. ELAM
    checkElamStatus(rep.isElamInstalled, rep.elamStatusString);

    // 10. Lista wymagań blokujących pełną rejestrację
    if (rep.isBackendStub) {
        rep.blockingRequirements.append(
            QStringLiteral("Backend WSC jest w trybie STUB — oczekuje na oficjalne SDK Microsoft Virus Initiative (MVI).")
        );
    }
    if (!rep.isBinarySigned) {
        rep.blockingRequirements.append(
            QStringLiteral("Brak ważnego podpisu cyfrowego Authenticode EV (Extended Validation).")
        );
    }
    if (!rep.isPplActive) {
        rep.blockingRequirements.append(
            QStringLiteral("Brak uprawnień Protected Process Light (Antimalware-Light) — wymagany certyfikowany sterownik ELAM.")
        );
    }
    if (!rep.isElamInstalled) {
        rep.blockingRequirements.append(
            QStringLiteral("Sterownik ELAM (Early Launch Anti-Malware) nie jest zainstalowany ani certyfikowany przez WHQL.")
        );
    }
    if (!rep.isVisibleInWsc) {
        rep.blockingRequirements.append(
            QStringLiteral("Multi-Guard nie jest zarejestrowany w Windows Security Center jako zewnętrzny dostawca antywirusa.")
        );
    }

    return rep;
}

QString WscDiagnosticReport::formattedSummary() const
{
    QString out;
    QTextStream ts(&out);

    ts << "=================================================================\n";
    ts << "         MULTI-GUARD ANTIVIRUS - AUDYT I DIAGNOSTYKA SYSTEMOWA   \n";
    ts << "=================================================================\n\n";

    ts << "[1] STAN SILNIKA MULTI-GUARD (ENGINE):\n";
    ts << "    - Silnik AV:                  " << (engineRunning ? "RUNNING" : "STOPPED") << "\n";
    ts << "    - Ochrona Real-Time (RTP):    " << rtpStatusString << "\n\n";

    ts << "[2] BAZA SYGNATUR (SIGNATURES):\n";
    ts << "    - Liczba sygnatur w bazie:    " << signatureCount << "\n";
    ts << "    - Data ostatniej aktualizacji: " << (lastSignatureUpdateIso.isEmpty() ? "BRAK" : lastSignatureUpdateIso) << "\n";
    ts << "    - Status aktualności:         " << signatureStatusString << "\n\n";

    ts << "[3] WINDOWS SECURITY CENTER (WSC - ODCZYT ROOT\\SECURITYCENTER2):\n";
    ts << "    - Widoczny dla Windows WSC:   " << (isVisibleInWsc ? "TAK" : "NIE") << "\n";
    if (isVisibleInWsc) {
        ts << "    - Zgłoszona nazwa:            " << wscDisplayName << "\n";
        ts << "    - Zgłoszony productState:     0x" << QString::number(wscReportedState, 16).rightJustified(6, '0') << "\n";
        ts << "    - Zgłoszona ścieżka EXE:      " << wscReportedExePath << "\n";
    }
    ts << "    - Zarejestrowane produkty AV: " << systemAvSummary << "\n\n";

    ts << "[4] STATUS INTEGRACJI PRODUCENTA (MVI / WSC BACKEND):\n";
    ts << "    - Oficjalny backend WSC:      " << (isOfficialBackendAvailable ? "DOSTĘPNY" : "NIEDOSTĘPNY") << "\n";
    ts << "    - Status implementacji:       " << (isBackendStub ? "STUB (Oczekuje na akredytację MVI)" : "PRODUKCYJNY") << "\n";
    ts << "    - Opis backendu:              " << backendDescription << "\n\n";

    ts << "[5] PODPIS CYFROWY BINARIÓW (AUTHENTICODE):\n";
    ts << "    - Stan podpisu:               " << (isBinarySigned ? "SIGNED" : "UNSIGNED") << "\n";
    ts << "    - Szczegóły certyfikatu:      " << signatureDetails << "\n\n";

    ts << "[6] USŁUGA SYSTEMOWA (WINDOWS SERVICE):\n";
    ts << "    - Usługa zainstalowana:       " << (isServiceInstalled ? "TAK" : "NIE") << "\n";
    ts << "    - Usługa uruchomiona:         " << (isServiceRunning ? "RUNNING" : "STOPPED") << "\n\n";

    ts << "[7] POZIOM OCHRONY PROCESU (PPL / ANTIMALWARE-LIGHT):\n";
    ts << "    - Status PPL:                 " << pplStatusString << "\n\n";

    ts << "[8] STEROWNIK EARLY LAUNCH ANTI-MALWARE (ELAM):\n";
    ts << "    - Status ELAM:                " << elamStatusString << "\n\n";

    ts << "[9] WYMAGANIA BLOKUJĄCE OFICJALNĄ REJESTRACJĘ W WINDOWS SECURITY:\n";
    if (blockingRequirements.isEmpty()) {
        ts << "    - Wszystkie wymagania spełnione. Gotowy do certyfikacji WSC.\n";
    } else {
        for (int i = 0; i < blockingRequirements.size(); ++i) {
            ts << "    [" << (i + 1) << "] " << blockingRequirements[i] << "\n";
        }
    }
    ts << "\n=================================================================\n";

    return out;
}

} // namespace verax
