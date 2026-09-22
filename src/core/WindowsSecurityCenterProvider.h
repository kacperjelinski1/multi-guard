#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <memory>
#include "SignatureDb.h"

namespace verax {

/**
 * @brief Wewnętrzny stan antywirusa Multi-Guard (Multi-Guard Internal State).
 * 
 * Całkowicie niezależny od mechanizmów systemu Windows.
 */
struct AvEngineInternalState {
    bool isEngineRunning       = false;
    bool isRtpActive           = false;
    bool isRtpEnabled          = false;
    SignatureStatus sigStatus  = SignatureStatus::UPDATE_REQUIRED;
    int  sigCount              = 0;
    QString lastSigUpdateIso;
    bool isLicenseValid        = false;
    QString licenseTier;
    bool hasComponentFailure   = false;
    QString failureReason;
    bool isAttentionRequired   = false;
    bool isUpdatingSignatures  = false;

    bool isFullyProtected() const {
        return isEngineRunning && isRtpActive && isRtpEnabled &&
               (sigStatus == SignatureStatus::UP_TO_DATE) && isLicenseValid && !hasComponentFailure;
    }
};

/**
 * @brief Znormalizowany stan dostawcy dla Windows Security Center.
 */
enum class WscNormalizedState {
    Active,            // RTP działa, sygnatury aktualne, silnik sprawny
    Snoozed,           // Ochrona tymczasowo wyłączona / zatrzymana przez użytkownika
    OutOfDate,         // Sygnatury przestarzałe (> 7 dni)
    AttentionRequired, // Wystąpił błąd, brak licencji lub uszkodzony komponent
    Stopped            // Usługa wyłączona (aplikacja zamknięta / usługa zatrzymana)
};

/**
 * @brief Stan przekazywany do warstwy komunikacji z Windows Security Center.
 */
struct WscReportedState {
    WscNormalizedState normalizedState = WscNormalizedState::Stopped;
    bool isRtpEnabled                  = false;
    bool areSignaturesUpToDate         = false;
    QString displayName;
    QString executablePath;
    QString engineVersion;

    // Standardowa 32-bitowa bitmaska Microsoft WSC (dla celów informacyjnych/diagnostycznych)
    quint32 calculateStandardProductStateBitmask() const;
};

/**
 * @brief Wyniki testu diagnostycznego Windows Security Center i gotowości MVI/PPL.
 */
struct WscDiagnosticReport {
    // 1. Multi-Guard Engine
    bool engineRunning = false;

    // 2. Real-Time Protection
    QString rtpStatusString; // "RUNNING", "STOPPED", "ERROR"

    // 3. Signatures
    int signatureCount = 0;
    QString lastSignatureUpdateIso;
    QString signatureStatusString; // "UP_TO_DATE", "OUT_OF_DATE", etc.

    // 4. Windows Security Center (odczyt z root\SecurityCenter2)
    bool isVisibleInWsc = false;
    QString wscDisplayName;
    quint32 wscReportedState = 0;
    QString wscReportedExePath;
    QString systemAvSummary;

    // 5. Status backendu WSC
    bool isOfficialBackendAvailable = false;
    bool isBackendStub = true;
    QString backendDescription;

    // 6. Binary Signing (Authenticode)
    bool isBinarySigned = false;
    QString signatureDetails;

    // 7. Usługa systemowa (Windows Service)
    bool isServiceInstalled = false;
    bool isServiceRunning = false;

    // 8. Poziom ochrony procesu (PPL)
    bool isPplActive = false; // "ENABLED", "NOT_AVAILABLE", "NOT_CERTIFIED"
    QString pplStatusString;

    // 9. Sterownik ELAM
    bool isElamInstalled = false;
    QString elamStatusString;

    // 10. Lista wymagań blokujących pełną rejestrację
    QStringList blockingRequirements;

    QString formattedSummary() const;
};

/**
 * @brief Interfejs backendu integracji Windows Security Center.
 * 
 * TODO(MVI): Official Microsoft AV provider integration required here.
 * Po uzyskaniu akredytacji MVI i certyfikacji WHQL ELAM, ten interfejs
 * implementuje bezpośrednie wywołania COM do wscapi.dll (IWscProduct / IWscProduct2).
 */
class IWscRegistrationBackend {
public:
    virtual ~IWscRegistrationBackend() = default;
    virtual bool isAvailable() const = 0;
    virtual bool isStub() const = 0;
    virtual bool registerProvider(const QString &exePath, const WscReportedState &state) = 0;
    virtual bool updateState(const WscReportedState &state) = 0;
    virtual bool unregisterProvider() = 0;
    virtual QString backendDescription() const = 0;
};

/**
 * @brief WindowsSecurityCenterProvider
 * 
 * Abstrakcyjna warstwa integracji oddzielająca wewnętrzny stan Multi-Guard
 * od mechanizmu przekazywania tego stanu do Windows Security.
 */
class WindowsSecurityCenterProvider : public QObject {
    Q_OBJECT
public:
    static WindowsSecurityCenterProvider& instance();

    static const QString PRODUCT_GUID;
    static const QString DISPLAY_NAME;

    // Pobiera aktualny, rzeczywisty stan wewnętrzny silnika
    AvEngineInternalState collectInternalState() const;

    // Mapuje wewnętrzny stan Multi-Guard na format WSC
    WscReportedState mapToWscState(const AvEngineInternalState &internal) const;

    // Przeprowadza pełną, wyłącznie odczytową diagnostykę środowiska
    WscDiagnosticReport runDiagnostics();

    // Odświeża stan w Windows Security (deleguje do aktywnego backendu)
    bool refreshStatus();

    // Wyrejestrowanie (np. przy deinstalacji)
    bool unregisterProduct();

    // Zgłoszenie zatrzymania ochrony (np. przy zamykaniu usługi)
    bool notifyShutdown();

    // Wstrzyknięcie backendu (np. oficjalnego MVI po certyfikacji)
    void setBackend(std::unique_ptr<IWscRegistrationBackend> backend);

public slots:
    void onRtpStatusChanged(bool active);
    void onSignaturesUpdated(int added, int total, const QString &error);

private:
    explicit WindowsSecurityCenterProvider(QObject *parent = nullptr);
    ~WindowsSecurityCenterProvider() override;

    // Bezpieczny, wyłącznie odczytowy wgląd w stan WSC (brak modyfikacji WMI)
    void queryWscStateReadOnly(WscDiagnosticReport &report);

    // Weryfikacja podpisu Authenticode
    bool verifyBinarySignature(const QString &filePath, QString &detailsOut);

    // Weryfikacja poziomu ochrony procesu PPL
    bool checkProcessProtectionLevel(bool &isPpl, QString &statusString);

    // Weryfikacja stanu sterownika ELAM
    bool checkElamStatus(bool &installed, QString &statusString);

    std::unique_ptr<IWscRegistrationBackend> m_backend;
};

} // namespace verax
