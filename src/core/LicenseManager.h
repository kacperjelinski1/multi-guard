#pragma once

#include <QObject>
#include <QString>
#include <QSet>
#include <QMap>
#include <QVariant>
#include <QDateTime>

namespace verax {

enum class LicenseTier {
    Unlicensed = 0,
    AV,
    Secure,
    Assist,
    AssistPro,
    AdminFull
};

enum class LicenseCapability {
    BasicScanning = 0,       // Quick, Full, Custom, Memory
    QuarantineAndRepair,     // Quarantine storage & PE disinfection
    RealTimeProtection,      // Real-time file system monitoring
    UsbScanning,             // USB insertion auto-scan
    SignaturesAndUpdates,    // Signature DB updates
    Exclusions,              // Whitelist exclusions
    RansomwareProtection,    // Canary Guard / Sentinel
    WebProtection,           // WebShield & hosts file protection
    SystemRepair,            // Windows component & runtime repair
    FileShredder,            // Multi-pass secure file shredder
    DiskCleaner,             // System optimizer / cleaner
    StartupManager,          // Startup applications manager
    HardwareMonitor,         // CPU/RAM/GPU usage & temperatures
    RemoteRepair,            // Multi-Servis remote support session
    ServiceReports           // HTML station audit report generator
};

enum class LicenseStatus {
    Unlicensed = 0,
    Active,
    Expired,
    Suspended,
    Revoked,
    InvalidSignature,
    DeviceMismatch,
    ProductMismatch,
    NetworkError
};

inline uint qHash(LicenseCapability key, uint seed = 0) noexcept {
    return ::qHash(static_cast<uint>(key), seed);
}
inline uint qHash(LicenseTier key, uint seed = 0) noexcept {
    return ::qHash(static_cast<uint>(key), seed);
}
inline uint qHash(LicenseStatus key, uint seed = 0) noexcept {
    return ::qHash(static_cast<uint>(key), seed);
}

struct LicenseInfo {
    LicenseTier tier = LicenseTier::Unlicensed;
    LicenseStatus status = LicenseStatus::Unlicensed;
    QString licenseKey;
    QString rawToken;
    QString planId;
    QString planName;
    QString identifier;
    QString fingerprint;
    qint64 issuedAt = 0;
    qint64 validUntil = 0;   // 0 = perpetual
    qint64 tokenExpiresAt = 0;
    int graceDays = 0;
    QMap<QString, QVariant> features;
    bool isPerpetual = false;
    QString statusMessage;
};

class LicenseManager : public QObject {
    Q_OBJECT
public:
    static LicenseManager& instance();

    static constexpr const char* KEYGATE_BASE_URL = "https://license.multi-servis.pl";
    static constexpr const char* PRODUCT_ID = "9843d5fd-f090-4534-9d32-d66b64999acb";
    static constexpr const char* PINNED_PUBKEY_HEX = "ab51fb732f453762ba91bacb6fe18dd2b87fce313c4cc88c226b606599fcc1a3";

    // Initialize: loads saved token from storage, validates offline
    void init();

    // Device identification and KeyGate fingerprint
    QString deviceIdentifier() const;
    QString deviceFingerprint() const;
    static QString calculateFingerprint(const QString &identifier, const QString &productId);

    // Online activation (KeyGate POST /api/v1/license/activate)
    struct ActivationResult {
        bool success = false;
        QString errorMessage;
        QString errorCode;
        LicenseTier tier = LicenseTier::Unlicensed;
        LicenseInfo info;
    };
    ActivationResult activateKey(const QString &licenseKey, const QString &label = QString());

    // Online verification (KeyGate POST /api/v1/license/verify)
    ActivationResult verifyOnline(const QString &licenseKey);
    ActivationResult refreshOnline();

    // Offline validation of a token (Ed25519 signature + claims)
    ActivationResult validateToken(const QString &rawToken);

    // Capability check: core function used across GUI and backend
    bool hasCapability(LicenseCapability cap) const;

    // State getters
    bool isValid() const;
    bool isPerpetual() const;
    int daysRemaining() const;
    QString daysRemainingText() const;
    QString expirationDateText() const;
    LicenseTier currentTier() const;
    QString tierName() const;
    const LicenseInfo& currentLicense() const;
    LicenseStatus status() const;

    // Storage
    bool saveToken(const QString &token);
    QString loadSavedToken() const;
    bool saveKey(const QString &key);
    QString loadSavedKey() const;
    void clearLicense();

    // Refresh public key from GET /api/v1/license/pubkey
    bool fetchPublicKey();

signals:
    void licenseChanged(LicenseTier tier, bool isValid);

private:
    LicenseManager();
    ~LicenseManager() override = default;

    void updateCapabilities();
    LicenseTier resolveTier(const QString &planId,
                            const QString &planName,
                            const QMap<QString, QVariant> &features) const;

    LicenseInfo m_license;
    QSet<LicenseCapability> m_activeCapabilities;
    mutable QString m_cachedDeviceId;
    QString m_activePublicKeyHex;
};

} // namespace verax
