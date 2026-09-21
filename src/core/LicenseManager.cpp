#include "LicenseManager.h"
#include "Ed25519.h"
#include "Logger.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QEventLoop>
#include <QStandardPaths>
#include <QUrl>
#include <QSslSocket>

#ifdef Q_OS_WIN
#include <windows.h>
#include <QSettings>
#endif

namespace verax {

LicenseManager& LicenseManager::instance()
{
    static LicenseManager s_inst;
    return s_inst;
}

LicenseManager::LicenseManager()
    : m_activePublicKeyHex(QString::fromLatin1(PINNED_PUBKEY_HEX))
{
}

void LicenseManager::init()
{
    Logger::info("LicenseManager: Initializing licensing subsystem...");

    Logger::info(QStringLiteral("LicenseManager: SSL supportsSsl=%1, build=%2, runtime=%3")
                     .arg(QSslSocket::supportsSsl() ? QStringLiteral("YES") : QStringLiteral("NO"),
                          QSslSocket::sslLibraryBuildVersionString(),
                          QSslSocket::sslLibraryVersionString()));
    if (!QSslSocket::supportsSsl()) {
        Logger::warn("LicenseManager: OpenSSL runtime libraries not found! TLS/HTTPS requests will fail!");
    }

    // Try loading cached public key if present, otherwise pinned key is used
    QString savedToken = loadSavedToken();
    if (!savedToken.isEmpty()) {
        ActivationResult res = validateToken(savedToken);
        if (res.success) {
            m_license = res.info;
            m_license.rawToken = savedToken;
            m_license.licenseKey = loadSavedKey();
            updateCapabilities();
            Logger::info(QStringLiteral("LicenseManager: Valid license loaded. Tier=%1, Perpetual=%2")
                             .arg(tierName())
                             .arg(isPerpetual() ? "true" : "false"));
            emit licenseChanged(m_license.tier, true);
            return;
        } else {
            Logger::warn(QStringLiteral("LicenseManager: Saved token failed validation: %1 (%2)")
                             .arg(res.errorMessage, res.errorCode));
        }
    } else {
        // If no saved token exists yet, check if a license key was saved during installation
        QString savedKey = loadSavedKey();
        if (!savedKey.isEmpty()) {
            Logger::info("LicenseManager: Found saved license key from installer, attempting auto-activation...");
            ActivationResult res = activateKey(savedKey);
            if (res.success) {
                Logger::info("LicenseManager: Initial auto-activation succeeded!");
                return;
            } else {
                Logger::warn(QStringLiteral("LicenseManager: Initial auto-activation failed: %1 (%2)")
                                 .arg(res.errorMessage, res.errorCode));
            }
        }
    }

    // Unlicensed state
    m_license = LicenseInfo();
    m_license.status = LicenseStatus::Unlicensed;
    updateCapabilities();
    Logger::info("LicenseManager: Application running in unlicensed mode.");
    emit licenseChanged(LicenseTier::Unlicensed, false);
}

QString LicenseManager::deviceIdentifier() const
{
    if (!m_cachedDeviceId.isEmpty()) {
        return m_cachedDeviceId;
    }

#ifdef Q_OS_WIN
    // 1) Read Windows MachineGuid from HKLM
    QSettings reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography", QSettings::NativeFormat);
    QString machineGuid = reg.value("MachineGuid").toString().trimmed();
    if (!machineGuid.isEmpty()) {
        m_cachedDeviceId = machineGuid;
        return m_cachedDeviceId;
    }
#endif

    // 2) Fallback: persistent device ID file
    QString fallbackDir = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/Multi-Guard";
    QDir().mkpath(fallbackDir);
    QString idFilePath = fallbackDir + "/device.id";

    QFile idFile(idFilePath);
    if (idFile.open(QIODevice::ReadOnly)) {
        QString savedId = QString::fromUtf8(idFile.readAll()).trimmed();
        idFile.close();
        if (!savedId.isEmpty()) {
            m_cachedDeviceId = savedId;
            return m_cachedDeviceId;
        }
    }

    // Generate stable fallback identifier based on host and user
    QByteArray combined = QSysInfo::machineUniqueId();
    if (combined.isEmpty()) {
        combined = QSysInfo::prettyProductName().toUtf8() + ":" + QSysInfo::machineHostName().toUtf8();
    }
    QString newId = QCryptographicHash::hash(combined, QCryptographicHash::Sha256).toHex().left(32);

    if (idFile.open(QIODevice::WriteOnly)) {
        idFile.write(newId.toUtf8());
        idFile.close();
    }

    m_cachedDeviceId = newId;
    return m_cachedDeviceId;
}

QString LicenseManager::calculateFingerprint(const QString &identifier, const QString &productId)
{
    // SHA256(identifier + ":" + product_id) -> first 8 bytes -> lowercase hex (16 chars)
    QByteArray input = identifier.toUtf8() + ":" + productId.toUtf8();
    QByteArray hash = QCryptographicHash::hash(input, QCryptographicHash::Sha256);
    return hash.left(8).toHex().toLower();
}

QString LicenseManager::deviceFingerprint() const
{
    return calculateFingerprint(deviceIdentifier(), QString::fromLatin1(PRODUCT_ID));
}

LicenseManager::ActivationResult LicenseManager::activateKey(const QString &licenseKey, const QString &label)
{
    ActivationResult result;
    QString key = licenseKey.trimmed();
    if (key.isEmpty()) {
        result.errorMessage = tr("Klucz licencyjny nie może być pusty.");
        result.errorCode = QStringLiteral("EMPTY_KEY");
        return result;
    }

    QString id = deviceIdentifier();
    QString lbl = label.isEmpty() ? QSysInfo::machineHostName() : label;

    QJsonObject reqObj;
    reqObj["license_key"] = key;
    reqObj["identifier"] = id;
    reqObj["identifier_type"] = QStringLiteral("device");
    reqObj["label"] = lbl;

    QByteArray postData = QJsonDocument(reqObj).toJson(QJsonDocument::Compact);

    QNetworkAccessManager nam;
    QNetworkRequest request(QUrl(QStringLiteral("%1/api/v1/license/activate").arg(KEYGATE_BASE_URL)));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Accept", "application/json");

    QEventLoop loop;
    QNetworkReply *reply = nam.post(request, postData);
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    if (reply->error() != QNetworkReply::NoError && reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 0) {
        result.errorMessage = tr("Błąd połączenia z serwerem licencji KeyGate: %1").arg(reply->errorString());
        result.errorCode = QStringLiteral("NETWORK_ERROR");
        reply->deleteLater();
        return result;
    }

    QByteArray respData = reply->readAll();
    reply->deleteLater();

    QJsonParseError parseErr;
    QJsonDocument doc = QJsonDocument::fromJson(respData, &parseErr);
    if (parseErr.error != QJsonParseError::NoError) {
        result.errorMessage = tr("Nieprawidłowa odpowiedź serwera licencji.");
        result.errorCode = QStringLiteral("PARSE_ERROR");
        return result;
    }

    QJsonObject root = doc.object();
    bool success = root.value("success").toBool();

    if (!success) {
        QJsonObject errObj = root.value("error").toObject();
        result.errorCode = errObj.value("code").toString();
        result.errorMessage = errObj.value("message").toString();
        if (result.errorMessage.isEmpty()) {
            result.errorMessage = tr("Aktywacja licencji nie powiodła się.");
        }
        return result;
    }

    QJsonObject dataObj = root.value("data").toObject();
    QString token = dataObj.value("token").toString();
    if (token.isEmpty()) {
        result.errorMessage = tr("Brak tokena w odpowiedzi serwera.");
        result.errorCode = QStringLiteral("NO_TOKEN");
        return result;
    }

    // Validate token offline with Ed25519
    ActivationResult valRes = validateToken(token);
    if (!valRes.success) {
        return valRes;
    }

    // Save and commit
    saveToken(token);
    saveKey(key);
    m_license = valRes.info;
    m_license.licenseKey = key;
    m_license.rawToken = token;
    updateCapabilities();

    emit licenseChanged(m_license.tier, true);

    result.success = true;
    result.tier = m_license.tier;
    result.info = m_license;
    return result;
}

LicenseManager::ActivationResult LicenseManager::verifyOnline(const QString &licenseKey)
{
    ActivationResult result;
    QString key = licenseKey.trimmed();
    if (key.isEmpty()) {
        key = m_license.licenseKey;
    }
    if (key.isEmpty()) {
        result.errorMessage = tr("Brak klucza do weryfikacji.");
        result.errorCode = QStringLiteral("NO_KEY");
        return result;
    }

    QJsonObject reqObj;
    reqObj["license_key"] = key;
    reqObj["identifier"] = deviceIdentifier();

    QByteArray postData = QJsonDocument(reqObj).toJson(QJsonDocument::Compact);

    QNetworkAccessManager nam;
    QNetworkRequest request(QUrl(QStringLiteral("%1/api/v1/license/verify").arg(KEYGATE_BASE_URL)));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QEventLoop loop;
    QNetworkReply *reply = nam.post(request, postData);
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    if (reply->error() != QNetworkReply::NoError && reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 0) {
        result.errorMessage = reply->errorString();
        result.errorCode = QStringLiteral("NETWORK_ERROR");
        reply->deleteLater();
        return result;
    }

    QByteArray respData = reply->readAll();
    reply->deleteLater();

    QJsonDocument doc = QJsonDocument::fromJson(respData);
    QJsonObject root = doc.object();
    if (!root.value("success").toBool()) {
        QJsonObject errObj = root.value("error").toObject();
        result.errorCode = errObj.value("code").toString();
        result.errorMessage = errObj.value("message").toString();
        return result;
    }

    QJsonObject dataObj = root.value("data").toObject();
    QString token = dataObj.value("token").toString();

    ActivationResult valRes = validateToken(token);
    if (!valRes.success) {
        return valRes;
    }

    saveToken(token);
    saveKey(key);
    m_license = valRes.info;
    m_license.licenseKey = key;
    m_license.rawToken = token;
    updateCapabilities();

    emit licenseChanged(m_license.tier, true);

    result.success = true;
    result.tier = m_license.tier;
    result.info = m_license;
    return result;
}

LicenseManager::ActivationResult LicenseManager::refreshOnline()
{
    QString key = m_license.licenseKey;
    if (key.isEmpty()) {
        key = loadSavedKey();
    }
    if (key.isEmpty()) {
        ActivationResult res;
        res.errorMessage = tr("Brak zapisanego klucza licencyjnego do odświeżenia.");
        res.errorCode = QStringLiteral("NO_KEY");
        return res;
    }
    return verifyOnline(key);
}

LicenseManager::ActivationResult LicenseManager::validateToken(const QString &rawToken)
{
    ActivationResult res;
    QString token = rawToken.trimmed();
    int dotIdx = token.lastIndexOf('.');
    if (dotIdx <= 0 || dotIdx >= token.size() - 1) {
        res.errorMessage = tr("Nieprawidłowy format tokena (brak podpisu).");
        res.errorCode = QStringLiteral("INVALID_TOKEN_FORMAT");
        return res;
    }

    QString b64Payload = token.left(dotIdx);
    QString b64Sig = token.mid(dotIdx + 1);

    QByteArray signature = Ed25519::base64UrlDecode(b64Sig);
    if (signature.size() != Ed25519::SignatureSize) {
        res.errorMessage = tr("Nieprawidłowa długość podpisu Ed25519.");
        res.errorCode = QStringLiteral("INVALID_SIGNATURE_LENGTH");
        return res;
    }

    QByteArray pubKey = Ed25519::publicKeyFromHex(m_activePublicKeyHex);
    if (pubKey.size() != Ed25519::PublicKeySize) {
        res.errorMessage = tr("Błąd wewnętrzny klucza weryfikującego.");
        res.errorCode = QStringLiteral("INVALID_PUBKEY");
        return res;
    }

    // Ed25519 verification: signed region is the exact ASCII bytes of base64url(payload)
    if (!Ed25519::verify(b64Payload.toUtf8(), signature, pubKey)) {
        res.errorMessage = tr("Podpis cyfrowy tokena jest nieprawidłowy lub token został zmodyfikowany.");
        res.errorCode = QStringLiteral("INVALID_SIGNATURE");
        return res;
    }

    // Decode and parse payload
    QByteArray payloadBytes = Ed25519::base64UrlDecode(b64Payload);
    QJsonParseError jsonErr;
    QJsonDocument doc = QJsonDocument::fromJson(payloadBytes, &jsonErr);
    if (jsonErr.error != QJsonParseError::NoError || !doc.isObject()) {
        res.errorMessage = tr("Błąd dekodowania danych licencji.");
        res.errorCode = QStringLiteral("INVALID_PAYLOAD_JSON");
        return res;
    }

    QJsonObject p = doc.object();
    LicenseInfo info;
    info.rawToken = token;
    info.planId = p.value("pln").toString();
    info.identifier = p.value("did").toString();
    info.fingerprint = p.value("fpr").toString();
    info.issuedAt = p.value("iat").toVariant().toLongLong();
    info.validUntil = p.value("vun").toVariant().toLongLong();
    info.tokenExpiresAt = p.value("exp").toVariant().toLongLong();
    info.graceDays = p.value("grc").toInt();
    info.statusMessage = p.value("sts").toString();

    QJsonObject ftrObj = p.value("ftr").toObject();
    for (auto it = ftrObj.begin(); it != ftrObj.end(); ++it) {
        info.features.insert(it.key(), it.value().toVariant());
    }

    // 1) Validate Product ID
    QString tokenPid = p.value("pid").toString();
    if (tokenPid.compare(QString::fromLatin1(PRODUCT_ID), Qt::CaseInsensitive) != 0) {
        res.errorMessage = tr("Identyfikator produktu w licencji nie zgadza się z Multi-Guard.");
        res.errorCode = QStringLiteral("PRODUCT_MISMATCH");
        return res;
    }

    // 2) Validate Device Binding (Identifier & Fingerprint)
    QString currentId = deviceIdentifier();
    if (!info.identifier.isEmpty() && info.identifier.compare(currentId, Qt::CaseInsensitive) != 0) {
        res.errorMessage = tr("Licencja jest przypisana do innego urządzenia.");
        res.errorCode = QStringLiteral("DEVICE_MISMATCH");
        return res;
    }

    QString currentFpr = deviceFingerprint();
    if (!info.fingerprint.isEmpty() && info.fingerprint.compare(currentFpr, Qt::CaseInsensitive) != 0) {
        res.errorMessage = tr("Fingerprint urządzenia nie zgadza się z tokenem.");
        res.errorCode = QStringLiteral("FINGERPRINT_MISMATCH");
        return res;
    }

    // 3) Validate Status
    if (info.statusMessage == QLatin1String("suspended")) {
        res.errorMessage = tr("Licencja została zawieszona.");
        res.errorCode = QStringLiteral("LICENSE_SUSPENDED");
        return res;
    }
    if (info.statusMessage == QLatin1String("revoked")) {
        res.errorMessage = tr("Licencja została unieważniona (odwołana).");
        res.errorCode = QStringLiteral("LICENSE_REVOKED");
        return res;
    }
    if (info.statusMessage != QLatin1String("active") && info.statusMessage != QLatin1String("activated")) {
        res.errorMessage = tr("Status licencji nie jest aktywny: %1").arg(info.statusMessage);
        res.errorCode = QStringLiteral("LICENSE_INACTIVE");
        return res;
    }

    // 4) Resolve Tier
    info.tier = resolveTier(info.planId, info.planName, info.features);
    info.isPerpetual = (info.tier == LicenseTier::AdminFull) || (info.validUntil == 0);

    // 5) Check Expiration
    qint64 now = QDateTime::currentSecsSinceEpoch();
    if (!info.isPerpetual && info.validUntil > 0) {
        qint64 graceSeconds = static_cast<qint64>(info.graceDays) * 86400;
        if (now > (info.validUntil + graceSeconds)) {
            res.errorMessage = tr("Licencja wygasła w dniu %1.")
                                   .arg(QDateTime::fromSecsSinceEpoch(info.validUntil).toString("yyyy-MM-dd HH:mm"));
            res.errorCode = QStringLiteral("LICENSE_EXPIRED");
            return res;
        }
    }

    info.status = LicenseStatus::Active;
    res.success = true;
    res.tier = info.tier;
    res.info = info;
    return res;
}

LicenseTier LicenseManager::resolveTier(const QString &planId,
                                        const QString &planName,
                                        const QMap<QString, QVariant> &features) const
{
    // Check explicit feature override first
    if (features.contains("tier")) {
        QString t = features.value("tier").toString().toLower();
        if (t == "admin_full" || t == "admin") return LicenseTier::AdminFull;
        if (t == "assist_pro") return LicenseTier::AssistPro;
        if (t == "assist") return LicenseTier::Assist;
        if (t == "secure") return LicenseTier::Secure;
        if (t == "av") return LicenseTier::AV;
    }

    QString combined = (planId + " " + planName).toLower();

    if (combined.contains("admin")) {
        return LicenseTier::AdminFull;
    }
    if (combined.contains("assist") && combined.contains("pro")) {
        return LicenseTier::AssistPro;
    }
    if (combined.contains("assist")) {
        return LicenseTier::Assist;
    }
    if (combined.contains("secure")) {
        return LicenseTier::Secure;
    }
    if (combined.contains("av")) {
        return LicenseTier::AV;
    }

    // Default fallback if activated under this product
    return LicenseTier::AV;
}

void LicenseManager::updateCapabilities()
{
    m_activeCapabilities.clear();

    if (m_license.status != LicenseStatus::Active) {
        return;
    }

    switch (m_license.tier) {
    case LicenseTier::AV:
        m_activeCapabilities.insert(LicenseCapability::BasicScanning);
        m_activeCapabilities.insert(LicenseCapability::QuarantineAndRepair);
        m_activeCapabilities.insert(LicenseCapability::RealTimeProtection);
        m_activeCapabilities.insert(LicenseCapability::UsbScanning);
        m_activeCapabilities.insert(LicenseCapability::SignaturesAndUpdates);
        m_activeCapabilities.insert(LicenseCapability::Exclusions);
        break;

    case LicenseTier::Secure:
        // All of AV
        m_activeCapabilities.insert(LicenseCapability::BasicScanning);
        m_activeCapabilities.insert(LicenseCapability::QuarantineAndRepair);
        m_activeCapabilities.insert(LicenseCapability::RealTimeProtection);
        m_activeCapabilities.insert(LicenseCapability::UsbScanning);
        m_activeCapabilities.insert(LicenseCapability::SignaturesAndUpdates);
        m_activeCapabilities.insert(LicenseCapability::Exclusions);
        // Additional security modules
        m_activeCapabilities.insert(LicenseCapability::RansomwareProtection);
        m_activeCapabilities.insert(LicenseCapability::WebProtection);
        m_activeCapabilities.insert(LicenseCapability::SystemRepair);
        m_activeCapabilities.insert(LicenseCapability::FileShredder);
        break;

    case LicenseTier::Assist:
        // Architecture prepared; capabilities will be configured later per user instructions
        break;

    case LicenseTier::AssistPro:
        // Architecture prepared; capabilities will be configured later per user instructions
        break;

    case LicenseTier::AdminFull:
        // All capabilities enabled
        m_activeCapabilities.insert(LicenseCapability::BasicScanning);
        m_activeCapabilities.insert(LicenseCapability::QuarantineAndRepair);
        m_activeCapabilities.insert(LicenseCapability::RealTimeProtection);
        m_activeCapabilities.insert(LicenseCapability::UsbScanning);
        m_activeCapabilities.insert(LicenseCapability::SignaturesAndUpdates);
        m_activeCapabilities.insert(LicenseCapability::Exclusions);
        m_activeCapabilities.insert(LicenseCapability::RansomwareProtection);
        m_activeCapabilities.insert(LicenseCapability::WebProtection);
        m_activeCapabilities.insert(LicenseCapability::SystemRepair);
        m_activeCapabilities.insert(LicenseCapability::FileShredder);
        m_activeCapabilities.insert(LicenseCapability::DiskCleaner);
        m_activeCapabilities.insert(LicenseCapability::StartupManager);
        m_activeCapabilities.insert(LicenseCapability::HardwareMonitor);
        m_activeCapabilities.insert(LicenseCapability::RemoteRepair);
        m_activeCapabilities.insert(LicenseCapability::ServiceReports);
        break;

    default:
        break;
    }

    // Apply dynamic feature entitlements overrides from KeyGate
    if (m_license.features.value("basic_scanning").toBool())
        m_activeCapabilities.insert(LicenseCapability::BasicScanning);
    if (m_license.features.value("realtime_protection").toBool())
        m_activeCapabilities.insert(LicenseCapability::RealTimeProtection);
    if (m_license.features.value("ransomware_protection").toBool())
        m_activeCapabilities.insert(LicenseCapability::RansomwareProtection);
    if (m_license.features.value("web_protection").toBool())
        m_activeCapabilities.insert(LicenseCapability::WebProtection);
    if (m_license.features.value("system_repair").toBool())
        m_activeCapabilities.insert(LicenseCapability::SystemRepair);
    if (m_license.features.value("file_shredder").toBool())
        m_activeCapabilities.insert(LicenseCapability::FileShredder);
    if (m_license.features.value("disk_cleaner").toBool())
        m_activeCapabilities.insert(LicenseCapability::DiskCleaner);
    if (m_license.features.value("startup_manager").toBool())
        m_activeCapabilities.insert(LicenseCapability::StartupManager);
    if (m_license.features.value("hardware_monitor").toBool())
        m_activeCapabilities.insert(LicenseCapability::HardwareMonitor);
    if (m_license.features.value("remote_repair").toBool())
        m_activeCapabilities.insert(LicenseCapability::RemoteRepair);
    if (m_license.features.value("service_reports").toBool())
        m_activeCapabilities.insert(LicenseCapability::ServiceReports);
}

bool LicenseManager::hasCapability(LicenseCapability cap) const
{
    return m_activeCapabilities.contains(cap);
}

bool LicenseManager::isValid() const
{
    return (m_license.status == LicenseStatus::Active);
}

bool LicenseManager::isPerpetual() const
{
    return m_license.isPerpetual;
}

int LicenseManager::daysRemaining() const
{
    if (m_license.status != LicenseStatus::Active) {
        return 0;
    }
    if (m_license.isPerpetual || m_license.validUntil <= 0) {
        return -1;
    }
    qint64 now = QDateTime::currentSecsSinceEpoch();
    qint64 diff = m_license.validUntil - now;
    if (diff <= 0) {
        return 0;
    }
    return static_cast<int>((diff + 86399) / 86400);
}

QString LicenseManager::daysRemainingText() const
{
    if (m_license.status != LicenseStatus::Active) {
        return tr("Wygasła (0 dni)");
    }
    if (m_license.isPerpetual || m_license.validUntil <= 0) {
        return tr("Bezterminowa (Perpetual)");
    }
    int d = daysRemaining();
    if (d <= 0) {
        return tr("Wygasa dzisiaj!");
    } else if (d == 1) {
        return tr("Pozostał 1 dzień");
    } else if (d >= 2 && d <= 4) {
        return tr("Pozostały %1 dni").arg(d);
    } else {
        return tr("Pozostało %1 dni").arg(d);
    }
}

QString LicenseManager::expirationDateText() const
{
    if (m_license.status != LicenseStatus::Active) {
        return tr("Brak aktywnej licencji");
    }
    if (m_license.isPerpetual || m_license.validUntil <= 0) {
        return tr("Bezterminowa");
    }
    return QDateTime::fromSecsSinceEpoch(m_license.validUntil).toString(QStringLiteral("yyyy-MM-dd HH:mm"));
}

LicenseTier LicenseManager::currentTier() const
{
    return m_license.tier;
}

QString LicenseManager::tierName() const
{
    switch (m_license.tier) {
    case LicenseTier::AV:         return QStringLiteral("Multi-Guard AV");
    case LicenseTier::Secure:     return QStringLiteral("Multi-Guard Secure");
    case LicenseTier::Assist:     return QStringLiteral("Multi-Guard Assist");
    case LicenseTier::AssistPro:  return QStringLiteral("Multi-Guard Assist PRO");
    case LicenseTier::AdminFull:  return QStringLiteral("ADMIN FULL (Perpetual)");
    default:                      return QStringLiteral("Brak licencji");
    }
}

const LicenseInfo& LicenseManager::currentLicense() const
{
    return m_license;
}

bool LicenseManager::saveToken(const QString &token)
{
    QString dirPath = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/Multi-Guard";
    QDir().mkpath(dirPath);
    QString filePath = dirPath + "/license.token";

    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        file.write(token.toUtf8());
        file.close();
    }

#ifdef Q_OS_WIN
    // Also backup in registry
    QSettings reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Multi-Guard", QSettings::NativeFormat);
    reg.setValue("LicenseToken", token);
#endif

    return true;
}

QString LicenseManager::loadSavedToken() const
{
    // Try file first
    QString dirPath = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/Multi-Guard";
    QString filePath = dirPath + "/license.token";
    QFile file(filePath);
    if (file.open(QIODevice::ReadOnly)) {
        QString t = QString::fromUtf8(file.readAll()).trimmed();
        file.close();
        if (!t.isEmpty()) {
            return t;
        }
    }

#ifdef Q_OS_WIN
    // Fallback to registry
    QSettings reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Multi-Guard", QSettings::NativeFormat);
    QString t = reg.value("LicenseToken").toString().trimmed();
    if (!t.isEmpty()) {
        return t;
    }
#endif

    return QString();
}

bool LicenseManager::saveKey(const QString &key)
{
    QString dirPath = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/Multi-Guard";
    QDir().mkpath(dirPath);
    QString filePath = dirPath + "/license.key";

    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        file.write(key.trimmed().toUtf8());
        file.close();
    }

#ifdef Q_OS_WIN
    QSettings reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Multi-Guard", QSettings::NativeFormat);
    reg.setValue("LicenseKey", key.trimmed());
#endif

    return true;
}

QString LicenseManager::loadSavedKey() const
{
    QString dirPath = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/Multi-Guard";
    QString filePath = dirPath + "/license.key";
    QFile file(filePath);
    if (file.open(QIODevice::ReadOnly)) {
        QString k = QString::fromUtf8(file.readAll()).trimmed();
        file.close();
        if (!k.isEmpty()) {
            return k;
        }
    }

#ifdef Q_OS_WIN
    QSettings reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Multi-Guard", QSettings::NativeFormat);
    QString k = reg.value("LicenseKey").toString().trimmed();
    if (!k.isEmpty()) {
        return k;
    }
#endif

    return QString();
}

void LicenseManager::clearLicense()
{
    m_license = LicenseInfo();
    m_activeCapabilities.clear();

    QString dirPath = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/Multi-Guard";
    QFile::remove(dirPath + "/license.token");
    QFile::remove(dirPath + "/license.key");

#ifdef Q_OS_WIN
    QSettings reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Multi-Guard", QSettings::NativeFormat);
    reg.remove("LicenseToken");
    reg.remove("LicenseKey");
#endif

    emit licenseChanged(LicenseTier::Unlicensed, false);
}

bool LicenseManager::fetchPublicKey()
{
    QNetworkAccessManager nam;
    QNetworkRequest request(QUrl(QStringLiteral("%1/api/v1/license/pubkey").arg(KEYGATE_BASE_URL)));

    QEventLoop loop;
    QNetworkReply *reply = nam.get(request);
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    if (reply->error() == QNetworkReply::NoError) {
        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QString pubHex = doc.object().value("data").toObject().value("public_key").toString().trimmed();
        if (!pubHex.isEmpty()) {
            m_activePublicKeyHex = pubHex;
            reply->deleteLater();
            return true;
        }
    }
    reply->deleteLater();
    return false;
}

} // namespace verax
