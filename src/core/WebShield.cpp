#include "WebShield.h"
#include "Settings.h"
#include "Logger.h"
#include "LicenseManager.h"

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QTextStream>
#include <QRegularExpression>
#include <QProcess>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace verax {

static const char* kShieldStartTag = "# === MULTI-GUARD WEB & PHISHING SHIELD START ===";
static const char* kShieldEndTag   = "# === MULTI-GUARD WEB & PHISHING SHIELD END ===";

WebShield& WebShield::instance()
{
    static WebShield s;
    return s;
}

WebShield::WebShield(QObject *parent)
    : QObject(parent)
{
}

QString WebShield::hostsFilePath() const
{
#ifdef Q_OS_WIN
    const QString winDir = QDir::fromNativeSeparators(qgetenv("SystemRoot"));
    const QString base = winDir.isEmpty() ? QStringLiteral("C:/Windows") : winDir;
    return base + QStringLiteral("/System32/drivers/etc/hosts");
#else
    return QStringLiteral("/etc/hosts");
#endif
}

bool WebShield::createBackup(const QString &hostsPath) const
{
    const QString bakPath = hostsPath + QStringLiteral(".multiguard.bak");
    if (!QFile::exists(bakPath) && QFile::exists(hostsPath)) {
        return QFile::copy(hostsPath, bakPath);
    }
    return true;
}

QStringList WebShield::defaultMaliciousDomains() const
{
    return QStringList{
        // Ransomware C2 & Gateways
        QStringLiteral("lockbit-c2-portal.onion.pet"),
        QStringLiteral("lockbitsupp.com"),
        QStringLiteral("blackcat-alphv-ransom.top"),
        QStringLiteral("alphv-c2-gateway.net"),
        QStringLiteral("contisec-recover-data.biz"),
        QStringLiteral("wannacry-killswitch-test.com"),
        QStringLiteral("revil-support-portal.cc"),
        QStringLiteral("darkside-ransom-c2.org"),
        QStringLiteral("hive-ransom-portal.top"),
        QStringLiteral("medusa-locker-service.to"),
        QStringLiteral("phobos-pay-gateway.info"),

        // Infostealers & Trojans (RedLine, Lumma, Vidar, AgentTesla, AsyncRAT)
        QStringLiteral("redline-stealer-panel.ru"),
        QStringLiteral("lumma-gate-api.cc"),
        QStringLiteral("vidar-c2-collector.top"),
        QStringLiteral("agenttesla-keylogger-drop.net"),
        QStringLiteral("asyncrat-client-stream.biz"),
        QStringLiteral("remcos-rat-dns.org"),
        QStringLiteral("duckdns-dynamic-c2.top"),
        QStringLiteral("dropper-payload-direct.info"),
        QStringLiteral("trojan-downloader-gate.xyz"),

        // Fake Updates & Malicious Browsing
        QStringLiteral("chrome-update-security-patch.com"),
        QStringLiteral("windows-security-alert-warning.info"),
        QStringLiteral("browser-update-urgently.net"),
        QStringLiteral("adobe-flash-player-setup.top"),
        QStringLiteral("java-critical-patch-download.biz"),

        // Banking & Phishing
        QStringLiteral("secure-login-account-verify.com"),
        QStringLiteral("bank-security-confirmation.info"),
        QStringLiteral("paypal-security-center-update.com"),
        QStringLiteral("microsoft-online-verify-alert.net"),
        QStringLiteral("appleid-support-security-check.biz"),
        QStringLiteral("google-auth-verify-security.org"),
        QStringLiteral("crypto-wallet-connect-dapp.xyz"),
        QStringLiteral("metamask-seed-phrase-verify.net")
    };
}

int WebShield::blockedCount() const
{
    return defaultMaliciousDomains().size();
}

bool WebShield::isProtectionActive() const
{
    QFile f(hostsFilePath());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return Settings::instance().webShield();
    }
    const QString content = QString::fromUtf8(f.readAll());
    return content.contains(QLatin1String(kShieldStartTag));
}

bool WebShield::isEnabled() const
{
    return Settings::instance().webShield() && isProtectionActive();
}

void WebShield::setEnabled(bool enable)
{
    if (enable) {
        applyBlocklist();
    } else {
        removeBlocklist();
    }
}

bool WebShield::applyBlocklist()
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::WebProtection)) {
        Logger::warn("WebShield: Pominięto wdrożenie ochrony — brak uprawnień licencyjnych.");
        return false;
    }

    const QString hPath = hostsFilePath();
    createBackup(hPath);

#ifdef Q_OS_WIN
    SetFileAttributesW(reinterpret_cast<LPCWSTR>(hPath.utf16()), FILE_ATTRIBUTE_NORMAL);
#endif
    QFile::setPermissions(hPath, QFile::ReadOwner | QFile::WriteOwner | QFile::ReadGroup | QFile::WriteGroup | QFile::ReadOther);

    QFile inFile(hPath);
    if (!inFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        Logger::error(QStringLiteral("WebShield: Cannot read hosts file at %1 (need Administrator permissions)")
                      .arg(hPath));
        return false;
    }

    QString content = QString::fromUtf8(inFile.readAll());
    inFile.close();

    // If block is already present, strip it first so we have clean state
    if (content.contains(QLatin1String(kShieldStartTag))) {
        QRegularExpression re(QStringLiteral("%1.*?%2\\r?\\n?")
                              .arg(QRegularExpression::escape(QLatin1String(kShieldStartTag)),
                                   QRegularExpression::escape(QLatin1String(kShieldEndTag))),
                              QRegularExpression::DotMatchesEverythingOption);
        content.remove(re);
    }

    // Build new block
    QString block;
    block += QStringLiteral("\n%1\n").arg(QLatin1String(kShieldStartTag));
    block += QStringLiteral("# Multi-Guard Web & Phishing Shield - Blocks known malicious C2 & phishing domains\n");

    const QStringList domains = defaultMaliciousDomains();
    for (const QString &domain : domains) {
        block += QStringLiteral("0.0.0.0 %1\n").arg(domain);
    }
    block += QStringLiteral("%1\n").arg(QLatin1String(kShieldEndTag));

    content += block;

    QFile outFile(hPath);
    if (!outFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        Logger::error(QStringLiteral("WebShield: Cannot write hosts file at %1 (Administrator privileges required)")
                      .arg(hPath));
        return false;
    }

    QTextStream ts(&outFile);
    ts.setCodec("UTF-8");
    ts << content;
    outFile.close();

#ifdef Q_OS_WIN
    // Flush Windows DNS resolver cache immediately so new DNS blocks apply
    QProcess::execute(QStringLiteral("ipconfig"), {QStringLiteral("/flushdns")});
#endif

    Logger::info(QStringLiteral("WebShield: Successfully enabled. Blocked %1 malicious domains.")
                 .arg(domains.size()));
    emit statusChanged(true);
    return true;
}

bool WebShield::removeBlocklist()
{
    const QString hPath = hostsFilePath();

#ifdef Q_OS_WIN
    SetFileAttributesW(reinterpret_cast<LPCWSTR>(hPath.utf16()), FILE_ATTRIBUTE_NORMAL);
#endif
    QFile::setPermissions(hPath, QFile::ReadOwner | QFile::WriteOwner | QFile::ReadGroup | QFile::WriteGroup | QFile::ReadOther);

    QFile inFile(hPath);
    if (!inFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }

    QString content = QString::fromUtf8(inFile.readAll());
    inFile.close();

    if (!content.contains(QLatin1String(kShieldStartTag))) {
        emit statusChanged(false);
        return true;
    }

    QRegularExpression re(QStringLiteral("\\n?%1.*?%2\\r?\\n?")
                          .arg(QRegularExpression::escape(QLatin1String(kShieldStartTag)),
                               QRegularExpression::escape(QLatin1String(kShieldEndTag))),
                          QRegularExpression::DotMatchesEverythingOption);
    content.remove(re);

    QFile outFile(hPath);
    if (!outFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        Logger::error(QStringLiteral("WebShield: Failed to restore clean hosts file at %1").arg(hPath));
        return false;
    }

    QTextStream ts(&outFile);
    ts.setCodec("UTF-8");
    ts << content;
    outFile.close();

#ifdef Q_OS_WIN
    // Flush Windows DNS resolver cache immediately
    QProcess::execute(QStringLiteral("ipconfig"), {QStringLiteral("/flushdns")});
#endif

    Logger::info("WebShield: Successfully disabled. Cleaned hosts blocklist.");
    emit statusChanged(false);
    return true;
}

} // namespace verax
