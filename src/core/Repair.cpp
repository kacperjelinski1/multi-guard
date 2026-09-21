// Repair.cpp - cards: VC redist, hosts, Defender excl, Firewall, crypto svcs, drivers
// By Ali Sakkaf - https://alisakkaf.com
#include "Repair.h"
#include "Logger.h"
#include "LicenseManager.h"
#include "../../Version.h"
#include "../utils/HashUtils.h"

#include <QProcess>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QSettings>
#include <QStandardPaths>
#include <QCoreApplication>
#include <QDateTime>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QTimer>

#ifdef _WIN32
#  include <windows.h>
#endif

namespace verax {

Repair& Repair::instance() {
    static Repair r;
    return r;
}

Repair::Repair(QObject *parent) : QObject(parent) {}

QString Repair::tempDir() const {
    const QString d = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    QDir().mkpath(d);
    return d;
}

int Repair::runProcess(const QString &exe, const QStringList &args, int timeoutMs)
{
    QProcess p;
#ifdef _WIN32
    p.setCreateProcessArgumentsModifier(
        [](QProcess::CreateProcessArguments *a){
            a->flags |= CREATE_NO_WINDOW;
        });
#endif
    p.setProcessChannelMode(QProcess::MergedChannels);
    p.start(exe, args);
    if (!p.waitForStarted(5000)) return -1;
    if (!p.waitForFinished(timeoutMs)) {
        p.kill();
        p.waitForFinished(2000);
        return -2;
    }
    return p.exitCode();
}

bool Repair::downloadFile(const QString &url, const QString &dst, int timeoutMs)
{
    QNetworkAccessManager nam;
    QNetworkRequest req((QUrl(url)));
    req.setHeader(QNetworkRequest::UserAgentHeader,
                  QStringLiteral("%1/%2").arg(APP_NAME).arg(APP_VERSION_STR));
    req.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);

    QNetworkReply *r = nam.get(req);
    QEventLoop loop;
    QTimer tm; tm.setSingleShot(true); tm.setInterval(timeoutMs);
    QObject::connect(&tm,  &QTimer::timeout, r, &QNetworkReply::abort);
    QObject::connect(r,    &QNetworkReply::finished, &loop, &QEventLoop::quit);
    tm.start();
    loop.exec();

    if (r->error() != QNetworkReply::NoError) {
        Logger::warn(QStringLiteral("Download failed: %1 - %2")
                     .arg(url, r->errorString()));
        r->deleteLater();
        return false;
    }

    QFile f(dst);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        r->deleteLater();
        return false;
    }
    f.write(r->readAll());
    f.close();
    r->deleteLater();
    return true;
}

// ─── Probes ────────────────────────────────────────────────────────────
RepairStatus Repair::checkVcRedist()
{
#ifdef _WIN32
    static const char *keys[] = {
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x86",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x86"
    };
    for (auto *k : keys) {
        QSettings s(k, QSettings::NativeFormat);
        if (s.value("Installed").toInt() == 1) return RepairStatus::Ok;
    }
    return RepairStatus::Missing;
#else
    return RepairStatus::Ok;
#endif
}

RepairStatus Repair::checkHosts()
{
#ifdef _WIN32
    const QString p = QStringLiteral("C:/Windows/System32/drivers/etc/hosts");
    QFile f(p);
    if (!f.open(QIODevice::ReadOnly)) return RepairStatus::Unknown;
    const QString body = QString::fromUtf8(f.readAll()).toLower();
    f.close();
    static const char *bad[] = {
        "microsoft.com", "windowsupdate", "defender", "kaspersky",
        "symantec", "bitdefender", "license.", "activation."
    };
    for (auto *b : bad) {
        if (body.contains(QString::fromLatin1(b) + " 127.")) return RepairStatus::Bad;
        // Common pattern: "127.0.0.1 microsoft.com"
        QStringList lines = body.split('\n');
        for (const QString &ln : lines) {
            const QString s = ln.trimmed();
            if ((s.startsWith("127.") || s.startsWith("0.0.0.0"))
                && s.contains(QString::fromLatin1(b)))
                return RepairStatus::Bad;
        }
    }
    return RepairStatus::Ok;
#else
    return RepairStatus::Ok;
#endif
}

RepairStatus Repair::checkDefenderExclusion()
{
#ifdef _WIN32
    QStringList args = { "-NoProfile", "-WindowStyle", "Hidden", "-Command",
        QStringLiteral("(Get-MpPreference).ExclusionPath -contains '%1'")
        .arg(QString::fromLatin1(APP_INSTALL_DIR))
    };
    QProcess p;
    p.setCreateProcessArgumentsModifier(
        [](QProcess::CreateProcessArguments *a){ a->flags |= CREATE_NO_WINDOW; });
    p.start("powershell.exe", args);
    if (!p.waitForStarted(5000)) return RepairStatus::Unknown;
    if (!p.waitForFinished(15000)) { p.kill(); return RepairStatus::Unknown; }
    const QString out = QString::fromLocal8Bit(p.readAllStandardOutput()).trimmed();
    return out.startsWith("True", Qt::CaseInsensitive)
              ? RepairStatus::Ok : RepairStatus::Missing;
#else
    return RepairStatus::Ok;
#endif
}

RepairStatus Repair::checkFirewallRule()
{
#ifdef _WIN32
    QProcess p;
    p.setCreateProcessArgumentsModifier(
        [](QProcess::CreateProcessArguments *a){ a->flags |= CREATE_NO_WINDOW; });
    p.start("netsh", { "advfirewall", "firewall", "show", "rule",
                       QStringLiteral("name=%1 IN").arg(QString::fromLatin1(APP_NAME)) });
    if (!p.waitForStarted(5000)) return RepairStatus::Unknown;
    if (!p.waitForFinished(10000)) { p.kill(); return RepairStatus::Unknown; }
    return p.exitCode() == 0 ? RepairStatus::Ok : RepairStatus::Missing;
#else
    return RepairStatus::Ok;
#endif
}

RepairStatus Repair::checkCryptoServices()
{
#ifdef _WIN32
    QProcess p;
    p.setCreateProcessArgumentsModifier(
        [](QProcess::CreateProcessArguments *a){ a->flags |= CREATE_NO_WINDOW; });
    p.start("sc", { "query", "CryptSvc" });
    if (!p.waitForStarted(5000)) return RepairStatus::Unknown;
    if (!p.waitForFinished(8000)) { p.kill(); return RepairStatus::Unknown; }
    const QString out = QString::fromLocal8Bit(p.readAllStandardOutput());
    return out.contains("RUNNING") ? RepairStatus::Ok : RepairStatus::Bad;
#else
    return RepairStatus::Ok;
#endif
}

RepairStatus Repair::checkPhoneDrivers()
{
#ifdef _WIN32
    // Probe pnputil for any of the well-known mobile-OEM driver families.
    // pnputil /enum-drivers prints all third-party INFs the system knows
    // about. If at least one matches a phone-vendor pattern we treat the
    // driver stack as healthy.
    QProcess p;
    p.setCreateProcessArgumentsModifier(
        [](QProcess::CreateProcessArguments *a){ a->flags |= CREATE_NO_WINDOW; });
    p.start("pnputil.exe", { "/enum-drivers" });
    if (!p.waitForStarted(5000))   return RepairStatus::Unknown;
    if (!p.waitForFinished(15000)) { p.kill(); return RepairStatus::Unknown; }

    const QString out = QString::fromLocal8Bit(p.readAllStandardOutput()).toLower();

    // Match by vendor display name OR by INF prefix. Covers the families
    // that VeraxCore's bulk-install path (fixPhoneDrivers) targets.
    static const char *vendorMarkers[] = {
        "qualcomm",   "qcusbser", "qcomdloader", "qdloader",
        "mediatek",   "mtk",      "preloader",
        "spreadtrum", "sprd",     "unisoc",
        "samsung",    "ssusbdl",
        "huawei",     "honor",
        "xiaomi",     "miusb",
        "oppo",       "realtek_usb",
        "vivo",
        "android",    "adb interface", "adb composite",
        "google android"
    };
    for (auto *m : vendorMarkers) {
        if (out.contains(QString::fromLatin1(m))) return RepairStatus::Ok;
    }
    return RepairStatus::Missing;
#else
    return RepairStatus::Ok;
#endif
}

// ─── Fix actions (async via QtConcurrent-like inline thread) ──────────
void Repair::fixHosts()
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::SystemRepair)) {
        emit finished("hosts", false, tr("Wymagana licencja Multi-Guard Secure lub ADMIN FULL"));
        return;
    }
#ifdef _WIN32
    const QString p = QStringLiteral("C:/Windows/System32/drivers/etc/hosts");
    const QString stamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    const QString bak   = tempDir() + QStringLiteral("/hosts.bak.") + stamp;
    QFile::copy(p, bak);

    const QByteArray def =
        "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
        "127.0.0.1       localhost\r\n"
        "::1             localhost\r\n";

    QFile f(p);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        emit finished("hosts", false, tr("Cannot write hosts file (need admin)"));
        return;
    }
    f.write(def);
    f.close();
    Logger::info(QStringLiteral("hosts reset (backup at %1)").arg(bak));
    emit cardStatus("hosts", RepairStatus::Ok);
    emit finished("hosts", true, tr("Hosts file reset (backup saved)"));
#else
    emit finished("hosts", true, tr("Not applicable on this OS"));
#endif
}

void Repair::fixVcRedist()
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::SystemRepair)) {
        emit finished("redist", false, tr("Wymagana licencja Multi-Guard Secure lub ADMIN FULL"));
        return;
    }
    const QString url = QStringLiteral("https://aka.ms/vs/17/release/vc_redist.x86.exe");
    const QString dst = tempDir() + QStringLiteral("/vc_redist.x86.exe");
    emit progress("redist", 10, tr("Downloading VC++ Redistributable..."));
    if (!downloadFile(url, dst, 120000)) {
        emit finished("redist", false, tr("Download failed"));
        return;
    }
    emit progress("redist", 60, tr("Installing..."));
    const int rc = runProcess(dst, { "/quiet", "/norestart" }, 600000);
    QFile::remove(dst);
    const bool ok = (rc == 0 || rc == 3010); // 3010 = success, restart required
    emit cardStatus("redist", ok ? RepairStatus::Ok : RepairStatus::Bad);
    emit finished("redist", ok,
                  ok ? tr("VC++ Redistributable installed")
                     : tr("Installer returned code %1").arg(rc));
}

void Repair::fixDefenderExclusion()
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::SystemRepair)) {
        emit finished("defender", false, tr("Wymagana licencja Multi-Guard Secure lub ADMIN FULL"));
        return;
    }
#ifdef _WIN32
    const QString exe = QDir::toNativeSeparators(
                            QCoreApplication::applicationFilePath());
    const QString dir = QString::fromLatin1(APP_INSTALL_DIR);
    QStringList args = { "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden", "-Command",
        QStringLiteral("Add-MpPreference -ExclusionPath '%1'; "
                       "Add-MpPreference -ExclusionProcess '%2'").arg(dir, exe) };
    const int rc = runProcess("powershell.exe", args, 30000);
    const bool ok = (rc == 0);
    emit cardStatus("defender", ok ? RepairStatus::Ok : RepairStatus::Bad);
    emit finished("defender", ok,
                  ok ? tr("Defender exclusion added")
                     : tr("PowerShell returned code %1").arg(rc));
#else
    emit finished("defender", true, tr("Not applicable"));
#endif
}

void Repair::fixFirewallRule()
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::SystemRepair)) {
        emit finished("firewall", false, tr("Wymagana licencja Multi-Guard Secure lub ADMIN FULL"));
        return;
    }
#ifdef _WIN32
    const QString exe = QDir::toNativeSeparators(
                            QCoreApplication::applicationFilePath());
    const QString name = QString::fromLatin1(APP_NAME);
    runProcess("netsh", { "advfirewall", "firewall", "add", "rule",
        QStringLiteral("name=%1 IN").arg(name),
        "dir=in", "action=allow", QStringLiteral("program=%1").arg(exe),
        "enable=yes" }, 15000);
    const int rc = runProcess("netsh", { "advfirewall", "firewall", "add", "rule",
        QStringLiteral("name=%1 OUT").arg(name),
        "dir=out", "action=allow", QStringLiteral("program=%1").arg(exe),
        "enable=yes" }, 15000);
    const bool ok = (rc == 0);
    emit cardStatus("firewall", ok ? RepairStatus::Ok : RepairStatus::Bad);
    emit finished("firewall", ok,
                  ok ? tr("Firewall rules added")
                     : tr("netsh returned code %1").arg(rc));
#else
    emit finished("firewall", true, tr("Not applicable"));
#endif
}

void Repair::fixCryptoServices()
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::SystemRepair)) {
        emit finished("crypto", false, tr("Wymagana licencja Multi-Guard Secure lub ADMIN FULL"));
        return;
    }
#ifdef _WIN32
    runProcess("sc", { "config", "CryptSvc", "start=", "auto" }, 8000);
    const int rc = runProcess("net", { "start", "CryptSvc" }, 15000);
    const bool ok = (rc == 0 || rc == 2);  // 2 = already running
    emit cardStatus("crypto", ok ? RepairStatus::Ok : RepairStatus::Bad);
    emit finished("crypto", ok,
                  ok ? tr("Crypto Services running")
                     : tr("Service control returned code %1").arg(rc));
#else
    emit finished("crypto", true, tr("Not applicable"));
#endif
}

void Repair::fixPhoneDrivers(const QString &infFolder)
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::SystemRepair)) {
        emit finished("drivers", false, tr("Wymagana licencja Multi-Guard Secure lub ADMIN FULL"));
        return;
    }
#ifdef _WIN32
    if (infFolder.isEmpty() || !QDir(infFolder).exists()) {
        emit finished("drivers", false, tr("Please select a folder containing .inf drivers"));
        return;
    }
    const int rc = runProcess("pnputil.exe",
        { "/add-driver", infFolder + "\\*.inf", "/install", "/subdirs" }, 300000);
    const bool ok = (rc == 0);
    emit cardStatus("drivers", ok ? RepairStatus::Ok : RepairStatus::Bad);
    emit finished("drivers", ok,
                  ok ? tr("Drivers installed")
                     : tr("pnputil returned code %1").arg(rc));
#else
    Q_UNUSED(infFolder);
    emit finished("drivers", true, tr("Not applicable"));
#endif
}

QStringList Repair::checkAppDlls(const QString &appFolder,
                                 const QMap<QString,QString> &knownGood)
{
    QStringList bad;
    QDir d(appFolder);
    if (!d.exists()) return bad;
    for (auto it = knownGood.constBegin(); it != knownGood.constEnd(); ++it) {
        const QString dll = d.absoluteFilePath(it.key());
        if (!QFile::exists(dll)) { bad << it.key() + " (missing)"; continue; }
        const QString h = HashUtils::sha256Hex(dll);
        if (h.compare(it.value(), Qt::CaseInsensitive) != 0)
            bad << it.key() + " (hash mismatch)";
    }
    return bad;
}

void Repair::fixAll()
{
    fixHosts();
    fixDefenderExclusion();
    fixFirewallRule();
    fixCryptoServices();
    fixVcRedist();
}

} // namespace verax
