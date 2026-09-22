// Settings.cpp - QSettings facade with Windows-startup wiring
// By Ali Sakkaf - https://alisakkaf.com
#include "Settings.h"
#include "Logger.h"
#include "../../Version.h"
#include "SignatureDb.h"

#include <QSettings>
#include <QCoreApplication>
#include <QDir>
namespace verax {

Settings& Settings::instance() {
    static Settings s;
    return s;
}

Settings::Settings(QObject *parent) : QObject(parent) {
    m_updateUrl = QString::fromLatin1(APP_UPDATE_URL);
}

static QString regPath() {
    return QStringLiteral("HKEY_CURRENT_USER\\") + QString::fromLatin1(APP_REG_KEY);
}

void Settings::load()
{
    QSettings s(QSettings::NativeFormat, QSettings::UserScope,
                QString::fromLatin1(APP_VENDOR),
                QString::fromLatin1(APP_NAME));

    m_language          = s.value("general/language",        m_language).toString();
    m_theme             = s.value("general/theme",           m_theme).toString();
    m_startWithWindows  = true;
    applyStartupRegistry();
    m_contextMenu       = s.value("general/contextMenu",     m_contextMenu).toBool();
    m_trayOnClose       = s.value("general/trayOnClose",     m_trayOnClose).toBool();
    m_showNotifications = s.value("general/showNotifications", m_showNotifications).toBool();

    m_realTimeProtection   = s.value("scan/realTimeShield",     m_realTimeProtection).toBool();
    m_ransomwareProtection = s.value("scan/ransomwareShield",   m_ransomwareProtection).toBool();
    m_webShield            = s.value("web/shieldEnabled",       m_webShield).toBool();
    m_scanUsbOnInsert      = s.value("scan/usbOnInsert",        m_scanUsbOnInsert).toBool();
    m_scheduledScan        = s.value("scan/scheduled",          m_scheduledScan).toString();
    m_scheduledTime        = s.value("scan/scheduledTime",      m_scheduledTime).toString();
    m_exclusions           = s.value("scan/exclusions",         m_exclusions).toStringList();

    m_autoUpdate        = s.value("updates/auto",            m_autoUpdate).toBool();
    m_updateUrl         = s.value("updates/url",             m_updateUrl).toString();

    m_useSigDb          = s.value("engine/sigDb",            m_useSigDb).toBool();
    m_usePe             = s.value("engine/pe",               m_usePe).toBool();
    m_useHeur           = s.value("engine/heuristics",       m_useHeur).toBool();
    m_useCloud          = s.value("engine/cloud",            m_useCloud).toBool();

    m_heurThreshold     = s.value("engine/heurThreshold",    m_heurThreshold).toInt();
    m_detectionAction   = s.value("engine/action",           m_detectionAction).toString();

    m_clientName        = s.value("profile/clientName",      m_clientName).toString();
    m_clientPhone       = s.value("profile/clientPhone",     m_clientPhone).toString();
    m_clientEmail       = s.value("profile/clientEmail",     m_clientEmail).toString();
    m_scansCount        = s.value("stats/scansCount",        m_scansCount).toLongLong();
    m_threatsBlockedCount = s.value("stats/threatsBlocked",  m_threatsBlockedCount).toLongLong();
}

void Settings::save()
{
    QSettings s(QSettings::NativeFormat, QSettings::UserScope,
                QString::fromLatin1(APP_VENDOR),
                QString::fromLatin1(APP_NAME));

    s.setValue("general/language",          m_language);
    s.setValue("general/theme",             m_theme);
    s.setValue("general/startWithWindows",  m_startWithWindows);
    s.setValue("general/contextMenu",       m_contextMenu);
    s.setValue("general/trayOnClose",       m_trayOnClose);
    s.setValue("general/showNotifications", m_showNotifications);

    s.setValue("scan/realTimeShield",       m_realTimeProtection);
    s.setValue("scan/ransomwareShield",     m_ransomwareProtection);
    s.setValue("web/shieldEnabled",         m_webShield);
    s.setValue("scan/usbOnInsert",          m_scanUsbOnInsert);
    s.setValue("scan/scheduled",            m_scheduledScan);
    s.setValue("scan/scheduledTime",        m_scheduledTime);
    s.setValue("scan/exclusions",           m_exclusions);

    s.setValue("updates/auto",              m_autoUpdate);
    s.setValue("updates/url",               m_updateUrl);

    s.setValue("engine/sigDb",              m_useSigDb);
    s.setValue("engine/pe",                 m_usePe);
    s.setValue("engine/heuristics",         m_useHeur);
    s.setValue("engine/cloud",              m_useCloud);
    s.setValue("engine/heurThreshold",      m_heurThreshold);
    s.setValue("engine/action",             m_detectionAction);

    s.setValue("profile/clientName",        m_clientName);
    s.setValue("profile/clientPhone",       m_clientPhone);
    s.setValue("profile/clientEmail",       m_clientEmail);
    s.setValue("stats/scansCount",          m_scansCount);
    s.setValue("stats/threatsBlocked",      m_threatsBlockedCount);
    s.sync();
}

void Settings::setLanguage(const QString &v) {
    if (m_language == v) return;
    m_language = v;
    save();
    emit languageChanged(v);
}

void Settings::setTheme(const QString &v) {
    if (m_theme == v) return;
    m_theme = v;
    save();
}

void Settings::setStartWithWindows(bool v) {
    m_startWithWindows = v;
    save();
    applyStartupRegistry();
}

void Settings::setContextMenuIntegration(bool v) {
    m_contextMenu = v;
    save();
    applyContextMenuRegistry();
}

void Settings::setRealTimeProtection(bool v) {
    m_realTimeProtection = v;
    save();
}

void Settings::setRansomwareProtection(bool v) {
    m_ransomwareProtection = v;
    save();
}

void Settings::setWebShield(bool v) {
    m_webShield = v;
    save();
}

void Settings::addExclusion(const QString &path) {
    if (path.isEmpty()) return;
    const QString norm = QDir::cleanPath(path);
    if (!m_exclusions.contains(norm, Qt::CaseInsensitive)) {
        m_exclusions.append(norm);
        save();
    }
}

void Settings::removeExclusion(const QString &path) {
    const QString norm = QDir::cleanPath(path);
    for (int i = 0; i < m_exclusions.size(); ++i) {
        if (m_exclusions[i].compare(norm, Qt::CaseInsensitive) == 0) {
            m_exclusions.removeAt(i);
            save();
            break;
        }
    }
}

bool Settings::isExcluded(const QString &filePath) const {
    if (m_exclusions.isEmpty() || filePath.isEmpty()) return false;
    const QString target = QDir::cleanPath(filePath);

    for (const auto &ex : m_exclusions) {
        if (target.compare(ex, Qt::CaseInsensitive) == 0) return true;
        if (target.startsWith(ex + QLatin1Char('/'), Qt::CaseInsensitive)) return true;
#ifdef Q_OS_WIN
        if (target.startsWith(ex + QLatin1Char('\\'), Qt::CaseInsensitive)) return true;
#endif
    }
    return false;
}

void Settings::applyStartupRegistry()
{
    QSettings run("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows"
                  "\\CurrentVersion\\Run", QSettings::NativeFormat);
    const QString exe = QDir::toNativeSeparators(
                QCoreApplication::applicationFilePath());
    if (m_startWithWindows) {
        run.setValue(QString::fromLatin1(APP_NAME),
                     QStringLiteral("\"%1\" --tray").arg(exe));
        Logger::info(QStringLiteral("Startup registered: %1").arg(exe));
    } else {
        run.remove(QString::fromLatin1(APP_NAME));
        Logger::info(QStringLiteral("Startup deregistered"));
    }
}

void Settings::applyContextMenuRegistry()
{
#ifdef Q_OS_WIN
    const QString exe = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
    const QString text = tr("Skanuj za pomocą Multi-Guard");
    const QString icon = QStringLiteral("\"%1\",0").arg(exe);
    const QString cmd  = QStringLiteral("\"%1\" \"%2\"").arg(exe, "%1");

    QSettings regFiles("HKEY_CURRENT_USER\\Software\\Classes\\*\\shell\\MultiGuard", QSettings::NativeFormat);
    QSettings regDirs("HKEY_CURRENT_USER\\Software\\Classes\\Directory\\shell\\MultiGuard", QSettings::NativeFormat);

    if (m_contextMenu) {
        regFiles.setValue(".", text);
        regFiles.setValue("Icon", icon);
        regFiles.setValue("command/.", cmd);
        regFiles.sync();

        regDirs.setValue(".", text);
        regDirs.setValue("Icon", icon);
        regDirs.setValue("command/.", cmd);
        regDirs.sync();
        Logger::info("Context menu registered in HKCU");
    } else {
        regFiles.remove("");
        regFiles.sync();
        regDirs.remove("");
        regDirs.sync();
        Logger::info("Context menu deregistered from HKCU");
    }
#endif
}

void Settings::resetAll()
{
    // 1. Reset standard configuration settings
    QSettings s(QSettings::NativeFormat, QSettings::UserScope,
                QString::fromLatin1(APP_VENDOR),
                QString::fromLatin1(APP_NAME));
    s.clear();
    s.sync();

    // 2. Clear registry startup & context menu
    m_startWithWindows = true;
    applyStartupRegistry();
    m_contextMenu = false;
    applyContextMenuRegistry();

    // 3. Close the active database connection
    verax::SignatureDb::instance().close();

    // 4. Physical deletion of state files
    const QString appData = Logger::userDataDir();
    QFile::remove(appData + QStringLiteral("/db/verax.sqlite"));
    QFile::remove(appData + QStringLiteral("/db/verax.sqlite-shm"));
    QFile::remove(appData + QStringLiteral("/db/verax.sqlite-wal"));
    QFile::remove(appData + QStringLiteral("/db/verax_signatures.json"));

    // Remove logs
    QDir logDir(appData + QStringLiteral("/Logs"));
    if (logDir.exists()) {
        logDir.removeRecursively();
    }

    // 5. Reset member variables to defaults
    m_language          = QStringLiteral("pl");
    m_theme             = QStringLiteral("dark");
    m_contextMenu       = false;
    m_realTimeProtection= true;
    m_ransomwareProtection = true;
    m_webShield         = true;
    m_exclusions.clear();
    m_trayOnClose       = true;
    m_showNotifications = true;
    m_scanUsbOnInsert   = true;
    m_scheduledScan     = QStringLiteral("off");
    m_scheduledTime     = QStringLiteral("03:00");
    m_autoUpdate        = true;
    m_updateUrl         = QString::fromLatin1(APP_UPDATE_URL);
    m_useSigDb = m_usePe = m_useHeur = true;
    m_useCloud          = false;
    m_heurThreshold     = 60;
    m_detectionAction   = QStringLiteral("report");

    // 6. Reinitialize the fresh database from seed
    verax::SignatureDb::instance().initSchema();

    emit languageChanged(m_language);
}

} // namespace verax
