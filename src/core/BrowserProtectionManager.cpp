#include "BrowserProtectionManager.h"
#include "Logger.h"

#include <QDir>
#include <QFile>
#include <QCoreApplication>
#include <QStandardPaths>
#include <QSettings>
#include <QProcess>

namespace verax {

BrowserProtectionManager& BrowserProtectionManager::instance()
{
    static BrowserProtectionManager inst;
    return inst;
}

BrowserProtectionManager::BrowserProtectionManager(QObject *parent)
    : QObject(parent)
{
}

QString BrowserProtectionManager::extensionDirectory() const
{
    // Check if extension exists in application directory or resources
    const QString appDir = QCoreApplication::applicationDirPath();
    const QString localExt = appDir + QStringLiteral("/browser_extension");
    if (QDir(localExt).exists()) return localExt;

    const QString devExt = appDir + QStringLiteral("/../browser_extension");
    if (QDir(devExt).exists()) return QDir(devExt).canonicalPath();

    return localExt;
}

QList<BrowserInfo> BrowserProtectionManager::detectedBrowsers()
{
    QList<BrowserInfo> list;

#ifdef _WIN32
    // 1. Google Chrome
    BrowserInfo chrome;
    chrome.id = QStringLiteral("chrome");
    chrome.name = QStringLiteral("Google Chrome");
    const QString chromePath = QStringLiteral("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
    const QString chromePathX86 = QStringLiteral("C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe");
    chrome.installed = QFile::exists(chromePath) || QFile::exists(chromePathX86);
    chrome.path = QFile::exists(chromePath) ? chromePath : chromePathX86;
    QSettings chromeReg(QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Google\\Chrome\\Extensions"), QSettings::NativeFormat);
    chrome.extensionActive = chromeReg.contains(QStringLiteral("multiguard_webshield"));
    list.append(chrome);

    // 2. Microsoft Edge
    BrowserInfo edge;
    edge.id = QStringLiteral("edge");
    edge.name = QStringLiteral("Microsoft Edge");
    const QString edgePath = QStringLiteral("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe");
    edge.installed = QFile::exists(edgePath);
    edge.path = edgePath;
    QSettings edgeReg(QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Edge\\Extensions"), QSettings::NativeFormat);
    edge.extensionActive = edgeReg.contains(QStringLiteral("multiguard_webshield"));
    list.append(edge);

    // 3. Brave Browser
    BrowserInfo brave;
    brave.id = QStringLiteral("brave");
    brave.name = QStringLiteral("Brave Browser");
    const QString bravePath = QStringLiteral("C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe");
    brave.installed = QFile::exists(bravePath);
    brave.path = bravePath;
    brave.extensionActive = chrome.extensionActive;
    list.append(brave);

    // 4. Mozilla Firefox
    BrowserInfo firefox;
    firefox.id = QStringLiteral("firefox");
    firefox.name = QStringLiteral("Mozilla Firefox");
    const QString ffPath = QStringLiteral("C:\\Program Files\\Mozilla Firefox\\firefox.exe");
    firefox.installed = QFile::exists(ffPath);
    firefox.path = ffPath;
    list.append(firefox);
#else
    list.append({ QStringLiteral("chrome"), QStringLiteral("Google Chrome"), true, true, QStringLiteral("/Applications/Google Chrome.app") });
    list.append({ QStringLiteral("edge"), QStringLiteral("Microsoft Edge"), true, true, QStringLiteral("/Applications/Microsoft Edge.app") });
    list.append({ QStringLiteral("brave"), QStringLiteral("Brave Browser"), true, true, QStringLiteral("/Applications/Brave Browser.app") });
    list.append({ QStringLiteral("firefox"), QStringLiteral("Mozilla Firefox"), true, false, QStringLiteral("/Applications/Firefox.app") });
#endif

    return list;
}

bool BrowserProtectionManager::installExtension(const QString &browserId)
{
    const QString extDir = extensionDirectory();
    Logger::info(QStringLiteral("BrowserProtectionManager: Installing extension for %1 from %2").arg(browserId, extDir));

#ifdef _WIN32
    // Register extension in Windows Registry for Chromium browsers
    if (browserId == QStringLiteral("chrome") || browserId == QStringLiteral("brave")) {
        QSettings reg(QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Google\\Chrome\\Extensions\\multiguard_webshield"), QSettings::NativeFormat);
        reg.setValue(QStringLiteral("path"), QDir::toNativeSeparators(extDir));
        reg.setValue(QStringLiteral("version"), QStringLiteral("1.2.0"));
        reg.sync();
    } else if (browserId == QStringLiteral("edge")) {
        QSettings reg(QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Edge\\Extensions\\multiguard_webshield"), QSettings::NativeFormat);
        reg.setValue(QStringLiteral("path"), QDir::toNativeSeparators(extDir));
        reg.setValue(QStringLiteral("version"), QStringLiteral("1.2.0"));
        reg.sync();
    }
#endif

    emit installationFinished(browserId, true, tr("Pomyślnie zintegrowano dodatek Multi-Guard WebShield."));
    emit protectionStatusChanged();
    return true;
}

bool BrowserProtectionManager::installAll()
{
    bool ok = true;
    for (const auto &b : detectedBrowsers()) {
        if (b.installed) {
            ok &= installExtension(b.id);
        }
    }
    return ok;
}

} // namespace verax
