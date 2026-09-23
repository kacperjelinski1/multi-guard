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
    const QString edgePathX86 = QStringLiteral("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe");
    const QString edgePath64 = QStringLiteral("C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe");
    edge.installed = QFile::exists(edgePathX86) || QFile::exists(edgePath64);
    edge.path = QFile::exists(edgePath64) ? edgePath64 : edgePathX86;
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
    const QString ffPath64 = QStringLiteral("C:\\Program Files\\Mozilla Firefox\\firefox.exe");
    const QString ffPathX86 = QStringLiteral("C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe");
    firefox.installed = QFile::exists(ffPath64) || QFile::exists(ffPathX86);
    firefox.path = QFile::exists(ffPath64) ? ffPath64 : ffPathX86;
    firefox.extensionActive = false;
    list.append(firefox);

    // 5. Opera
    BrowserInfo opera;
    opera.id = QStringLiteral("opera");
    opera.name = QStringLiteral("Opera");
    const QString operaUser = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + QStringLiteral("/Programs/Opera/launcher.exe");
    const QString operaProg = QStringLiteral("C:\\Program Files\\Opera\\launcher.exe");
    opera.installed = QFile::exists(operaUser) || QFile::exists(operaProg);
    opera.path = QFile::exists(operaUser) ? operaUser : operaProg;
    QSettings operaReg(QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Opera Software\\Extensions"), QSettings::NativeFormat);
    opera.extensionActive = operaReg.contains(QStringLiteral("multiguard_webshield")) || chrome.extensionActive;
    list.append(opera);

    // 6. Opera GX
    BrowserInfo operaGx;
    operaGx.id = QStringLiteral("operagx");
    operaGx.name = QStringLiteral("Opera GX");
    const QString gxUser = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + QStringLiteral("/Programs/Opera GX/launcher.exe");
    const QString gxProg = QStringLiteral("C:\\Program Files\\Opera GX\\launcher.exe");
    operaGx.installed = QFile::exists(gxUser) || QFile::exists(gxProg);
    operaGx.path = QFile::exists(gxUser) ? gxUser : gxProg;
    operaGx.extensionActive = opera.extensionActive;
    list.append(operaGx);

    // 7. Vivaldi
    BrowserInfo vivaldi;
    vivaldi.id = QStringLiteral("vivaldi");
    vivaldi.name = QStringLiteral("Vivaldi");
    const QString vivUser = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + QStringLiteral("/Vivaldi/Application/vivaldi.exe");
    const QString vivProg = QStringLiteral("C:\\Program Files\\Vivaldi\\Application\\vivaldi.exe");
    vivaldi.installed = QFile::exists(vivUser) || QFile::exists(vivProg);
    vivaldi.path = QFile::exists(vivUser) ? vivUser : vivProg;
    vivaldi.extensionActive = chrome.extensionActive;
    list.append(vivaldi);

    // 8. Tor Browser
    BrowserInfo tor;
    tor.id = QStringLiteral("tor");
    tor.name = QStringLiteral("Tor Browser");
    const QString torUser = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation) + QStringLiteral("/Tor Browser/Browser/firefox.exe");
    const QString torProg = QStringLiteral("C:\\Program Files\\Tor Browser\\Browser\\firefox.exe");
    tor.installed = QFile::exists(torUser) || QFile::exists(torProg);
    tor.path = QFile::exists(torUser) ? torUser : torProg;
    tor.extensionActive = false;
    list.append(tor);
#else
    list.append({ QStringLiteral("chrome"), QStringLiteral("Google Chrome"), true, true, QStringLiteral("/Applications/Google Chrome.app") });
    list.append({ QStringLiteral("edge"), QStringLiteral("Microsoft Edge"), true, true, QStringLiteral("/Applications/Microsoft Edge.app") });
    list.append({ QStringLiteral("brave"), QStringLiteral("Brave Browser"), true, true, QStringLiteral("/Applications/Brave Browser.app") });
    list.append({ QStringLiteral("firefox"), QStringLiteral("Mozilla Firefox"), true, false, QStringLiteral("/Applications/Firefox.app") });
    list.append({ QStringLiteral("opera"), QStringLiteral("Opera"), false, false, QStringLiteral("") });
    list.append({ QStringLiteral("operagx"), QStringLiteral("Opera GX"), false, false, QStringLiteral("") });
    list.append({ QStringLiteral("vivaldi"), QStringLiteral("Vivaldi"), false, false, QStringLiteral("") });
#endif

    return list;
}

bool BrowserProtectionManager::installExtension(const QString &browserId)
{
    const QString extDir = extensionDirectory();
    Logger::info(QStringLiteral("BrowserProtectionManager: Installing extension for %1 from %2").arg(browserId, extDir));

#ifdef _WIN32
    // Register extension in Windows Registry for all Chromium browsers
    const QStringList regPaths = {
        QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Google\\Chrome\\Extensions\\multiguard_webshield"),
        QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Google\\Chrome\\Extensions\\multiguard_webshield"),
        QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Edge\\Extensions\\multiguard_webshield"),
        QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Edge\\Extensions\\multiguard_webshield"),
        QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Opera Software\\Extensions\\multiguard_webshield"),
        QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\BraveSoftware\\Brave-Browser\\Extensions\\multiguard_webshield"),
        QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Vivaldi\\Extensions\\multiguard_webshield")
    };
    for (const auto &p : regPaths) {
        QSettings reg(p, QSettings::NativeFormat);
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
