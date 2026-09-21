#include "StartupManager.h"
#include "Scanner.h"
#include "Logger.h"
#include "LicenseManager.h"

#include <QSettings>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>
#include <QRegularExpression>

namespace verax {

QString StartupManager::extractExecutablePath(const QString &cmd)
{
    QString trimmed = cmd.trimmed();
    if (trimmed.startsWith('"')) {
        int endQuote = trimmed.indexOf('"', 1);
        if (endQuote > 1) {
            return trimmed.mid(1, endQuote - 1);
        }
    }
    int exeIdx = trimmed.indexOf(".exe", 0, Qt::CaseInsensitive);
    if (exeIdx != -1) {
        return trimmed.left(exeIdx + 4).trimmed();
    }
    return trimmed.split(' ').first();
}

QList<StartupEntry> StartupManager::getEntries()
{
    QList<StartupEntry> results;

#ifdef Q_OS_WIN
    // 1. HKCU Run
    {
        QSettings hkcu("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
        for (const QString &key : hkcu.allKeys()) {
            StartupEntry e;
            e.name = key;
            e.command = hkcu.value(key).toString();
            e.cleanPath = extractExecutablePath(e.command);
            e.location = "HKCU Run";
            e.enabled = true;
            if (QFile::exists(e.cleanPath)) {
                e.isSigned = Scanner::verifyAuthenticode(e.cleanPath);
            }
            results.append(e);
        }
    }

    // 2. HKLM Run
    {
        QSettings hklm("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
        for (const QString &key : hklm.allKeys()) {
            StartupEntry e;
            e.name = key;
            e.command = hklm.value(key).toString();
            e.cleanPath = extractExecutablePath(e.command);
            e.location = "HKLM Run";
            e.enabled = true;
            if (QFile::exists(e.cleanPath)) {
                e.isSigned = Scanner::verifyAuthenticode(e.cleanPath);
            }
            results.append(e);
        }
    }

    // 3. HKCU RunDisabled (custom / msconfig key)
    {
        QSettings hkcuDis("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunDisabled", QSettings::NativeFormat);
        for (const QString &key : hkcuDis.allKeys()) {
            StartupEntry e;
            e.name = key;
            e.command = hkcuDis.value(key).toString();
            e.cleanPath = extractExecutablePath(e.command);
            e.location = "HKCU Run";
            e.enabled = false;
            if (QFile::exists(e.cleanPath)) {
                e.isSigned = Scanner::verifyAuthenticode(e.cleanPath);
            }
            results.append(e);
        }
    }

    // 4. Startup Folder
    QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QString roaming = QDir::cleanPath(appData + "/..");
    QString userStartup = roaming + "/Microsoft/Windows/Start Menu/Programs/Startup";
    QDir startupDir(userStartup);
    if (startupDir.exists()) {
        for (const QFileInfo &fi : startupDir.entryInfoList(QDir::Files | QDir::NoDotAndDotDot)) {
            StartupEntry e;
            e.name = fi.completeBaseName();
            e.command = fi.absoluteFilePath();
            e.cleanPath = fi.absoluteFilePath();
            e.location = "Folder Startup";
            e.enabled = !fi.fileName().endsWith(".disabled", Qt::CaseInsensitive);
            if (QFile::exists(e.cleanPath)) {
                e.isSigned = Scanner::verifyAuthenticode(e.cleanPath);
            }
            results.append(e);
        }
    }
#endif

    return results;
}

bool StartupManager::setEntryEnabled(const StartupEntry &entry, bool enable)
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::StartupManager)) {
        Logger::warn("StartupManager: Pominięto modyfikację — brak uprawnień licencyjnych.");
        return false;
    }
#ifdef Q_OS_WIN
    if (entry.location == "HKCU Run") {
        QSettings active("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
        QSettings disabled("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunDisabled", QSettings::NativeFormat);

        if (enable) {
            active.setValue(entry.name, entry.command);
            disabled.remove(entry.name);
        } else {
            disabled.setValue(entry.name, entry.command);
            active.remove(entry.name);
        }
        active.sync();
        disabled.sync();
        return true;
    } else if (entry.location == "Folder Startup") {
        if (enable && entry.command.endsWith(".disabled", Qt::CaseInsensitive)) {
            QString newName = entry.command.left(entry.command.length() - 9);
            return QFile::rename(entry.command, newName);
        } else if (!enable && !entry.command.endsWith(".disabled", Qt::CaseInsensitive)) {
            return QFile::rename(entry.command, entry.command + ".disabled");
        }
        return true;
    }
#else
    Q_UNUSED(entry);
    Q_UNUSED(enable);
#endif
    return false;
}

bool StartupManager::deleteEntry(const StartupEntry &entry)
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::StartupManager)) {
        Logger::warn("StartupManager: Pominięto usunięcie wpisu — brak uprawnień licencyjnych.");
        return false;
    }
#ifdef Q_OS_WIN
    if (entry.location == "HKCU Run") {
        QSettings active("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
        QSettings disabled("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunDisabled", QSettings::NativeFormat);
        active.remove(entry.name);
        disabled.remove(entry.name);
        active.sync();
        disabled.sync();
        return true;
    } else if (entry.location == "HKLM Run") {
        QSettings active("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
        active.remove(entry.name);
        active.sync();
        return true;
    } else if (entry.location == "Folder Startup") {
        return QFile::remove(entry.command);
    }
#else
    Q_UNUSED(entry);
#endif
    return false;
}

} // namespace verax
