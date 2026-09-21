#pragma once

#include <QString>
#include <QList>

namespace verax {

struct StartupEntry {
    QString name;
    QString command;
    QString cleanPath;
    QString location; // "HKCU Run", "HKLM Run", "Folder Startup"
    bool isSigned = false;
    bool enabled = true;
};

class StartupManager {
public:
    static QList<StartupEntry> getEntries();
    static bool setEntryEnabled(const StartupEntry &entry, bool enable);
    static bool deleteEntry(const StartupEntry &entry);

private:
    static QString extractExecutablePath(const QString &cmd);
};

} // namespace verax
