#include "ContextMenuManager.h"

#include <QCoreApplication>
#include <QDir>
#include <QSettings>
#include <QObject>

namespace verax {

bool ContextMenuManager::isEnabled()
{
#ifdef Q_OS_WIN
    QSettings regCheck("HKEY_CURRENT_USER\\Software\\Classes\\*\\shell\\MultiGuard\\command", QSettings::NativeFormat);
    return regCheck.contains(".");
#else
    return false;
#endif
}

bool ContextMenuManager::setEnabled(bool enable)
{
#ifdef Q_OS_WIN
    const QString exePath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
    const QString title = QObject::tr("Scan with Multi-Guard");

    const QStringList keys = {
        "HKEY_CURRENT_USER\\Software\\Classes\\*\\shell\\MultiGuard",
        "HKEY_CURRENT_USER\\Software\\Classes\\Directory\\shell\\MultiGuard",
        "HKEY_CURRENT_USER\\Software\\Classes\\Drive\\shell\\MultiGuard"
    };

    if (enable) {
        for (const QString &keyPath : keys) {
            QSettings reg(keyPath, QSettings::NativeFormat);
            reg.setValue(".", title);
            reg.setValue("Icon", QString("\"%1\",0").arg(exePath));
            reg.setValue("command/.", QString("\"%1\" \"%2\"").arg(exePath, "%1"));
            reg.sync();
        }
        return true;
    } else {
        QSettings regRoot("HKEY_CURRENT_USER\\Software\\Classes", QSettings::NativeFormat);
        regRoot.remove("*\\shell\\MultiGuard");
        regRoot.remove("Directory\\shell\\MultiGuard");
        regRoot.remove("Drive\\shell\\MultiGuard");
        regRoot.sync();
        return true;
    }
#else
    Q_UNUSED(enable);
    return false;
#endif
}

} // namespace verax
