#include "ThemeManager.h"
#include "../core/Settings.h"
#include "../core/Logger.h"
#include "../../Version.h"

#include <QApplication>
#include <QFile>
#include <QSettings>
#include <QRegularExpression>

namespace verax {

bool ThemeManager::isDark()
{
    return effectiveTheme() == QLatin1String("dark");
}

QString ThemeManager::effectiveTheme()
{
    QString mode = Settings::instance().theme().toLower().trimmed();
    if (mode.isEmpty()) mode = "dark";

    if (mode == "system") {
#ifdef Q_OS_WIN
        QSettings reg("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", QSettings::NativeFormat);
        int light = reg.value("AppsUseLightTheme", 0).toInt();
        return (light == 1) ? QStringLiteral("light") : QStringLiteral("dark");
#else
        return QStringLiteral("dark");
#endif
    } else if (mode == "light") {
        return QStringLiteral("light");
    }
    return QStringLiteral("dark");
}

void ThemeManager::applyTheme(const QString &themeMode)
{
    if (!themeMode.isEmpty()) {
        Settings::instance().setTheme(themeMode);
    }

    const QString eff = effectiveTheme();
    const QString qssPath = (eff == "light") ? QStringLiteral(":/styles/Daylight.qss")
                                             : QStringLiteral(":/styles/Dark.qss");

    QFile qss(qssPath);
    if (qss.open(QIODevice::ReadOnly)) {
        QString css = QString::fromUtf8(qss.readAll());
        css.replace(QStringLiteral("%APP_NAME%"), QString::fromLatin1(APP_NAME));
        css.replace(QStringLiteral("%APP_VERSION%"), QString::fromLatin1(APP_VERSION_STR));

        if (Settings::instance().language() == "ar") {
            QRegularExpression re("font-weight:\\s*[a-zA-Z0-9]+\\s*;?");
            css.replace(re, "");
        }

        qApp->setStyleSheet(css);
        Logger::info(QStringLiteral("Theme applied: %1 (file: %2)").arg(eff, qssPath));
    } else {
        Logger::warn(QStringLiteral("Could not open stylesheet: %1").arg(qssPath));
    }
}

QString ThemeManager::trayStyleSheet()
{
    if (isDark()) {
        return QStringLiteral(
            "QMenu { background: #121622; color: #F1F5F9; border: 1px solid #252E42; border-radius: 8px; padding: 6px; }\n"
            "QMenu::item { padding: 8px 24px 8px 12px; border-radius: 4px; font-size: 12px; }\n"
            "QMenu::item:selected { background: #00E676; color: #000000; font-weight: bold; }\n"
            "QMenu::separator { height: 1px; background: #252E42; margin: 4px 8px; }"
        );
    } else {
        return QStringLiteral(
            "QMenu { background: #FFFFFF; color: #0F172A; border: 1px solid #CBD5E1; border-radius: 8px; padding: 6px; }\n"
            "QMenu::item { padding: 8px 24px 8px 12px; border-radius: 4px; font-size: 12px; }\n"
            "QMenu::item:selected { background: #2563EB; color: #FFFFFF; font-weight: bold; }\n"
            "QMenu::separator { height: 1px; background: #E2E8F0; margin: 4px 8px; }"
        );
    }
}

QString ThemeManager::alertStyleSheet(const QString &accentColor)
{
    if (isDark()) {
        return QString(
            "#alertCard {"
            "  background: rgba(18, 22, 34, 0.96);"
            "  border: 1px solid rgba(255, 255, 255, 0.12);"
            "  border-left: 5px solid %1;"
            "  border-radius: 10px;"
            "}"
            "QLabel { color: #F1F5F9; }"
        ).arg(accentColor);
    } else {
        return QString(
            "#alertCard {"
            "  background: rgba(255, 255, 255, 0.98);"
            "  border: 1px solid rgba(0, 0, 0, 0.12);"
            "  border-left: 5px solid %1;"
            "  border-radius: 10px;"
            "}"
            "QLabel { color: #0F172A; }"
        ).arg(accentColor);
    }
}

} // namespace verax
