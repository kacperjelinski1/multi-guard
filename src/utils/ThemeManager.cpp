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
    return true;
}

QString ThemeManager::effectiveTheme()
{
    return QStringLiteral("dark");
}

void ThemeManager::applyTheme(const QString &themeMode)
{
    Q_UNUSED(themeMode);
    Settings::instance().setTheme(QStringLiteral("dark"));

    const QString qssPath = QStringLiteral(":/styles/Dark.qss");

    QFile qss(qssPath);
    if (qss.open(QIODevice::ReadOnly)) {
        QString css = QString::fromUtf8(qss.readAll());
        css.replace(QStringLiteral("%APP_NAME%"), QString::fromLatin1(APP_NAME));
        css.replace(QStringLiteral("%APP_VERSION%"), QString::fromLatin1(APP_VERSION_STR));

        qApp->setStyleSheet(css);
        Logger::info(QStringLiteral("Theme applied: dark (file: %1)").arg(qssPath));
    } else {
        Logger::warn(QStringLiteral("Could not open stylesheet: %1").arg(qssPath));
    }
}

QString ThemeManager::trayStyleSheet()
{
    return QStringLiteral(
        "QMenu { font-family: 'Nunito', 'Segoe UI', sans-serif; background-color: #0c1322; color: #F1F5F9; border: 1px solid #1e293b; border-radius: 10px; padding: 6px; }\n"
        "QMenu::item { font-family: 'Nunito', 'Segoe UI', sans-serif; padding: 8px 24px 8px 14px; border-radius: 6px; font-size: 11px; font-weight: 600; }\n"
        "QMenu::item:selected { background-color: #0284c7; color: #FFFFFF; font-weight: 700; }\n"
        "QMenu::item:disabled { color: #64748b; font-weight: 700; font-size: 10px; }\n"
        "QMenu::separator { height: 1px; background: #1e293b; margin: 4px 8px; }"
    );
}

QString ThemeManager::alertStyleSheet(const QString &accentColor)
{
    return QString(
        "#alertCard {"
        "  background: rgba(18, 22, 34, 0.96);"
        "  border: 1px solid rgba(255, 255, 255, 0.12);"
        "  border-left: 5px solid %1;"
        "  border-radius: 10px;"
        "}"
        "QLabel { color: #F1F5F9; }"
    ).arg(accentColor);
}

} // namespace verax
