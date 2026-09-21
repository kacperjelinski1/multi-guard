#pragma once

#include <QString>

namespace verax {

class ThemeManager {
public:
    enum Mode {
        Dark,
        Light,
        System
    };

    static void applyTheme(const QString &themeMode = QString());
    static bool isDark();
    static QString effectiveTheme(); // "dark" or "light"

    static QString trayStyleSheet();
    static QString alertStyleSheet(const QString &accentColor);
};

} // namespace verax
