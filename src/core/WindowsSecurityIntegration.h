#pragma once

#include <QString>

namespace verax {

class WindowsSecurityIntegration {
public:
    static const QString INSTANCE_GUID;

    // Registers Multi-Guard as the active Antivirus provider in Windows Security Center (root\SecurityCenter2)
    // and disables Microsoft Defender real-time monitoring to prevent conflicting scans.
    static bool registerAntivirus(const QString &installDir = QString(), const QString &exePath = QString());

    // Updates the product state in SecurityCenter2 (active / snoozed / up-to-date)
    static bool updateProductState(bool enabled, bool upToDate = true);

    // Unregisters Multi-Guard from Windows Security Center (e.g. on uninstall)
    static bool unregisterAntivirus();

    // Thoroughly disables Microsoft Defender to avoid scanning conflicts and CPU contention
    static bool disableDefender();

    // Configures Defender exclusions and real-time monitoring preferences
    static bool configureDefenderExclusions(const QString &installDir, const QString &exePath);

    // Restores default Defender monitoring if Multi-Guard is uninstalled
    static bool restoreDefender();
};

} // namespace verax
