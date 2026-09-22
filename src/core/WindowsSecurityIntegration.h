#pragma once

#include <QString>
#include "WindowsSecurityCenterProvider.h"

namespace verax {

/**
 * @brief WindowsSecurityIntegration
 * 
 * Fasada integracji z Windows Security Center zapewniająca wsteczną kompatybilność.
 * Deleguje operacje do WindowsSecurityCenterProvider.
 * Zgodna z wytycznymi Microsoftu - nie modyfikuje rejestru Defendera, nie dodaje
 * automatycznych wykluczeń Add-MpPreference i nie forsuje zmian uprawnień.
 */
class WindowsSecurityIntegration {
public:
    static const QString INSTANCE_GUID;

    // Odświeża stan produktu w module dostawcy WSC
    static bool registerAntivirus(const QString &installDir = QString(), const QString &exePath = QString());

    // Odświeża stan produktu na podstawie parametrów
    static bool updateProductState(bool enabled, bool upToDate = true);

    // Wyrejestrowanie produktu (np. przy deinstalacji)
    static bool unregisterAntivirus();

    // Kompatybilność wsteczna - bezpieczne no-op (decyzję o stanie Defendera podejmuje wyłącznie system Windows)
    static bool disableDefender();
    static bool restoreDefender();
};

} // namespace verax
