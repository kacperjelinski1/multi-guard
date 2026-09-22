// WindowsSecurityIntegration.cpp
// Facade delegating to WindowsSecurityCenterProvider
#include "WindowsSecurityIntegration.h"
#include "WindowsSecurityCenterProvider.h"
#include "Logger.h"
#include "../../Version.h"

namespace verax {

const QString WindowsSecurityIntegration::INSTANCE_GUID = WindowsSecurityCenterProvider::PRODUCT_GUID;

bool WindowsSecurityIntegration::registerAntivirus(const QString &installDir, const QString &exePath)
{
    Q_UNUSED(installDir);
    Q_UNUSED(exePath);
    return WindowsSecurityCenterProvider::instance().refreshStatus();
}

bool WindowsSecurityIntegration::updateProductState(bool enabled, bool upToDate)
{
    Q_UNUSED(enabled);
    Q_UNUSED(upToDate);
    return WindowsSecurityCenterProvider::instance().refreshStatus();
}

bool WindowsSecurityIntegration::unregisterAntivirus()
{
    return WindowsSecurityCenterProvider::instance().unregisterProduct();
}

bool WindowsSecurityIntegration::disableDefender()
{
    // Zgodnie z oficjalnymi zasadami Microsoftu, aplikacja zewnętrzna NIE wyłącza Defendera.
    // Jeżeli produkt zostanie oficjalnie zarejestrowany w WSC, Windows sam podejmuje decyzję o uśpieniu Defendera.
    Logger::info("WindowsSecurityIntegration: Zarządzanie stanem Defendera pozostawione w całości systemowi operacyjnemu (brak ręcznych modyfikacji).");
    return true;
}

bool WindowsSecurityIntegration::restoreDefender()
{
    Logger::info("WindowsSecurityIntegration: Przywrócenie Defendera jest zarządzane natywnie przez Windows Security Center.");
    return true;
}

} // namespace verax
