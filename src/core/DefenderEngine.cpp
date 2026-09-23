#include "DefenderEngine.h"
#include "Logger.h"
#include "WindowsCommand.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCoreApplication>
#include <QTimer>
#include <QSettings>
#include <QTime>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace verax {

DefenderEngine& DefenderEngine::instance()
{
    static DefenderEngine s_instance;
    return s_instance;
}

DefenderEngine::DefenderEngine()
{
    locateMpCmdRun();
}

DefenderEngine::~DefenderEngine()
{
    if (m_scanProcess) m_scanProcess->disconnect(this);
}

void DefenderEngine::locateMpCmdRun()
{
#ifdef Q_OS_WIN
    // 1. Search modern Windows 10/11 Platform directory
    QDir platformDir(QStringLiteral("C:/ProgramData/Microsoft/Windows Defender/Platform"));
    if (platformDir.exists()) {
        const QStringList subDirs = platformDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name | QDir::Reversed);
        for (const QString &d : subDirs) {
            QString candidate = platformDir.filePath(d + QStringLiteral("/MpCmdRun.exe"));
            if (QFile::exists(candidate)) {
                m_mpCmdRunPath = candidate;
                break;
            }
        }
    }

    // 2. Search default Program Files location
    if (m_mpCmdRunPath.isEmpty()) {
        QString standardPath = QStringLiteral("C:/Program Files/Windows Defender/MpCmdRun.exe");
        if (QFile::exists(standardPath)) {
            m_mpCmdRunPath = standardPath;
        }
    }

    // 3. Search Program Files (x86) fallback
    if (m_mpCmdRunPath.isEmpty()) {
        QString x86Path = QStringLiteral("C:/Program Files (x86)/Windows Defender/MpCmdRun.exe");
        if (QFile::exists(x86Path)) {
            m_mpCmdRunPath = x86Path;
        }
    }
#endif

    if (!m_mpCmdRunPath.isEmpty()) {
        Logger::info(QStringLiteral("DefenderEngine: Zlokalizowano Microsoft Defender CLI: %1").arg(m_mpCmdRunPath));
    } else {
        Logger::warn(QStringLiteral("DefenderEngine: Nie znaleziono MpCmdRun.exe w domyślnych ścieżkach systemowych."));
    }
}

bool DefenderEngine::isAvailable() const
{
#if defined(Q_OS_WIN) || defined(MULTIGUARD_TESTING)
    return !m_mpCmdRunPath.isEmpty() && QFile::exists(m_mpCmdRunPath);
#else
    return false;
#endif
}

QString DefenderEngine::mpCmdRunPath() const
{
    return m_mpCmdRunPath;
}

QString DefenderEngine::runPowerShellCommand(const QString &command, bool *ok)
{
    const auto result = WindowsCommand::powershell(command);
    if (ok) *ok = result.ok;
    m_lastError = result.ok ? QString() : result.error;
    return result.output;
}

bool DefenderEngine::startScan(ScanMode mode, const QStringList &customPaths)
{
    if (m_isScanning) { m_lastError = tr("Skanowanie już trwa."); return false; }
    if (!isAvailable()) { m_lastError = tr("Microsoft Defender jest niedostępny na tym systemie."); return false; }
    if (mode == Custom && customPaths.isEmpty()) { m_lastError = tr("Wybierz plik lub folder."); return false; }
    for (const auto &path : customPaths) {
        if (!QFileInfo::exists(path)) { m_lastError = tr("Nie znaleziono: %1").arg(path); return false; }
    }
    m_seenDetectionIds.clear();
    const auto previous = getQuarantineItems();
    if (!m_lastError.isEmpty()) return false; // No baseline means no reliable delta.
    for (const auto &item : previous) m_seenDetectionIds.insert(item.id);
    m_currentMode = mode;
    m_detectedThreats.clear();
    m_pendingCustomPaths = customPaths;
    m_totalCustomPaths = customPaths.size();
    m_cancelled = false; m_hadError = false; m_lastError.clear();
    m_startedAt = QDateTime::currentSecsSinceEpoch();
    m_isScanning = true;
    emit scanStarted(mode == Quick ? tr("Szybkie skanowanie Microsoft Defender")
        : mode == Full ? tr("Pełne skanowanie Microsoft Defender") : tr("Skanowanie niestandardowe Microsoft Defender"));
    if (!m_progressTimer) {
        m_progressTimer = new QTimer(this);
        connect(m_progressTimer, &QTimer::timeout, this, &DefenderEngine::onProgressTimerTick);
    }
    m_progressTimer->start(1000);
    if (mode == Custom) startNextCustomTarget();
    else launchScan({"-Scan", "-ScanType", mode == Quick ? "1" : "2"});
    return true;
}

void DefenderEngine::launchScan(const QStringList &args)
{
    if (m_scanProcess) { m_scanProcess->disconnect(this); m_scanProcess->deleteLater(); }
    m_scanProcess = new QProcess(this);
#ifdef Q_OS_WIN
    m_scanProcess->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *a){ a->flags |= 0x08000000; });
#endif
    m_processOutput.clear();
    connect(m_scanProcess, &QProcess::readyReadStandardOutput, this, &DefenderEngine::onProcessReadyRead);
    connect(m_scanProcess, &QProcess::readyReadStandardError, this, &DefenderEngine::onProcessReadyRead);
    connect(m_scanProcess, QOverload<int,QProcess::ExitStatus>::of(&QProcess::finished), this, &DefenderEngine::onProcessFinished);
    m_scanProcess->start(m_mpCmdRunPath, args);
    if (!m_scanProcess->waitForStarted(4000)) {
        m_hadError = true;
        m_lastError = m_scanProcess->errorString();
        finishScan();
    }
}

void DefenderEngine::startNextCustomTarget()
{
    if (m_pendingCustomPaths.isEmpty()) { finishScan(); return; }
    const QString target = m_pendingCustomPaths.takeFirst();
    emit fileScanned(target); // Target only: never interpreted as a file counter.
    launchScan({"-Scan", "-ScanType", "3", "-File", QDir::toNativeSeparators(target)});
}

void DefenderEngine::cancelScan()
{
    if (!m_isScanning) return;
    if (!canCancel()) { m_lastError = tr("MpCmdRun obsługuje anulowanie tylko szybkiego i pełnego skanowania."); return; }
    const auto result = WindowsCommand::run(m_mpCmdRunPath, {"-Scan", "-Cancel"});
    if (!result.ok) { m_lastError = result.error; return; }
    // Keep the original process and lock until it actually finishes.
    m_cancelled = true;
    emit scanProgress(-1, tr("Wysłano żądanie anulowania; oczekiwanie na zakończenie Defendera."));
}

void DefenderEngine::onProcessReadyRead()
{
    if (!m_scanProcess) return;
    m_processOutput += QString::fromLocal8Bit(m_scanProcess->readAllStandardOutput() + m_scanProcess->readAllStandardError());
    if (m_processOutput.size() > 65536) m_processOutput = m_processOutput.right(65536);
}

void DefenderEngine::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    onProcessReadyRead();
    // Microsoft documents 2 as either an unresolved detection OR a scan error.
    // Never manufacture a Trojan or claim a successful clean scan from this code.
    if (exitStatus != QProcess::NormalExit || exitCode != 0) {
        m_hadError = true;
        m_lastError = tr("Defender: kod %1. Wymagana kontrola wyniku/remediacji. %2").arg(exitCode).arg(m_processOutput.trimmed());
    }
    if (!m_cancelled && !m_hadError && m_currentMode == Custom && !m_pendingCustomPaths.isEmpty()) startNextCustomTarget();
    else finishScan();
}

void DefenderEngine::finishScan()
{
    const QString scanError = m_lastError;
    const auto detections = getQuarantineItems();
    const QString detectionError = m_lastError;
    m_lastError = scanError;
    if (!detectionError.isEmpty()) { m_hadError = true; m_lastError += " " + detectionError; }
    for (const auto &item : detections) {
        if (m_seenDetectionIds.contains(item.id)) continue;
        // This delta can include simultaneous real-time detections. The UI labels it accordingly.
        ThreatInfo info;
        info.path = item.path; info.detectionName = item.name; info.severity = 5;
        info.reason = tr("Nowe zdarzenie Defendera w czasie skanowania; akcja %1, powodzenie: %2").arg(item.actionId).arg(item.actionSuccess);
        m_detectedThreats.append(info);
        emit threatDetected(info);
    }
    m_isScanning = false;
    if (m_progressTimer) m_progressTimer->stop();
    emit scanFinished(!m_hadError && !m_cancelled, m_detectedThreats.size(), m_detectedThreats);
}

void DefenderEngine::onProgressTimerTick()
{
    if (!m_isScanning) return;
    const qint64 elapsed = QDateTime::currentSecsSinceEpoch() - m_startedAt;
    emit scanProgress(-1, tr("Microsoft Defender: %1 s. Procent i liczba plików nie są udostępniane.%2")
        .arg(elapsed).arg(m_cancelled ? tr(" Oczekiwanie na anulowanie.") : QString()));
}

bool DefenderEngine::updateSignatures()
{
    if (!isAvailable()) return false;

    QProcess *proc = new QProcess(this);
#ifdef Q_OS_WIN
    proc->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000;
    });
#endif

    connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, proc](int exitCode, QProcess::ExitStatus exitStatus) {
        bool ok = (exitStatus == QProcess::NormalExit && exitCode == 0);
        DefenderStatus st = getStatus();
        emit signaturesUpdated(ok, st.signatureVersion);
        proc->deleteLater();
    });

    proc->start(m_mpCmdRunPath, { QStringLiteral("-SignatureUpdate") });
    if (!proc->waitForStarted(3000)) {
        proc->deleteLater();
        emit signaturesUpdated(false, QString());
        return false;
    }
    return true;
}

bool DefenderEngine::isRealTimeProtectionEnabled()
{
    QString out = runPowerShellCommand(QStringLiteral("(Get-MpComputerStatus).RealTimeProtectionEnabled"));
    if (out.compare(QStringLiteral("True"), Qt::CaseInsensitive) == 0) {
        return true;
    }
    if (out.compare(QStringLiteral("False"), Qt::CaseInsensitive) == 0) {
        return false;
    }
    return false; // Unknown must never be shown as protected.
}

bool DefenderEngine::setRealTimeProtection(bool enable)
{
    QString cmd = QStringLiteral("Set-MpPreference -DisableRealtimeMonitoring %1")
                  .arg(enable ? QStringLiteral("$false") : QStringLiteral("$true"));
    bool ok = false;
    runPowerShellCommand(cmd, &ok);

    bool currentState = isRealTimeProtectionEnabled();
    emit protectionStateChanged(currentState);
    return ok && currentState == enable;
}

DefenderStatus DefenderEngine::getStatus()
{
    DefenderStatus status;
    const auto result = WindowsCommand::powershell(
        "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMRunningMode,AntivirusSignatureVersion,AMServiceVersion,BehaviorMonitorEnabled,IoavProtectionEnabled | ConvertTo-Json -Compress");
    if (!result.ok) { status.error = result.error; return status; }
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(result.output.toUtf8(), &error);
    if (!doc.isObject() || !doc.object().value("RealTimeProtectionEnabled").isBool() || !doc.object().value("AntivirusEnabled").isBool()) {
        status.error = tr("Nieprawidłowa odpowiedź stanu Microsoft Defender."); return status;
    }
    const auto obj = doc.object();
    status.known = true;
    status.realTimeProtectionEnabled = obj.value("RealTimeProtectionEnabled").toBool();
    status.antivirusEnabled = obj.value("AntivirusEnabled").toBool();
    status.behaviorMonitorEnabled = obj.value("BehaviorMonitorEnabled").toBool();
    status.ioavProtectionEnabled = obj.value("IoavProtectionEnabled").toBool();
    status.runningMode = obj.value("AMRunningMode").toString();
    status.signatureVersion = obj.value("AntivirusSignatureVersion").toString();
    status.engineVersion = obj.value("AMServiceVersion").toString();
    return status;
}

QList<DefenderQuarantineItem> DefenderEngine::getQuarantineItems()
{
    QList<DefenderQuarantineItem> items;
    // Get-MpThreatDetection contains history, not the quarantine inventory.
    // Join ThreatID to Get-MpThreat to obtain names; serialize arrays and dates explicitly.
    bool ok = false;
    const QString json = runPowerShellCommand(
        "$names=@{}; Get-MpThreat | ForEach-Object { $names[[string]$_.ThreatID]=$_ }; "
        "ConvertTo-Json -Depth 4 -Compress -InputObject @((Get-MpThreatDetection) | ForEach-Object { $t=$names[[string]$_.ThreatID]; "
        "[pscustomobject]@{ id=[string]$_.DetectionID; name=if($t){$t.ThreatName}else{[string]$_.ThreatID}; "
        "path=($_.Resources -join '; '); time=$_.InitialDetectionTime.ToUniversalTime().ToString('o'); "
        "action=[int]$_.CleaningActionID; success=[bool]$_.ActionSuccess; active=if($t){[bool]$t.IsActive}else{$false} } })", &ok);
    if (!ok) return items;
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(json.toUtf8(), &error);
    if (!doc.isArray() && !doc.isObject()) { m_lastError = tr("Nieprawidłowa odpowiedź historii Defendera."); return items; }
    const auto array = doc.isArray() ? doc.array() : QJsonArray{doc.object()};
    for (const auto &value : array) {
        const auto obj = value.toObject();
        DefenderQuarantineItem item;
        item.id=obj.value("id").toString(); item.name=obj.value("name").toString(); item.path=obj.value("path").toString();
        item.detectedTime=QDateTime::fromString(obj.value("time").toString(), Qt::ISODateWithMs);
        item.actionId=obj.value("action").toInt(); item.actionSuccess=obj.value("success").toBool(); item.active=obj.value("active").toBool();
        if (!item.id.isEmpty()) items.append(item);
    }
    return items;
}

QString DefenderEngine::quarantineListing(bool *ok)
{
    const auto result = WindowsCommand::run(m_mpCmdRunPath, {"-Restore", "-ListAll"});
    if (ok) *ok = result.ok;
    m_lastError = result.error;
    return result.ok ? result.output : result.error;
}

bool DefenderEngine::remediateActiveThreats()
{
    bool ok = false;
    runPowerShellCommand("Remove-MpThreat", &ok);
    return ok;
}

bool DefenderEngine::restoreQuarantinedItem(const QString &threatName)
{
    if (threatName.isEmpty() || !isAvailable()) return false;
    const auto result = WindowsCommand::run(m_mpCmdRunPath, {"-Restore", "-Name", threatName});
    m_lastError = result.error;
    return result.ok;
}

bool DefenderEngine::removeQuarantinedItem(const QString &threatName)
{
    Q_UNUSED(threatName);
    m_lastError = tr("Usuwanie konkretnej pozycji kwarantanny jest dostępne w Zabezpieczeniach Windows.");
    return false;
}
bool DefenderEngine::purgeAllQuarantine()
{
    m_lastError = tr("Remove-MpThreat usuwa aktywne zagrożenia, nie opróżnia kwarantanny.");
    return false;
}

bool DefenderEngine::startOfflineScan()
{
    bool ok = false;
    runPowerShellCommand(QStringLiteral("Start-MpWDOScan"), &ok);
    return ok;
}

bool DefenderEngine::isCloudProtectionEnabled()
{
    QString out = runPowerShellCommand(QStringLiteral("(Get-MpPreference).MAPSReporting"));
    int val = out.trimmed().toInt();
    return val > 0;
}

bool DefenderEngine::setCloudProtection(bool enable)
{
    QString cmd = QStringLiteral("Set-MpPreference -MAPSReporting %1").arg(enable ? 2 : 0);
    bool ok = false;
    runPowerShellCommand(cmd, &ok);
    return ok;
}

bool DefenderEngine::isBehaviorMonitoringEnabled()
{
    QString out = runPowerShellCommand(QStringLiteral("(Get-MpComputerStatus).BehaviorMonitorEnabled"));
    return out.compare(QStringLiteral("True"), Qt::CaseInsensitive) == 0;
}

bool DefenderEngine::setBehaviorMonitoring(bool enable)
{
    QString cmd = QStringLiteral("Set-MpPreference -DisableBehaviorMonitoring %1")
                  .arg(enable ? QStringLiteral("$false") : QStringLiteral("$true"));
    bool ok = false;
    runPowerShellCommand(cmd, &ok);
    return ok;
}

bool DefenderEngine::isNetworkProtectionEnabled()
{
    QString out = runPowerShellCommand(QStringLiteral("(Get-MpPreference).EnableNetworkProtection"));
    return out.trimmed() == QStringLiteral("1");
}

bool DefenderEngine::setNetworkProtection(bool enable)
{
    QString cmd = QStringLiteral("Set-MpPreference -EnableNetworkProtection %1")
                  .arg(enable ? QStringLiteral("Enabled") : QStringLiteral("Disabled"));
    bool ok = false;
    runPowerShellCommand(cmd, &ok);
    return ok;
}

bool DefenderEngine::isControlledFolderAccessEnabled()
{
    QString out = runPowerShellCommand(QStringLiteral("(Get-MpPreference).EnableControlledFolderAccess"));
    return out.trimmed() == QStringLiteral("1");
}

bool DefenderEngine::setControlledFolderAccess(bool enable)
{
    QString cmd = QStringLiteral("Set-MpPreference -EnableControlledFolderAccess %1")
                  .arg(enable ? QStringLiteral("Enabled") : QStringLiteral("Disabled"));
    bool ok = false;
    runPowerShellCommand(cmd, &ok);
    return ok;
}

bool DefenderEngine::isAsrRulesEnabled()
{
    QString out = runPowerShellCommand(QStringLiteral("(Get-MpPreference).AttackSurfaceReductionRules_Actions"));
    return out.contains(QStringLiteral("1"));
}

bool DefenderEngine::enableAsrRules(bool enable)
{
    int action = enable ? 1 : 0;
    QString cmd = QStringLiteral(
        "Set-MpPreference -AttackSurfaceReductionRules_Ids "
        "@('be9ba2d9-53ea-44a7-ac61-757b0ee57755',"
        "'d4f940ab-401b-4efc-aadc-ad5f3c50688a',"
        "'3b576869-a4ec-4529-8536-b80a7769e8ac',"
        "'9e6c4e1f-7d60-422f-82fb-6d977e5600dd',"
        "'d1e49aac-8f56-4280-b9ba-993a6d77406c',"
        "'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4') "
        "-AttackSurfaceReductionRules_Actions @(%1,%1,%1,%1,%1,%1)"
    ).arg(action);
    bool ok = false;
    runPowerShellCommand(cmd, &ok);
    return ok;
}

bool DefenderEngine::setScheduledScan(bool enable, int dayOfWeek, const QTime &time)
{
    if (!enable) {
        bool ok = false;
        runPowerShellCommand(QStringLiteral("Set-MpPreference -ScanScheduleDay 8"), &ok);
        return ok;
    }
    QString timeStr = time.toString(QStringLiteral("hh:mm:ss"));
    QString cmd = QStringLiteral("Set-MpPreference -ScanScheduleDay %1 -ScanScheduleQuickScanTime '%2'")
                  .arg(dayOfWeek).arg(timeStr);
    bool ok = false;
    runPowerShellCommand(cmd, &ok);
    return ok;
}

bool DefenderEngine::addDefenderExclusion(const QString &path)
{
    if (path.isEmpty()) return false;
    QString clean = QDir::toNativeSeparators(path);
    clean.replace(QLatin1Char('\''), QStringLiteral("''"));
    bool ok = false;
    runPowerShellCommand(QStringLiteral("Add-MpPreference -ExclusionPath '%1'").arg(clean), &ok);
    return ok;
}

bool DefenderEngine::removeDefenderExclusion(const QString &path)
{
    if (path.isEmpty()) return false;
    QString clean = QDir::toNativeSeparators(path);
    clean.replace(QLatin1Char('\''), QStringLiteral("''"));
    bool ok = false;
    runPowerShellCommand(QStringLiteral("Remove-MpPreference -ExclusionPath '%1'").arg(clean), &ok);
    return ok;
}

bool DefenderEngine::archiveScanningEnabled()
{
    bool ok = false;
    const QString out = runPowerShellCommand("(Get-MpPreference).DisableArchiveScanning", &ok);
    return ok && out.compare("False", Qt::CaseInsensitive) == 0;
}
bool DefenderEngine::setArchiveScanning(bool enable)
{
    bool ok = false;
    runPowerShellCommand(QString("Set-MpPreference -DisableArchiveScanning %1").arg(enable ? "$false" : "$true"), &ok);
    return ok && archiveScanningEnabled() == enable;
}
QStringList DefenderEngine::exclusions()
{
    bool ok = false;
    const QString out = runPowerShellCommand("ConvertTo-Json -InputObject @((Get-MpPreference).ExclusionPath) -Compress", &ok);
    QStringList paths;
    if (ok) for (const auto &value : QJsonDocument::fromJson(out.toUtf8()).array()) if (value.isString()) paths << value.toString();
    return paths;
}
int DefenderEngine::scanCpuLimit()
{
    bool ok = false;
    const QString out = runPowerShellCommand("(Get-MpPreference).ScanAvgCPULoadFactor", &ok);
    return ok ? out.toInt() : -1;
}
bool DefenderEngine::setScanCpuLimit(int percent)
{
    if (percent < 5 || percent > 100) return false;
    bool ok = false;
    runPowerShellCommand(QString("Set-MpPreference -ScanAvgCPULoadFactor %1").arg(percent), &ok);
    return ok && scanCpuLimit() == percent;
}

} // namespace verax
