#include "DefenderEngine.h"
#include "Logger.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCoreApplication>
#include <QTimer>

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
    cancelScan();
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
#ifdef Q_OS_WIN
    return !m_mpCmdRunPath.isEmpty() && QFile::exists(m_mpCmdRunPath);
#else
    return false;
#endif
}

QString DefenderEngine::mpCmdRunPath() const
{
    return m_mpCmdRunPath;
}

QString DefenderEngine::runPowerShellCommand(const QString &command)
{
#ifdef Q_OS_WIN
    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000; /* CREATE_NO_WINDOW */
    });

    QStringList args;
    args << QStringLiteral("-NoProfile")
         << QStringLiteral("-NonInteractive")
         << QStringLiteral("-ExecutionPolicy") << QStringLiteral("Bypass")
         << QStringLiteral("-Command") << command;

    proc.start(QStringLiteral("powershell.exe"), args);
    if (!proc.waitForStarted(3000)) return QString();
    if (!proc.waitForFinished(10000)) {
        proc.kill();
        return QString();
    }
    return QString::fromUtf8(proc.readAllStandardOutput()).trimmed();
#else
    Q_UNUSED(command);
    return QString();
#endif
}

bool DefenderEngine::startScan(ScanMode mode, const QStringList &customPaths)
{
    if (m_isScanning) {
        Logger::warn(QStringLiteral("DefenderEngine: Skanowanie jest już w toku."));
        return false;
    }

    if (!isAvailable()) {
        Logger::warn(QStringLiteral("DefenderEngine: MpCmdRun.exe niedostępny."));
        return false;
    }

    m_currentMode = mode;
    m_detectedThreats.clear();
    m_simulatedPercent = 0;

    if (mode == Custom) {
        m_pendingCustomPaths = customPaths;
        if (m_pendingCustomPaths.isEmpty()) {
            m_pendingCustomPaths << QDir::homePath();
        }
        m_totalCustomPaths = m_pendingCustomPaths.size();
        m_isScanning = true;
        emit scanStarted(tr("Skanowanie obiektów silnikiem Microsoft Defender"));
        startNextCustomTarget();
        return true;
    }

    QString scanTypeName;
    QStringList args;
    if (mode == Quick) {
        scanTypeName = tr("Szybkie skanowanie Microsoft Defender");
        args << QStringLiteral("-Scan") << QStringLiteral("-ScanType") << QStringLiteral("1");
    } else {
        scanTypeName = tr("Pełne skanowanie systemu Microsoft Defender");
        args << QStringLiteral("-Scan") << QStringLiteral("-ScanType") << QStringLiteral("2");
    }

    if (m_scanProcess) {
        m_scanProcess->deleteLater();
        m_scanProcess = nullptr;
    }

    m_scanProcess = new QProcess(this);
#ifdef Q_OS_WIN
    m_scanProcess->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000; /* CREATE_NO_WINDOW */
    });
#endif

    connect(m_scanProcess, &QProcess::readyReadStandardOutput, this, &DefenderEngine::onProcessReadyRead);
    connect(m_scanProcess, &QProcess::readyReadStandardError, this, &DefenderEngine::onProcessReadyRead);
    connect(m_scanProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &DefenderEngine::onProcessFinished);

    m_isScanning = true;
    emit scanStarted(scanTypeName);
    emit scanProgress(5, tr("Inicjalizacja silnika Microsoft Defender..."));

    m_scanProcess->start(m_mpCmdRunPath, args);
    if (!m_scanProcess->waitForStarted(4000)) {
        m_isScanning = false;
        Logger::error(QStringLiteral("DefenderEngine: Nie udało się uruchomić procesu skanera Defender."));
        emit scanFinished(false, 0, {});
        return false;
    }

    return true;
}

void DefenderEngine::startNextCustomTarget()
{
    if (m_pendingCustomPaths.isEmpty()) {
        m_isScanning = false;
        emit scanProgress(100, tr("Skanowanie obiektów silnikiem Defender zakończone."));
        emit scanFinished(true, m_detectedThreats.size(), m_detectedThreats);
        return;
    }

    QString currentTarget = m_pendingCustomPaths.takeFirst();
    int completed = m_totalCustomPaths - m_pendingCustomPaths.size();
    int pct = qBound(5, (completed * 100) / qMax(1, m_totalCustomPaths), 95);

    emit scanProgress(pct, tr("Skanowanie (%1/%2): %3")
        .arg(completed).arg(m_totalCustomPaths).arg(QFileInfo(currentTarget).fileName()));
    emit fileScanned(currentTarget);

    QStringList args;
    args << QStringLiteral("-Scan") << QStringLiteral("-ScanType") << QStringLiteral("3")
         << QStringLiteral("-File") << QDir::toNativeSeparators(currentTarget);

    if (m_scanProcess) {
        m_scanProcess->deleteLater();
        m_scanProcess = nullptr;
    }
    m_scanProcess = new QProcess(this);
#ifdef Q_OS_WIN
    m_scanProcess->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000;
    });
#endif
    connect(m_scanProcess, &QProcess::readyReadStandardOutput, this, &DefenderEngine::onProcessReadyRead);
    connect(m_scanProcess, &QProcess::readyReadStandardError, this, &DefenderEngine::onProcessReadyRead);
    connect(m_scanProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &DefenderEngine::onProcessFinished);

    m_scanProcess->start(m_mpCmdRunPath, args);
    if (!m_scanProcess->waitForStarted(4000)) {
        Logger::error(QStringLiteral("DefenderEngine: Błąd uruchomienia skanu dla %1").arg(currentTarget));
        startNextCustomTarget();
    }
}

void DefenderEngine::cancelScan()
{
    m_pendingCustomPaths.clear();
    if (m_scanProcess && m_scanProcess->state() != QProcess::NotRunning) {
        m_scanProcess->kill();
        m_scanProcess->waitForFinished(2000);
    }
    if (m_isScanning) {
        m_isScanning = false;
        emit scanFinished(false, m_detectedThreats.size(), m_detectedThreats);
    }
}

void DefenderEngine::onProcessReadyRead()
{
    if (!m_scanProcess) return;

    QByteArray out = m_scanProcess->readAllStandardOutput();
    QByteArray err = m_scanProcess->readAllStandardError();
    QString text = QString::fromLocal8Bit(out + err);

    if (text.isEmpty()) return;

    // Advance simulated progress smoothly for Quick/Full scans
    if (m_currentMode != Custom || m_totalCustomPaths <= 1) {
        m_simulatedPercent = qMin(94, m_simulatedPercent + 4);
        emit scanProgress(m_simulatedPercent, tr("Trwa analiza silnikiem Microsoft Defender..."));
    }

    // Check if threat detected
    static QRegularExpression threatRx(
        QStringLiteral("(?:Threat|ThreatName|Zagrożenie)\\s*:\\s*([A-Za-z0-9_\\-\\.:/!]+)"),
        QRegularExpression::CaseInsensitiveOption);
    static QRegularExpression resRx(
        QStringLiteral("(?:Resources|file|Zasoby)\\s*:\\s*(?:file:)?([^\r\n]+)"),
        QRegularExpression::CaseInsensitiveOption);

    auto threatMatch = threatRx.match(text);
    if (threatMatch.hasMatch()) {
        ThreatInfo info;
        info.detectionName = threatMatch.captured(1).trimmed();
        info.family = info.detectionName.section(QLatin1Char('/'), 0, 0).section(QLatin1Char(':'), -1, -1);
        if (info.family.isEmpty()) info.family = QStringLiteral("Malware");

        auto resMatch = resRx.match(text);
        if (resMatch.hasMatch()) {
            info.path = resMatch.captured(1).trimmed();
        } else {
            info.path = tr("Wykryto przez Microsoft Defender");
        }
        info.severity = 10;
        info.repairable = false;
        info.reason = tr("Wykryto zagrożenie: %1").arg(info.detectionName);

        bool alreadyReported = false;
        for (const auto &ex : m_detectedThreats) {
            if (ex.detectionName == info.detectionName && ex.path == info.path) {
                alreadyReported = true;
                break;
            }
        }
        if (!alreadyReported) {
            m_detectedThreats.append(info);
            emit threatDetected(info);
        }
    }
}

void DefenderEngine::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    // If exit code is 2 (threat detected) but not parsed from buffer, check quarantine
    if (exitCode == 2 && m_detectedThreats.isEmpty()) {
        auto latest = getQuarantineItems();
        if (!latest.isEmpty()) {
            ThreatInfo info;
            info.detectionName = latest.first().name;
            info.path = latest.first().path.isEmpty() ? tr("Wykryto przez Microsoft Defender") : latest.first().path;
            info.severity = 10;
            info.family = info.detectionName.section(QLatin1Char('/'), 0, 0).section(QLatin1Char(':'), -1, -1);
            info.reason = tr("Zagrożenie wykryte przez silnik Microsoft Defender");
            m_detectedThreats.append(info);
            emit threatDetected(info);
        }
    }

    if (m_currentMode == Custom && !m_pendingCustomPaths.isEmpty()) {
        startNextCustomTarget();
        return;
    }

    m_isScanning = false;
    bool success = (exitStatus == QProcess::NormalExit && (exitCode == 0 || exitCode == 2));
    emit scanProgress(100, tr("Skanowanie silnikiem Defender zakończone."));
    emit scanFinished(success, m_detectedThreats.size(), m_detectedThreats);

    Logger::info(QStringLiteral("DefenderEngine: Skanowanie zakończone z kodem %1. Wykryto zagrożeń: %2")
        .arg(exitCode).arg(m_detectedThreats.size()));
}

bool DefenderEngine::updateSignatures()
{
    if (!isAvailable()) return false;

    QProcess proc;
#ifdef Q_OS_WIN
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000;
    });
#endif

    proc.start(m_mpCmdRunPath, { QStringLiteral("-SignatureUpdate") });
    if (!proc.waitForStarted(3000)) return false;
    bool finished = proc.waitForFinished(30000);

    bool ok = (finished && proc.exitCode() == 0);
    DefenderStatus st = getStatus();
    emit signaturesUpdated(ok, st.signatureVersion);
    return ok;
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
    return true; // default safe
}

bool DefenderEngine::setRealTimeProtection(bool enable)
{
    QString cmd = QStringLiteral("Set-MpPreference -DisableRealtimeMonitoring %1")
                  .arg(enable ? QStringLiteral("$false") : QStringLiteral("$true"));
    runPowerShellCommand(cmd);

    bool currentState = isRealTimeProtectionEnabled();
    emit protectionStateChanged(currentState);
    return currentState == enable;
}

DefenderStatus DefenderEngine::getStatus()
{
    DefenderStatus status;
    QString json = runPowerShellCommand(
        QStringLiteral("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, AMServiceVersion | ConvertTo-Json")
    );

    if (!json.isEmpty()) {
        QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            status.realTimeProtectionEnabled = obj.value(QStringLiteral("RealTimeProtectionEnabled")).toBool(true);
            status.signatureVersion = obj.value(QStringLiteral("AntivirusSignatureVersion")).toString();
            status.engineVersion = obj.value(QStringLiteral("AMServiceVersion")).toString();
        }
    }
    return status;
}

QList<DefenderQuarantineItem> DefenderEngine::getQuarantineItems()
{
    QList<DefenderQuarantineItem> items;
    QString json = runPowerShellCommand(
        QStringLiteral("Get-MpThreatDetection | Select-Object InitialDetectionTime, ThreatName, Resources | ConvertTo-Json")
    );

    if (json.isEmpty()) return items;

    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    QJsonArray arr;
    if (doc.isArray()) {
        arr = doc.array();
    } else if (doc.isObject()) {
        arr.append(doc.object());
    }

    for (const auto &val : arr) {
        QJsonObject obj = val.toObject();
        DefenderQuarantineItem it;
        it.name = obj.value(QStringLiteral("ThreatName")).toString();
        it.detectedTime = QDateTime::currentDateTime();
        it.severity = QStringLiteral("Wysoki");
        if (obj.contains(QStringLiteral("Resources"))) {
            it.path = obj.value(QStringLiteral("Resources")).toString();
        }
        if (!it.name.isEmpty()) {
            items.append(it);
        }
    }
    return items;
}

bool DefenderEngine::restoreQuarantinedItem(const QString &threatName)
{
    if (threatName.isEmpty() || !isAvailable()) return false;

    QProcess proc;
#ifdef Q_OS_WIN
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= 0x08000000;
    });
#endif
    proc.start(m_mpCmdRunPath, { QStringLiteral("-Restore"), QStringLiteral("-Name"), threatName });
    if (!proc.waitForStarted(3000)) return false;
    return proc.waitForFinished(10000) && (proc.exitCode() == 0);
}

bool DefenderEngine::removeQuarantinedItem(const QString &threatName)
{
    QString cmd = QStringLiteral("Remove-MpThreat");
    if (!threatName.isEmpty()) {
        cmd = QStringLiteral("Get-MpThreatDetection | Where-Object { $_.ThreatName -eq '%1' } | Remove-MpThreat").arg(threatName);
    }
    runPowerShellCommand(cmd);
    return true;
}

bool DefenderEngine::purgeAllQuarantine()
{
    runPowerShellCommand(QStringLiteral("Remove-MpThreat"));
    return true;
}

bool DefenderEngine::startOfflineScan()
{
    QString out = runPowerShellCommand(QStringLiteral("Start-MpWDOScan"));
    return true;
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
    runPowerShellCommand(cmd);
    return true;
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
    runPowerShellCommand(cmd);
    return true;
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
    runPowerShellCommand(cmd);
    return true;
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
    runPowerShellCommand(cmd);
    return true;
}

} // namespace verax
