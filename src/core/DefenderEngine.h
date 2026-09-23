#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QProcess>
#include <QDateTime>
#include <QTime>
#include <QTimer>
#include <QList>
#include <QSet>
#include "Scanner.h"

namespace verax {

struct DefenderStatus {
    bool known = false;
    QString error;
    QString runningMode;
    bool antivirusEnabled = false;
    bool realTimeProtectionEnabled = false;
    bool cloudProtectionEnabled = false;
    bool behaviorMonitorEnabled = false;
    bool ioavProtectionEnabled = false;
    QString engineVersion;
    QString signatureVersion;
    QDateTime signatureLastUpdated;
};

struct DefenderQuarantineItem {
    QString id;
    QString name;
    QString path;
    QString severity;
    QDateTime detectedTime;
    bool actionSuccess = false;
    int actionId = 0;
    bool active = false;
};

class DefenderEngine : public QObject {
    Q_OBJECT
public:
    enum ScanMode {
        Quick = 0,
        Full = 1,
        Custom = 2
    };

    static DefenderEngine& instance();

    // Check if Windows Defender tooling is available
    bool isAvailable() const;
    QString mpCmdRunPath() const;

    // Advanced Scans
    bool startScan(ScanMode mode, const QStringList &customPaths = {});
    bool startOfflineScan();
    void cancelScan();
    bool isScanning() const { return m_isScanning; }
    QString lastError() const { return m_lastError; }
    bool canCancel() const { return m_currentMode != Custom; }
    bool wasCancelled() const { return m_cancelled; }
    qint64 scanStartedAt() const { return m_startedAt; }

    // Signatures
    bool updateSignatures();

    // Protection settings
    bool isRealTimeProtectionEnabled();
    bool setRealTimeProtection(bool enable);

    bool isCloudProtectionEnabled();
    bool setCloudProtection(bool enable);

    bool isBehaviorMonitoringEnabled();
    bool setBehaviorMonitoring(bool enable);

    bool isNetworkProtectionEnabled();
    bool setNetworkProtection(bool enable);

    bool isControlledFolderAccessEnabled();
    bool setControlledFolderAccess(bool enable);

    // Attack Surface Reduction (ASR)
    bool isAsrRulesEnabled();
    bool enableAsrRules(bool enable);

    // Defender Scheduled Scan
    bool setScheduledScan(bool enable, int dayOfWeek = 0, const QTime &time = QTime(12, 0));

    // Dynamic Exclusion Management
    bool addDefenderExclusion(const QString &path);
    bool removeDefenderExclusion(const QString &path);

    // Telemetry & Status
    DefenderStatus getStatus();

    // Quarantine management
    QList<DefenderQuarantineItem> getQuarantineItems(); // Detection history, not a quarantine inventory.
    QString quarantineListing(bool *ok = nullptr);
    bool remediateActiveThreats();
    bool setArchiveScanning(bool enable);
    bool archiveScanningEnabled();
    QStringList exclusions();
    bool setScanCpuLimit(int percent);
    int scanCpuLimit();
    bool restoreQuarantinedItem(const QString &threatName);
    bool removeQuarantinedItem(const QString &threatName);
    bool purgeAllQuarantine();

signals:
    void scanStarted(const QString &scanType);
    void scanProgress(int percent, const QString &statusText);
    void fileScanned(const QString &filePath);
    void threatDetected(const ThreatInfo &threat);
    void scanFinished(bool success, int threatsCount, const QList<ThreatInfo> &threats);
    void signaturesUpdated(bool success, const QString &version);
    void protectionStateChanged(bool enabled);

#ifdef MULTIGUARD_TESTING
public:
    void setScanExecutableForTests(const QString &path) { m_mpCmdRunPath = path; }
#endif
private slots:
    void onProcessReadyRead();
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProgressTimerTick();

private:
    DefenderEngine();
    ~DefenderEngine() override;

    void locateMpCmdRun();
    QString runPowerShellCommand(const QString &command, bool *ok = nullptr);
    void startNextCustomTarget();
    void launchScan(const QStringList &args);
    void finishScan();

    QString   m_mpCmdRunPath;
    bool      m_isScanning = false;
    QProcess *m_scanProcess = nullptr;
    QTimer   *m_progressTimer = nullptr;

    ScanMode m_currentMode = Quick;
    QList<ThreatInfo> m_detectedThreats;
    QString m_processOutput;
    QString m_lastError;
    QSet<QString> m_seenDetectionIds;
    bool m_cancelled = false;
    bool m_hadError = false;
    qint64 m_startedAt = 0;

    QStringList m_pendingCustomPaths;
    int m_totalCustomPaths = 0;
};

} // namespace verax
