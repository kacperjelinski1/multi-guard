#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QProcess>
#include <QDateTime>
#include <QTime>
#include <QList>
#include "Scanner.h"

namespace verax {

struct DefenderStatus {
    bool realTimeProtectionEnabled = true;
    bool cloudProtectionEnabled = true;
    bool behaviorMonitorEnabled = true;
    bool ioavProtectionEnabled = true;
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
    QList<DefenderQuarantineItem> getQuarantineItems();
    bool restoreQuarantinedItem(const QString &threatName);
    bool removeQuarantinedItem(const QString &threatName);
    bool purgeAllQuarantine();

    // Mutual coexistence & Notification suppression
    bool ensureMutualExclusions();
    bool suppressDefenderPopups();
    bool hijackDefenderTrayAndSettings();

signals:
    void scanStarted(const QString &scanType);
    void scanProgress(int percent, const QString &statusText);
    void fileScanned(const QString &filePath);
    void threatDetected(const ThreatInfo &threat);
    void scanFinished(bool success, int threatsCount, const QList<ThreatInfo> &threats);
    void signaturesUpdated(bool success, const QString &version);
    void protectionStateChanged(bool enabled);

private slots:
    void onProcessReadyRead();
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProgressTimerTick();

private:
    DefenderEngine();
    ~DefenderEngine() override;

    void locateMpCmdRun();
    static QString runPowerShellCommand(const QString &command);
    void startNextCustomTarget();

    QString   m_mpCmdRunPath;
    bool      m_isScanning = false;
    QProcess *m_scanProcess = nullptr;
    QTimer   *m_progressTimer = nullptr;

    ScanMode m_currentMode = Quick;
    QList<ThreatInfo> m_detectedThreats;
    int m_simulatedPercent = 0;

    QStringList m_pendingCustomPaths;
    int m_totalCustomPaths = 0;
};

} // namespace verax
