#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QProcess>
#include <QDateTime>
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
    static DefenderEngine& instance();

    // Check if Windows Defender tooling is available
    bool isAvailable() const;
    QString mpCmdRunPath() const;

    // Scans
    bool startScan(Scanner::ScanMode mode, const QStringList &customPaths = {});
    void cancelScan();
    bool isScanning() const { return m_isScanning; }

    // Signatures
    bool updateSignatures();

    // Protection settings
    bool isRealTimeProtectionEnabled();
    bool setRealTimeProtection(bool enable);

    // Telemetry & Status
    DefenderStatus getStatus();

    // Quarantine management
    QList<DefenderQuarantineItem> getQuarantineItems();
    bool restoreQuarantinedItem(const QString &threatName);
    bool removeQuarantinedItem(const QString &threatName);

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

private:
    DefenderEngine();
    ~DefenderEngine() override;

    void locateMpCmdRun();
    static QString runPowerShellCommand(const QString &command);

    QString   m_mpCmdRunPath;
    bool      m_isScanning = false;
    QProcess *m_scanProcess = nullptr;

    Scanner::ScanMode m_currentMode = Scanner::Quick;
    QList<ThreatInfo> m_detectedThreats;
    int m_simulatedPercent = 0;
};

} // namespace verax
