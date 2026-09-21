#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QSet>
#include <QMap>
#include <QDateTime>
#include <QMutex>
#include "Scanner.h"

class QFileSystemWatcher;
class QTimer;

namespace verax {

class RealTimeShield : public QObject {
    Q_OBJECT
public:
    static RealTimeShield& instance();

    void start();
    void stop();
    bool isRunning() const { return m_running; }

    void setEnabled(bool enable);
    bool isEnabled() const;

    QStringList monitoredPaths() const;
    void addMonitoredPath(const QString &path);
    void removeMonitoredPath(const QString &path);

signals:
    void threatDetected(const verax::ThreatInfo &info);
    void fileScanned(const QString &path);
    void statusChanged(bool active);

private slots:
    void onDirectoryChanged(const QString &path);
    void onFileChanged(const QString &path);
    void processPendingQueue();

private:
    explicit RealTimeShield(QObject *parent = nullptr);
    ~RealTimeShield();

    void scanFileAsync(const QString &filePath);
    bool isSafeToScan(const QString &filePath) const;
    void setupDefaultWatchPaths();

    QFileSystemWatcher *m_watcher = nullptr;
    QTimer             *m_debounceTimer = nullptr;
    QSet<QString>       m_pendingFiles;
    QMap<QString, qint64> m_recentScanned; // path -> lastModified timestamp
    QMutex              m_mutex;
    bool                m_running = false;
};

} // namespace verax
