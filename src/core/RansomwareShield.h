#pragma once

#include <QObject>
#include <QStringList>
#include <QDateTime>
#include <QMap>
#include <QVector>
#include <memory>

class QFileSystemWatcher;

namespace verax {

class RansomwareShield : public QObject {
    Q_OBJECT

public:
    static RansomwareShield& instance();

    bool isEnabled() const { return m_enabled; }
    void setEnabled(bool enabled);

    void addProtectedFolder(const QString &path);
    QStringList protectedFolders() const { return m_protectedFolders; }

signals:
    void ransomwareActivityDetected(const QString &folder, const QString &description);

public slots:
    void onDirectoryChanged(const QString &path);
    void onFileChanged(const QString &path);

private:
    explicit RansomwareShield(QObject *parent = nullptr);
    ~RansomwareShield() override = default;

    void setupWatchers();
    void seedCanaryFiles();
    bool checkCanaryFiles();
    static double calculateEntropy(const QString &filePath);
    static bool hasRansomwareExtension(const QString &filePath);

    bool m_enabled = true;
    QStringList m_protectedFolders;
    std::unique_ptr<QFileSystemWatcher> m_watcher;

    // Burst rate tracking for rapid modifications
    QMap<QString, QVector<qint64>> m_modHistory; // folder -> timestamps in ms
    QMap<QString, QString> m_canaryHashes;       // filePath -> original hash
};

} // namespace verax
