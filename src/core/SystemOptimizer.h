#pragma once

#include <QString>
#include <QStringList>
#include <QList>
#include <functional>

namespace verax {

struct CleanItem {
    QString id;
    QString name;
    QString description;
    qint64 byteCount = 0;
    int fileCount = 0;
    bool enabled = true;
};

class SystemOptimizer {
public:
    static SystemOptimizer& instance();

    QList<CleanItem> scanSystem();
    qint64 cleanItems(const QStringList &categoryIds);
    void optimizeMemory();

    // File Shredder
    static bool shredFile(const QString &path, std::function<void(int)> progressCb = nullptr);
    static bool shredDirectory(const QString &dirPath, std::function<void(int)> progressCb = nullptr);

    static QString formatBytes(qint64 bytes);

private:
    SystemOptimizer() = default;
    qint64 getDirSize(const QString &path, int &fileCount);
    qint64 cleanDir(const QString &path);
    static bool overwriteFile(const QString &path);
};

} // namespace verax
