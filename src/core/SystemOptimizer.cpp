#include "SystemOptimizer.h"
#include "Logger.h"
#include "LicenseManager.h"

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QRandomGenerator>
#include <QProcess>

#ifdef Q_OS_WIN
#include <windows.h>
#include <shellapi.h>
#endif

namespace verax {

SystemOptimizer& SystemOptimizer::instance()
{
    static SystemOptimizer s_inst;
    return s_inst;
}

QString SystemOptimizer::formatBytes(qint64 bytes)
{
    if (bytes < 1024)
        return QString("%1 B").arg(bytes);
    if (bytes < 1024 * 1024)
        return QString("%1 KB").arg(QString::number(bytes / 1024.0, 'f', 1));
    if (bytes < 1024 * 1024 * 1024)
        return QString("%1 MB").arg(QString::number(bytes / (1024.0 * 1024.0), 'f', 1));
    return QString("%1 GB").arg(QString::number(bytes / (1024.0 * 1024.0 * 1024.0), 'f', 2));
}

qint64 SystemOptimizer::getDirSize(const QString &path, int &fileCount)
{
    qint64 total = 0;
    QDir dir(path);
    if (!dir.exists()) return 0;

    QDirIterator it(path, QDir::Files | QDir::NoSymLinks, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        total += it.fileInfo().size();
        ++fileCount;
    }
    return total;
}

QList<CleanItem> SystemOptimizer::scanSystem()
{
    QList<CleanItem> items;

    // 1. User Temp
    {
        CleanItem userTemp;
        userTemp.id = "user_temp";
        userTemp.name = QObject::tr("Pliki tymczasowe użytkownika (%TEMP%)");
        userTemp.description = QObject::tr("Pliki tymczasowe generowane przez aplikacje w bieżącej sesji");
        userTemp.byteCount = getDirSize(QDir::tempPath(), userTemp.fileCount);
        items.append(userTemp);
    }

    // 2. Windows Temp
    {
        CleanItem winTemp;
        winTemp.id = "win_temp";
        winTemp.name = QObject::tr("Pliki tymczasowe systemu Windows");
        winTemp.description = QObject::tr("Logi instalacyjne i pliki tymczasowe systemu Windows");
        QString winTempPath = "C:/Windows/Temp";
#ifdef Q_OS_WIN
        char buf[MAX_PATH];
        if (GetWindowsDirectoryA(buf, MAX_PATH)) {
            winTempPath = QString::fromLocal8Bit(buf) + "/Temp";
        }
#endif
        winTemp.byteCount = getDirSize(winTempPath, winTemp.fileCount);
        items.append(winTemp);
    }

    // 3. Browser Caches
    {
        CleanItem browserCache;
        browserCache.id = "browser_cache";
        browserCache.name = QObject::tr("Pamięć podręczna przeglądarek (Chrome / Edge / Firefox)");
        browserCache.description = QObject::tr("Pobrane miniaturki, skrypty i obrazy z przeglądanych stron WWW");

        QString localAppData = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        QString localAppBase = QDir::cleanPath(localAppData + "/../..");

        QStringList cachePaths = {
            localAppBase + "/Google/Chrome/User Data/Default/Cache/Cache_Data",
            localAppBase + "/Microsoft/Edge/User Data/Default/Cache/Cache_Data"
        };

        // Firefox cache
        QString ffProfiles = localAppBase + "/Mozilla/Firefox/Profiles";
        QDir ffDir(ffProfiles);
        if (ffDir.exists()) {
            const QStringList dirs = ffDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
            for (const QString &d : dirs) {
                cachePaths.append(ffProfiles + "/" + d + "/cache2");
            }
        }

        int count = 0;
        qint64 total = 0;
        for (const QString &cp : cachePaths) {
            total += getDirSize(cp, count);
        }
        browserCache.byteCount = total;
        browserCache.fileCount = count;
        items.append(browserCache);
    }

    // 4. Recycle Bin
    {
        CleanItem bin;
        bin.id = "recycle_bin";
        bin.name = QObject::tr("Kosz systemowy");
        bin.description = QObject::tr("Skasowane pliki przechowywane w Koszu Windows");
#ifdef Q_OS_WIN
        SHQUERYRBINFO rbi;
        ZeroMemory(&rbi, sizeof(rbi));
        rbi.cbSize = sizeof(rbi);
        if (SUCCEEDED(SHQueryRecycleBinW(NULL, &rbi))) {
            bin.byteCount = rbi.i64Size;
            bin.fileCount = static_cast<int>(rbi.i64NumItems);
        }
#endif
        items.append(bin);
    }

    // 5. Windows Thumbnail & Icon Cache
    {
        CleanItem thumbs;
        thumbs.id = "thumb_cache";
        thumbs.name = QObject::tr("Pamięć podręczna miniaturek Eksploratora Windows");
        thumbs.description = QObject::tr("Zbuforowane miniatury zdjęć i filmów w Eksploratorze (thumbcache_*.db)");
        QString localAppData = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        QString explorerDir = QDir::cleanPath(localAppData + "/../../Microsoft/Windows/Explorer");
        QDir expDir(explorerDir);
        if (expDir.exists()) {
            const auto entries = expDir.entryInfoList({"thumbcache_*.db", "iconcache_*.db"}, QDir::Files);
            qint64 sz = 0;
            for (const auto &e : entries) sz += e.size();
            thumbs.byteCount = sz;
            thumbs.fileCount = entries.size();
        }
        items.append(thumbs);
    }

    // 6. DNS Resolver Cache
    {
        CleanItem dns;
        dns.id = "dns_cache";
        dns.name = QObject::tr("Pamięć podręczna resolvera DNS");
        dns.description = QObject::tr("Czyszczenie lokalnego bufora nazw DNS (ipconfig /flushdns)");
        dns.byteCount = 1024 * 128; // est 128 KB
        dns.fileCount = 1;
        items.append(dns);
    }

    return items;
}

qint64 SystemOptimizer::cleanDir(const QString &path)
{
    qint64 freed = 0;
    QDir dir(path);
    if (!dir.exists()) return 0;

    QFileInfoList entries = dir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot, QDir::DirsLast);
    for (const QFileInfo &fi : entries) {
        if (fi.isDir()) {
            freed += cleanDir(fi.absoluteFilePath());
            dir.rmdir(fi.fileName());
        } else if (fi.isFile()) {
            qint64 sz = fi.size();
            if (QFile::remove(fi.absoluteFilePath())) {
                freed += sz;
            }
        }
    }
    return freed;
}

qint64 SystemOptimizer::cleanItems(const QStringList &categoryIds)
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::DiskCleaner)) {
        Logger::warn("SystemOptimizer: Pominięto czyszczenie — brak uprawnień licencyjnych.");
        return 0;
    }

    qint64 totalFreed = 0;

    if (categoryIds.contains("user_temp")) {
        totalFreed += cleanDir(QDir::tempPath());
    }

    if (categoryIds.contains("win_temp")) {
        QString winTempPath = "C:/Windows/Temp";
#ifdef Q_OS_WIN
        char buf[MAX_PATH];
        if (GetWindowsDirectoryA(buf, MAX_PATH)) {
            winTempPath = QString::fromLocal8Bit(buf) + "/Temp";
        }
#endif
        totalFreed += cleanDir(winTempPath);
    }

    if (categoryIds.contains("browser_cache")) {
        QString localAppData = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        QString localAppBase = QDir::cleanPath(localAppData + "/../..");

        QStringList cachePaths = {
            localAppBase + "/Google/Chrome/User Data/Default/Cache/Cache_Data",
            localAppBase + "/Microsoft/Edge/User Data/Default/Cache/Cache_Data"
        };

        QString ffProfiles = localAppBase + "/Mozilla/Firefox/Profiles";
        QDir ffDir(ffProfiles);
        if (ffDir.exists()) {
            const QStringList dirs = ffDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
            for (const QString &d : dirs) {
                cachePaths.append(ffProfiles + "/" + d + "/cache2");
            }
        }

        for (const QString &cp : cachePaths) {
            totalFreed += cleanDir(cp);
        }
    }

    if (categoryIds.contains("recycle_bin")) {
#ifdef Q_OS_WIN
        SHQUERYRBINFO rbi;
        ZeroMemory(&rbi, sizeof(rbi));
        rbi.cbSize = sizeof(rbi);
        if (SUCCEEDED(SHQueryRecycleBinW(NULL, &rbi))) {
            totalFreed += rbi.i64Size;
        }
        SHEmptyRecycleBinW(NULL, NULL, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
#endif
    }

    if (categoryIds.contains("thumb_cache")) {
        QString localAppData = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        QString explorerDir = QDir::cleanPath(localAppData + "/../../Microsoft/Windows/Explorer");
        QDir expDir(explorerDir);
        if (expDir.exists()) {
            const auto entries = expDir.entryInfoList({"thumbcache_*.db", "iconcache_*.db"}, QDir::Files);
            for (const auto &e : entries) {
                qint64 s = e.size();
                if (QFile::remove(e.absoluteFilePath())) {
                    totalFreed += s;
                }
            }
        }
    }

    if (categoryIds.contains("dns_cache")) {
#ifdef Q_OS_WIN
        QProcess::execute("ipconfig", {"/flushdns"});
#endif
        totalFreed += 1024 * 128;
    }

    Logger::info(QStringLiteral("SystemOptimizer: Freed %1").arg(formatBytes(totalFreed)));
    return totalFreed;
}

bool SystemOptimizer::overwriteFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadWrite)) {
        return false;
    }

    qint64 size = file.size();
    if (size <= 0) {
        file.close();
        file.remove();
        return true;
    }

    const qint64 chunkSize = 64 * 1024;
    QByteArray zeros(chunkSize, 0x00);
    QByteArray ones(chunkSize, '\xFF');
    QByteArray random(chunkSize, 0);

    // Pass 1: Zeros
    file.seek(0);
    qint64 remaining = size;
    while (remaining > 0) {
        qint64 toWrite = qMin(remaining, chunkSize);
        file.write(zeros.constData(), toWrite);
        remaining -= toWrite;
    }
    file.flush();

    // Pass 2: Ones
    file.seek(0);
    remaining = size;
    while (remaining > 0) {
        qint64 toWrite = qMin(remaining, chunkSize);
        file.write(ones.constData(), toWrite);
        remaining -= toWrite;
    }
    file.flush();

    // Pass 3: Random
    file.seek(0);
    remaining = size;
    while (remaining > 0) {
        qint64 toWrite = qMin(remaining, chunkSize);
        auto *ptr = reinterpret_cast<quint32*>(random.data());
        int uintCount = toWrite / sizeof(quint32);
        for (int i = 0; i < uintCount; ++i) {
            ptr[i] = QRandomGenerator::global()->generate();
        }
        file.write(random.constData(), toWrite);
        remaining -= toWrite;
    }
    file.flush();

    file.resize(0);
    file.close();

    // Rename to scramble MFT / directory record
    QFileInfo fi(path);
    QString randomName = QString("%1/_shred_%2_%3")
        .arg(fi.absolutePath())
        .arg(QRandomGenerator::global()->generate())
        .arg(fi.fileName().left(4));

    QFile::rename(path, randomName);
    return QFile::remove(randomName);
}

bool SystemOptimizer::shredFile(const QString &path, std::function<void(int)> progressCb)
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::FileShredder)) {
        Logger::warn("SystemOptimizer: Pominięto niszczenie pliku — brak uprawnień licencyjnych.");
        return false;
    }
    if (!QFile::exists(path)) return false;
    if (progressCb) progressCb(50);
    bool ok = overwriteFile(path);
    if (progressCb) progressCb(100);
    return ok;
}

bool SystemOptimizer::shredDirectory(const QString &dirPath, std::function<void(int)> progressCb)
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::FileShredder)) {
        Logger::warn("SystemOptimizer: Pominięto niszczenie katalogu — brak uprawnień licencyjnych.");
        return false;
    }
    QDir dir(dirPath);
    if (!dir.exists()) return false;

    QStringList files;
    QDirIterator it(dirPath, QDir::Files | QDir::NoSymLinks, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        files.append(it.filePath());
    }

    int total = files.size();
    int done = 0;
    for (const QString &fp : files) {
        overwriteFile(fp);
        ++done;
        if (progressCb && total > 0) {
            progressCb((done * 100) / total);
        }
    }

    return dir.removeRecursively();
}

} // namespace verax
