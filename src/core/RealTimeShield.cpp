#include "RealTimeShield.h"
#include "Settings.h"
#include "Logger.h"
#include "Quarantine.h"
#include "LicenseManager.h"
#include "../utils/HashUtils.h"

#include <QFileSystemWatcher>
#include <QTimer>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>
#include <QtConcurrent>
#include <QDateTime>

namespace verax {

RealTimeShield& RealTimeShield::instance()
{
    static RealTimeShield s;
    return s;
}

RealTimeShield::RealTimeShield(QObject *parent)
    : QObject(parent)
{
    m_watcher = new QFileSystemWatcher(this);
    connect(m_watcher, &QFileSystemWatcher::directoryChanged,
            this, &RealTimeShield::onDirectoryChanged);
    connect(m_watcher, &QFileSystemWatcher::fileChanged,
            this, &RealTimeShield::onFileChanged);

    m_debounceTimer = new QTimer(this);
    m_debounceTimer->setSingleShot(true);
    m_debounceTimer->setInterval(750);
    connect(m_debounceTimer, &QTimer::timeout,
            this, &RealTimeShield::processPendingQueue);

    setupDefaultWatchPaths();
}

RealTimeShield::~RealTimeShield()
{
    stop();
}

void RealTimeShield::setupDefaultWatchPaths()
{
    QStringList defaultPaths;

    const QString downloads = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (!downloads.isEmpty()) defaultPaths << downloads;

    const QString desktop = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
    if (!desktop.isEmpty()) defaultPaths << desktop;

#ifdef Q_OS_WIN
    const QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    const QString startup = QDir::homePath() + QStringLiteral("/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup");
    if (QDir(startup).exists()) defaultPaths << startup;
#endif

    for (const QString &p : defaultPaths) {
        if (!p.isEmpty() && QDir(p).exists()) {
            addMonitoredPath(p);
        }
    }
}

void RealTimeShield::start()
{
    if (m_running) return;
    if (!LicenseManager::instance().hasCapability(LicenseCapability::RealTimeProtection)) {
        Logger::warn("RealTimeShield: Pominięto uruchomienie — brak uprawnień licencyjnych.");
        return;
    }
    m_running = true;
    Logger::info(QStringLiteral("RealTimeShield: Activated. Monitoring %1 directories")
                 .arg(m_watcher->directories().size()));
    emit statusChanged(true);
}

void RealTimeShield::stop()
{
    if (!m_running) return;
    m_running = false;
    if (m_debounceTimer && m_debounceTimer->isActive()) {
        m_debounceTimer->stop();
    }
    {
        QMutexLocker lock(&m_mutex);
        m_pendingFiles.clear();
    }
    Logger::info("RealTimeShield: Deactivated");
    emit statusChanged(false);
}

void RealTimeShield::setEnabled(bool enable)
{
    Settings::instance().setRealTimeProtection(enable);
    if (enable) {
        start();
    } else {
        stop();
    }
}

bool RealTimeShield::isEnabled() const
{
    return Settings::instance().realTimeProtection();
}

QStringList RealTimeShield::monitoredPaths() const
{
    return m_watcher ? m_watcher->directories() : QStringList();
}

void RealTimeShield::addMonitoredPath(const QString &path)
{
    if (!m_watcher || path.isEmpty()) return;
    QFileInfo fi(path);
    if (fi.exists() && fi.isDir() && !m_watcher->directories().contains(path)) {
        m_watcher->addPath(path);
        Logger::info(QStringLiteral("RealTimeShield: Watching path %1").arg(path));
    }
}

void RealTimeShield::removeMonitoredPath(const QString &path)
{
    if (m_watcher && m_watcher->directories().contains(path)) {
        m_watcher->removePath(path);
        Logger::info(QStringLiteral("RealTimeShield: Stopped watching %1").arg(path));
    }
}

void RealTimeShield::onDirectoryChanged(const QString &path)
{
    if (!m_running) return;

    QDir dir(path);
    if (!dir.exists()) return;

    const QFileInfoList entries = dir.entryInfoList(
        QDir::Files | QDir::NoDotAndDotDot | QDir::Readable,
        QDir::Time
    );

    const qint64 nowSecs = QDateTime::currentSecsSinceEpoch();
    QMutexLocker lock(&m_mutex);

    for (const QFileInfo &fi : entries) {
        // Only consider files modified within the last 15 seconds
        if (qAbs(nowSecs - fi.lastModified().toSecsSinceEpoch()) <= 15) {
            m_pendingFiles.insert(fi.absoluteFilePath());
        }
    }

    m_debounceTimer->start();
}

void RealTimeShield::onFileChanged(const QString &path)
{
    if (!m_running) return;
    QFileInfo fi(path);
    if (fi.exists() && fi.isFile()) {
        QMutexLocker lock(&m_mutex);
        m_pendingFiles.insert(path);
        m_debounceTimer->start();
    }
}

bool RealTimeShield::isSafeToScan(const QString &filePath) const
{
    if (Settings::instance().isExcluded(filePath)) return false;

    QFileInfo fi(filePath);
    if (!fi.exists() || !fi.isFile()) return false;

    // Ignore incomplete downloads and temporary files
    const QString name = fi.fileName().toLower();
    const QString ext  = fi.suffix().toLower();

    if (ext == "crdownload" || ext == "part" || ext == "tmp" ||
        ext == "download"   || ext == "opdownload" || name.startsWith("~$")) {
        return false;
    }

    if (fi.size() <= 0 || fi.size() > (100LL * 1024 * 1024)) {
        return false;
    }

    // Check if file is readable (not locked exclusively by writing process)
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly)) {
        return false;
    }
    f.close();

    return true;
}

void RealTimeShield::processPendingQueue()
{
    if (!m_running) return;

    QSet<QString> toProcess;
    {
        QMutexLocker lock(&m_mutex);
        toProcess = m_pendingFiles;
        m_pendingFiles.clear();
    }

    for (const QString &filePath : toProcess) {
        if (!isSafeToScan(filePath)) {
            // If file exists but is temporarily locked, retry in a moment
            QFileInfo fi(filePath);
            if (fi.exists() && fi.size() > 0) {
                const QString ext = fi.suffix().toLower();
                if (ext != "crdownload" && ext != "part" && ext != "tmp") {
                    QMutexLocker lock(&m_mutex);
                    m_pendingFiles.insert(filePath);
                    m_debounceTimer->start(1200);
                }
            }
            continue;
        }

        QFileInfo fi(filePath);
        const qint64 modTime = fi.lastModified().toSecsSinceEpoch();

        {
            QMutexLocker lock(&m_mutex);
            if (m_recentScanned.contains(filePath) && m_recentScanned.value(filePath) == modTime) {
                continue; // Already scanned this version
            }
            m_recentScanned[filePath] = modTime;

            // Trim cache if too large
            if (m_recentScanned.size() > 1000) {
                m_recentScanned.clear();
            }
        }

        scanFileAsync(filePath);
    }
}

void RealTimeShield::scanFileAsync(const QString &filePath)
{
    QtConcurrent::run([this, filePath]() {
        QFileInfo fi(filePath);
        const QString ext = fi.suffix().toLower();

        // Anti-Ransomware Canary Guard: detect known ransomware encrypted extensions
        static const QSet<QString> ransomwareExts = {
            "locked", "crypto", "lockbit", "crypted", "enc", "wnry",
            "blackcat", "phobos", "medusa", "makop", "ransom", "crypt"
        };
        if (ransomwareExts.contains(ext)) {
            ThreatInfo rInfo;
            rInfo.path = filePath;
            rInfo.detectionName = QStringLiteral("Ransom:Win32/MassEncryptor.Extension.%1").arg(ext.toUpper());
            rInfo.family = QStringLiteral("Ransomware");
            rInfo.severity = 10;
            rInfo.size = fi.size();
            rInfo.reason = QStringLiteral("Wykryto plik ze złośliwym rozszerzeniem ransomware (.%1)").arg(ext);
            rInfo.sha256 = HashUtils::sha256Hex(filePath);

            Logger::warn(QStringLiteral("RealTimeShield: [ANTI-RANSOMWARE GUARD] Ransomware extension detected on %1")
                         .arg(filePath));

            if (Settings::instance().detectionAction() == "quarantine") {
                Quarantine::instance().moveToVault(filePath, rInfo.sha256, rInfo.detectionName);
            }
            emit threatDetected(rInfo);
            return;
        }

        ScanRequest req;
        req.useSigDb  = Settings::instance().useSignatureDb();
        req.usePe     = Settings::instance().usePeInspection();
        req.useHeur   = Settings::instance().useHeuristics();
        req.useCloud  = Settings::instance().useCloudLookup();
        req.threshold = Settings::instance().heuristicThreshold();
        req.action    = Settings::instance().detectionAction();

        ThreatInfo info;
        Scanner localScanner;
        int score = localScanner.inspectFile(filePath, req, info);

        if (score >= req.threshold && !info.detectionName.isEmpty()) {
            Logger::warn(QStringLiteral("RealTimeShield: [THREAT] %1 detected in %2 (score %3)")
                         .arg(info.detectionName, filePath).arg(score));

            if (req.action == "quarantine") {
                QString vPath = Quarantine::instance().moveToVault(
                    filePath, info.sha256, info.detectionName);
                if (!vPath.isEmpty()) {
                    Logger::info(QStringLiteral("RealTimeShield: Moved threat to vault: %1").arg(vPath));
                }
            }

            emit threatDetected(info);
        } else {
            emit fileScanned(filePath);
        }
    });
}

} // namespace verax
