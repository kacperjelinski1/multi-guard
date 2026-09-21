#include "RansomwareShield.h"
#include "Logger.h"
#include "LicenseManager.h"
#include "../widgets/NotificationAlert.h"
#include "../utils/HashUtils.h"

#include <QStandardPaths>
#include <QFileSystemWatcher>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <cmath>

namespace verax {

RansomwareShield& RansomwareShield::instance()
{
    static RansomwareShield s;
    return s;
}

RansomwareShield::RansomwareShield(QObject *parent)
    : QObject(parent)
{
    // Auto-discover sensitive user directories
    const auto locations = {
        QStandardPaths::DesktopLocation,
        QStandardPaths::DocumentsLocation,
        QStandardPaths::PicturesLocation,
        QStandardPaths::DownloadLocation
    };

    for (auto loc : locations) {
        const QString path = QStandardPaths::writableLocation(loc);
        if (!path.isEmpty() && QDir(path).exists() && !m_protectedFolders.contains(path)) {
            m_protectedFolders.append(path);
        }
    }

    setupWatchers();
    seedCanaryFiles();
}

void RansomwareShield::setEnabled(bool enabled)
{
    if (enabled && !LicenseManager::instance().hasCapability(LicenseCapability::RansomwareProtection)) {
        Logger::warn("RansomwareShield: Nie można włączyć — brak uprawnień licencyjnych.");
        m_enabled = false;
        return;
    }
    if (m_enabled == enabled) return;
    m_enabled = enabled;
    if (m_enabled) {
        setupWatchers();
        seedCanaryFiles();
        Logger::info(QStringLiteral("RansomwareShield: Enabled across %1 folders").arg(m_protectedFolders.size()));
    } else {
        if (m_watcher) {
            m_watcher->removePaths(m_watcher->files());
            m_watcher->removePaths(m_watcher->directories());
        }
        Logger::info(QStringLiteral("RansomwareShield: Disabled"));
    }
}

void RansomwareShield::addProtectedFolder(const QString &path)
{
    if (path.isEmpty() || !QDir(path).exists() || m_protectedFolders.contains(path)) return;
    m_protectedFolders.append(path);
    if (m_enabled && m_watcher) {
        m_watcher->addPath(path);
    }
}

void RansomwareShield::setupWatchers()
{
    if (!m_watcher) {
        m_watcher = std::make_unique<QFileSystemWatcher>(this);
        connect(m_watcher.get(), &QFileSystemWatcher::directoryChanged,
                this, &RansomwareShield::onDirectoryChanged);
        connect(m_watcher.get(), &QFileSystemWatcher::fileChanged,
                this, &RansomwareShield::onFileChanged);
    }

    for (const auto &folder : m_protectedFolders) {
        m_watcher->addPath(folder);
    }
}

void RansomwareShield::seedCanaryFiles()
{
    const QByteArray canarySeed = "MULTI_GUARD_CANARY_SENTINEL_DATA_VALIDATION_TOKEN_9918237";
    const QString canaryHash = HashUtils::sha256(canarySeed);

    for (const auto &folder : m_protectedFolders) {
        const QString canaryPath = folder + QDir::separator() + QStringLiteral(".multi_guard_canary.dat");
        if (!QFile::exists(canaryPath)) {
            QFile f(canaryPath);
            if (f.open(QIODevice::WriteOnly)) {
                f.write(canarySeed);
                f.close();
#ifdef Q_OS_WIN
                // Set hidden attribute on Windows
                SetFileAttributesW(reinterpret_cast<LPCWSTR>(canaryPath.utf16()), FILE_ATTRIBUTE_HIDDEN);
#endif
            }
        }
        m_canaryHashes[canaryPath] = canaryHash;
        if (m_watcher && QFile::exists(canaryPath)) {
            m_watcher->addPath(canaryPath);
        }
    }
}

bool RansomwareShield::hasRansomwareExtension(const QString &filePath)
{
    static const QStringList badExts = {
        QStringLiteral(".locked"), QStringLiteral(".crypto"), QStringLiteral(".crypted"),
        QStringLiteral(".enc"), QStringLiteral(".wnry"), QStringLiteral(".lockbit"),
        QStringLiteral(".blackcat"), QStringLiteral(".phobos"), QStringLiteral(".mallox"),
        QStringLiteral(".rhysida"), QStringLiteral(".crypt"), QStringLiteral(".wannacry")
    };

    const QString lower = filePath.toLower();
    for (const auto &ext : badExts) {
        if (lower.endsWith(ext)) return true;
    }
    return false;
}

double RansomwareShield::calculateEntropy(const QString &filePath)
{
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly)) return 0.0;
    
    // Read up to 64KB
    const QByteArray data = f.read(65536);
    f.close();

    if (data.size() < 512) return 0.0;

    int counts[256] = {0};
    for (int i = 0; i < data.size(); ++i) {
        counts[static_cast<quint8>(data[i])]++;
    }

    double entropy = 0.0;
    const double len = static_cast<double>(data.size());
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = static_cast<double>(counts[i]) / len;
            entropy -= p * (std::log(p) / std::log(2.0));
        }
    }
    return entropy;
}

void RansomwareShield::onFileChanged(const QString &path)
{
    if (!m_enabled) return;

    // 1. Check if canary file was modified or deleted
    if (m_canaryHashes.contains(path)) {
        if (!QFile::exists(path)) {
            QString msg = tr("Wykryto usunięcie pliku-pułapki (Canary File) w folderze: %1").arg(path);
            Logger::error(QStringLiteral("RansomwareShield ALERT: Canary file deleted: %1").arg(path));
            NotificationAlert::showThreat(tr("Ransomware Shield"), tr("Wykryto usunięcie pliku-pułapki!"), path);
            emit ransomwareActivityDetected(path, msg);
            return;
        }

        const QString currentHash = HashUtils::sha256File(path);
        if (currentHash != m_canaryHashes.value(path)) {
            QString msg = tr("Wykryto nieautoryzowaną modyfikację/szyfrowanie pliku-pułapki: %1").arg(path);
            Logger::error(QStringLiteral("RansomwareShield ALERT: Canary modified: %1").arg(path));
            NotificationAlert::showThreat(tr("Ransomware Shield"), tr("Wykryto próbę szyfrowania plików!"), path);
            emit ransomwareActivityDetected(path, msg);
            return;
        }
    }
}

void RansomwareShield::onDirectoryChanged(const QString &dirPath)
{
    if (!m_enabled) return;

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    auto &history = m_modHistory[dirPath];

    // Clean timestamps older than 2 seconds
    while (!history.isEmpty() && (now - history.first()) > 2000) {
        history.removeFirst();
    }
    history.append(now);

    // Burst rate detection: more than 6 modifications in 2000 ms
    if (history.size() >= 7) {
        QDir d(dirPath);
        const auto entries = d.entryInfoList(QDir::Files, QDir::Time);
        for (const auto &info : entries) {
            const QString absPath = info.absoluteFilePath();
            
            // Check known ransomware extension
            if (hasRansomwareExtension(absPath)) {
                QString desc = tr("Wykryto plik o podejrzanym rozszerzeniu ransomware: %1").arg(info.fileName());
                Logger::error(QStringLiteral("RansomwareShield: Extension detected %1").arg(absPath));
                NotificationAlert::showThreat(tr("Ransomware Shield"), tr("Zablokowano atak Ransomware!"), absPath);
                emit ransomwareActivityDetected(dirPath, desc);
                history.clear();
                return;
            }

            // Check high entropy on recently created/modified files
            if (info.size() > 4096) {
                double ent = calculateEntropy(absPath);
                if (ent >= 7.93) { // Highly encrypted
                    QString desc = tr("Wykryto gwałtowne szyfrowanie (Entropia: %1) pliku: %2").arg(QString::number(ent, 'f', 2), info.fileName());
                    Logger::error(QStringLiteral("RansomwareShield: High entropy encryption detected: %1 (%2)").arg(absPath, QString::number(ent)));
                    NotificationAlert::showThreat(tr("Ransomware Shield"), tr("Zablokowano próbę szyfrowania!"), absPath);
                    emit ransomwareActivityDetected(dirPath, desc);
                    history.clear();
                    return;
                }
            }
        }
    }
}

} // namespace verax
