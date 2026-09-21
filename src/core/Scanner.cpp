#include "Scanner.h"
#include "Logger.h"
#include "SignatureDb.h"
#include "Settings.h"
#include "../utils/HashUtils.h"

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDirIterator>
#include <QDateTime>
#include <QThread>
#include <QtConcurrent>
#include <QCoreApplication>
#include <QRegularExpression>
#include <QTextStream>
#include <QDataStream>
#include <QSet>
#include <cmath>
#include <cstring>

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QEventLoop>
#include <QTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDebug>
#include <QProcess>
#include "Quarantine.h"
#ifdef _WIN32
#  include <windows.h>
#  include <tlhelp32.h>
#  include <psapi.h>
#  include <wintrust.h>
#  include <softpub.h>
#endif

namespace verax {

QMutex                 Scanner::s_cloudMutex;
QHash<QString, ThreatInfo> Scanner::s_cloudCache;

bool Scanner::verifyAuthenticode(const QString &path)
{
#ifdef _WIN32
    std::wstring wPath = path.toStdWString();
    WINTRUST_FILE_INFO fileData{};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = wPath.c_str();

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData{};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; // Fast offline check
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_IGNORE;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;

    LONG status = WinVerifyTrust(NULL, &policyGuid, &winTrustData);
    return (status == ERROR_SUCCESS);
#else
    Q_UNUSED(path);
    return false;
#endif
}

Scanner::Scanner(QObject *parent) : QObject(parent)
{
    // Self-Registration directly inside the constructor to bypass timing issues
    qRegisterMetaType<verax::ThreatInfo>("verax::ThreatInfo");
    qRegisterMetaType<verax::ScanReport>("verax::ScanReport");
    qRegisterMetaType<verax::ScanRequest>("verax::ScanRequest");
}

Scanner::~Scanner() = default;

void Scanner::request(const ScanRequest &req)
{
    if (isRunning()) {
        // Safety: force-reset if the flag got stuck (e.g. previous build crash)
        Logger::warn("Scanner::request called while m_running=1, force-resetting");
        m_running.storeRelease(0);
    }
    m_stop.storeRelease(0);
    m_pause.storeRelease(0);
    m_running.storeRelease(1);
    QtConcurrent::run([this, req] { runOn(req); });
}

void Scanner::requestStop() { m_stop.storeRelease(1); }
void Scanner::requestPause(bool p) { m_pause.storeRelease(p ? 1 : 0); }

void Scanner::enumerate(const QString &target, QStringList &out, const QStringList &exts)
{
    QFileInfo info(target);
    if (info.isFile()) { out << target; return; }
    if (!info.isDir()) return;

    QDirIterator it(target, QDir::Files | QDir::NoDotAndDotDot | QDir::System | QDir::Hidden, QDirIterator::Subdirectories);
    int checkedCount = 0;
    while (it.hasNext()) {
        if (m_stop.loadAcquire()) return;
        const QString p = it.next();
        ++checkedCount;

        QFileInfo fi(p);
        if (fi.isSymLink() || !fi.isReadable()) continue;

        if (exts.isEmpty()) {
            out << p;
        } else {
            const QString s = fi.suffix().toLower();
            if (exts.contains(s)) out << p;
        }
        
        // Send UI feedback during enumeration to prevent "stuck" state
        if (checkedCount % 50 == 0) {
            emit progress(0, out.size(), 0);
            emit fileScanned(QStringLiteral("Wyszukiwanie: ") + fi.fileName());
        }
        
        if (out.size() > 500000) return;
    }
}
void Scanner::runOn(const ScanRequest &req)
{
#ifdef _WIN32
    // Low priority I/O and CPU: allows user to game or work with zero stutter during background scan
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
#endif
    emit started();
    // Force UI feedback instantly on initialization
    emit progress(0, 0, 1);

    Logger::info(QStringLiteral("Scan begin: targets=%1 sigDb=%2 pe=%3 heur=%4 cloud=%5 threshold=%6 action=%7")
                 .arg(req.targets.size()).arg(req.useSigDb).arg(req.usePe)
                 .arg(req.useHeur).arg(req.useCloud)
                 .arg(req.threshold).arg(req.action));
    m_cloudCallsThisScan = 0;
    m_cloudErrorWarned   = false;

    // Load byte signatures for precise scanning
    m_byteSignatures = SignatureDb::instance().loadByteSignatures();

    ScanReport report;
    report.startedAt = QDateTime::currentSecsSinceEpoch();

    try {
        QStringList all;
        QStringList exts;
        for (const QString &e : req.extensionFilter) exts << e.toLower();

        for (const QString &t : req.targets) {
            if (m_stop.loadAcquire()) break;
            enumerate(t, all, exts);
        }

        const qint64 total = all.size();
        qint64 done = 0;

        if (total == 0) {
            qDebug() << "Scanner Central Engine: Target path is empty or contains no matching files.";
            emit progress(100, 0, 0);
            report.finishedAt = QDateTime::currentSecsSinceEpoch();
            m_running.storeRelease(0);
            emit finished(report);
            return;
        }

        qint64 lastUiUpdateMs = 0;
        QElapsedTimer uiTimer;
        uiTimer.start();

        for (const QString &p : all) {
            if (m_stop.loadAcquire()) {
                qDebug() << "Scanner Central Engine: Stop command verified and executed.";
                break;
            }
            while (m_pause.loadAcquire()) QThread::msleep(150);

            ThreatInfo info;
            const int score = inspectFile(p, req, info);

            if (score >= req.threshold || !info.detectionName.isEmpty()) {
                info.score = score;
                ++report.threatsFound;

                Logger::warn(QStringLiteral("Threat: %1 [%2] score=%3 reason=%4")
                             .arg(p, info.detectionName).arg(score).arg(info.reason));

                if (req.action == "repair") {
                    if (info.repairable) {
                        if (advancedCleanThreat(p, info)) {
                            info.reason += " | [CLEAN THREAT SUCCESS]";
                            Logger::info(QStringLiteral("Clean Threat success: %1").arg(p));
                        } else {
                            info.reason += " | [CLEAN THREAT FAILED]";
                        }
                    } else {
                        // Fallback to legacy section wipe
                        if (disinfectPE(p)) {
                            info.reason += " | [REPAIRED SUCCESSFULLY]";
                            Logger::info(QStringLiteral("File disinfected: %1").arg(p));
                        } else {
                            info.reason += " | [REPAIR FAILED]";
                        }
                    }
                }
                emit threatFound(info);
            }

            ++done;
            ++report.filesScanned;

            const qint64 now = uiTimer.elapsed();
            if (now - lastUiUpdateMs >= 35 || done == total) {
                lastUiUpdateMs = now;
                emit fileScanned(p);
                emit progress(int((done * 100) / total), done, total);
            }
        }

        if (done == total) emit progress(100, done, total);

    } catch (...) {
        Logger::error("Scanner encountered an exception inside global execution loop.");
    }

    report.finishedAt = QDateTime::currentSecsSinceEpoch();
    Logger::info(QStringLiteral("Scan end: files=%1 threats=%2 duration=%3s")
                 .arg(report.filesScanned).arg(report.threatsFound)
                 .arg(report.finishedAt - report.startedAt));
    m_running.storeRelease(0);
    emit finished(report);
}

int Scanner::inspectFile(const QString &path, const ScanRequest &req, ThreatInfo &info)
{
    if (Settings::instance().isExcluded(path)) return 0;
    QFileInfo fi(path);
    if (!fi.exists() || !fi.isFile()) return 0;
    info.path = path;
    info.size = fi.size();

    if (info.size <= 0 || info.size > req.maxFileBytes) return 0;

    int score = 0;
    const QString ext = fi.suffix().toLower();

    // 0) Standard EICAR Antivirus Test File detection (industry standard signature)
    if (fi.size() <= 65536) {
        QFile fEicar(path);
        if (fEicar.open(QIODevice::ReadOnly)) {
            QByteArray headBytes = fEicar.read(4096);
            if (headBytes.contains("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")) {
                info.detectionName = QStringLiteral("EICAR-Standard-AV-Test-File");
                info.family        = QStringLiteral("TestVirus");
                info.severity      = 5;
                info.repairable    = false;
                info.reason        = QStringLiteral("Matched EICAR standard antivirus test string");
                return 100;
            }
        }
    }

    // 1) Hash DB lookup — cheapest and most definitive engine.
    QString hash;
    if (req.useSigDb) {
        hash = HashUtils::sha256Hex(path).toLower().trimmed();
        info.sha256 = hash;
        if (!hash.isEmpty()) {
            const SigHit hit = SignatureDb::instance().lookup(hash);
            if (!hit.name.isEmpty()) {
                info.detectionName = hit.name;
                info.family        = hit.family;
                info.severity      = hit.severity;
                info.repairable    = hit.repairable;
                info.repairMethod  = hit.repairMethod;
                info.entryPointPatch = hit.entryPointPatch;
                info.reason        = QStringLiteral("Matched known malicious SHA256 in local database");
                return 100;
            }
        }
    }

    // 2) Dispatch the structural / content engine by file type.
    static const QSet<QString> peExts        = { "exe","dll","sys","scr","ocx","cpl","drv","efi" };
    static const QSet<QString> scriptExts    = { "bat","cmd","ps1","psm1","vbs","vbe","js","jse","wsf","hta","sh" };
    static const QSet<QString> docExts       = { "docm","xlsm","pptm","dotm","xltm","potm","docx","xlsx","pptx","rtf","pdf" };
    static const QSet<QString> archiveExts   = { "zip","jar","apk","xpi","crx","iso","msix","appx","docx","xlsx","pptx" };

    if (req.usePe && peExts.contains(ext)) {
        score += peHeuristics(path, info);

        // Authenticode signature verification (SmartScreen whitelisting):
        // If the binary has a cryptographically valid, trusted digital signature,
        // reduce borderline heuristic score to prevent false positives on legitimate software.
        if (verifyAuthenticode(path)) {
            if (score < 85) {
                score = qMax(0, score - 60);
                info.reason += QStringLiteral(" | [Podpis cyfrowy Authenticode: Prawidłowy]");
            }
        }
    }
    if (req.useHeur && scriptExts.contains(ext)) {
        score += scriptHeuristics(path, info);
    }
    if (req.useHeur && docExts.contains(ext)) {
        score += documentHeuristics(path, info);
    }
    if (req.useHeur && archiveExts.contains(ext)) {
        score += archiveHeuristics(path, info);
    }

    // 3) Path / attribute heuristics ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â applied to ANY file type, low weight.
    if (req.useHeur) {
        const QString lower = path.toLower();
        int heurScore = 0;
        QStringList heurNotes;

        if ((lower.contains("\\temp\\") || lower.contains("/temp/") ||
             lower.contains("\\appdata\\local\\temp\\")) &&
            fi.lastModified().daysTo(QDateTime::currentDateTime()) < 30)
        {
            heurScore += 20;
            heurNotes << QStringLiteral("Executed from volatile local temporary folder");
        }
        // Persistence-location red flag (executables dropped under Startup)
        if (peExts.contains(ext) &&
            (lower.contains("\\start menu\\programs\\startup\\") ||
             lower.contains("\\start menu\\startup\\")))
        {
            heurScore += 25;
            heurNotes << QStringLiteral("Executable placed under user Startup folder");
        }
        // Double-extension trick: foo.pdf.exe / invoice.docx.scr
        const QString name = fi.fileName().toLower();
        static const QRegularExpression dblExtRx(
            QStringLiteral("\\.(pdf|docx?|xlsx?|jpg|png|txt|zip)\\.(exe|scr|cmd|bat|com|pif|vbs|js)$"));
        if (dblExtRx.match(name).hasMatch()) {
            heurScore += 50;
            heurNotes << QStringLiteral("Double extension trick (filename masquerade)");
        }
#ifdef _WIN32
        const DWORD attrs = GetFileAttributesW(reinterpret_cast<const wchar_t*>(path.utf16()));
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_HIDDEN) &&
            peExts.contains(ext))
        {
            heurScore += 20;
            heurNotes << QStringLiteral("Hidden executable file");
        }
#endif
        if (heurScore > 0) {
            score += heurScore;
            if (!info.reason.isEmpty()) info.reason += "; ";
            info.reason += heurNotes.join("; ");
        }
    }

    // 4) Cloud ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â last resort, capped to keep scan responsive. Only call for
    // files that are SUSPICIOUS but inconclusive locally (score > 0, no DB hit).
    if (req.useCloud && score > 0 && score < req.threshold &&
        info.detectionName.isEmpty() && !hash.isEmpty() &&
        m_cloudCallsThisScan < 50)
    {
        ++m_cloudCallsThisScan;
        if (cloudLookup(hash, info)) {
            return 100;
        }
    }

    if (score >= req.threshold && info.detectionName.isEmpty()) {
        info.detectionName = QStringLiteral("Heuristic.Suspect");
    }
    return score;
}

bool Scanner::cloudLookup(const QString &hash, ThreatInfo &info)
{
    // Check in-memory cloud cache first
    {
        QMutexLocker locker(&s_cloudMutex);
        if (s_cloudCache.contains(hash)) {
            ThreatInfo cached = s_cloudCache.value(hash);
            if (!cached.detectionName.isEmpty()) {
                info = cached;
                return true;
            }
            return false; // Cached as clean
        }
    }

    // Guard: abort if scan was cancelled while we were queued
    if (m_stop.loadAcquire()) return false;

    bool detected = false;
    QNetworkAccessManager *nam = nullptr;
    QNetworkReply *reply = nullptr;

    try {
        nam = new QNetworkAccessManager();
        QNetworkRequest req(QUrl("https://mb-api.abuse.ch/api/v1/"));
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
        req.setRawHeader("Auth-Key", "c918204488a01eb5a765bcc629ab1ffc5810fa37310cca8b");

        QByteArray data = "query=get_info&hash=" + hash.toUtf8();
        reply = nam->post(req, data);
        if (!reply) {
            delete nam;
            return false;
        }

        QEventLoop loop;
        // Use QueuedConnection to prevent cross-thread signal issues
        connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit, Qt::QueuedConnection);
        QTimer timer;
        timer.setSingleShot(true);
        connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        timer.start(2500);
        loop.exec();
        if (timer.isActive()) timer.stop();

        // Check again after blocking wait — scan might have been cancelled
        if (m_stop.loadAcquire()) {
            if (reply) { reply->abort(); reply->deleteLater(); }
            delete nam;
            return false;
        }

        if (reply && reply->isFinished() && reply->error() == QNetworkReply::NoError) {
            const QByteArray body = reply->readAll();
            const QJsonDocument doc = QJsonDocument::fromJson(body);
            if (!doc.isNull() && doc.isObject()) {
                const QJsonObject root = doc.object();
                const QString status = root.value("query_status").toString();
                if (status == QLatin1String("ok")) {
                    const QJsonArray dataArr = root.value("data").toArray();
                    if (!dataArr.isEmpty()) {
                        QString sig = dataArr[0].toObject().value("signature").toString();
                        if (sig.isEmpty() || sig == QLatin1String("null"))
                            sig = QStringLiteral("Malware");
                        info.detectionName = QStringLiteral("Cloud.") + sig;
                        info.family   = sig;
                        info.severity = 9;
                        info.reason   = QStringLiteral("Identified via MalwareBazaar cloud intel");
                        Logger::info(QStringLiteral("Cloud HIT: %1 -> %2").arg(hash, sig));
                        detected = true;
                    }
                }
                // Cache result (either malware info or empty ThreatInfo for clean)
                {
                    QMutexLocker locker(&s_cloudMutex);
                    s_cloudCache.insert(hash, detected ? info : ThreatInfo());
                }
            }
        } else if (reply && reply->error() != QNetworkReply::NoError) {
            if (!m_cloudErrorWarned) {
                m_cloudErrorWarned = true;
                Logger::warn(QStringLiteral("Cloud lookup network error: %1 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â skipping further cloud calls this run")
                             .arg(reply->errorString()));
                m_cloudCallsThisScan = 999999;
            }
        }
    } catch (...) {
        // Catch ANY exception (including pure virtual method calls from Qt internals)
        // to prevent the entire application from crashing during cloud lookup.
        Logger::error(QStringLiteral("Cloud lookup exception caught ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â aborting cloud for this scan"));
        m_cloudCallsThisScan = 999999;
        detected = false;
    }

    if (reply) reply->deleteLater();
    if (nam) nam->deleteLater();
    return detected;
}

static double shannonEntropy(const uchar *p, qint64 n) {
    if (n <= 0 || !p) return 0.0;
    quint64 hist[256] = {0};
    for (qint64 i = 0; i < n; ++i) ++hist[p[i]];
    double h = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!hist[i]) continue;
        const double pr = double(hist[i]) / double(n);
        h -= pr * (std::log(pr) / std::log(2.0));
    }
    return h;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Advanced PE virus family detection ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Floxif
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
#ifdef _WIN32

// Helper: is this section name a known commercial packer/protector?
static bool isKnownPackerSection(const QString &nm)
{
    static const char *packers[] = {
        ".upx0", ".upx1", ".upx2", ".mpress1", ".mpress2",
        ".themida", ".vmp0", ".vmp1", ".vmp2",
        ".aspack", ".adata", ".pec", ".petite", ".pec2",
        ".nsp0", ".nsp1", ".enigma1", ".enigma2",
        ".perplex", nullptr
    };
    for (int k = 0; packers[k]; ++k)
        if (nm == QString::fromLatin1(packers[k])) return true;
    return false;
}

// Helper: is this a standard compiler/linker section name?
static bool isStandardSection(const QString &nm)
{
    static const char *stdSec[] = {
        // Microsoft MSVC/linker standard
        ".text", ".code", ".rdata", ".data", ".bss", ".idata", ".edata",
        ".rsrc", ".reloc", ".tls", ".crt", ".gfids", ".00cfg", ".pdata",
        ".xdata", ".debug", ".didat", ".sxdata", ".voltbl", ".mrdata",
        // Debug/profile sections
        ".debug$s", ".debug$t", ".debug$p", ".debug$f",
        // MSVC extended
        ".textbss", ".shared", ".orpc", ".ndata",
        // GCC/MinGW
        ".ctors", ".dtors", ".jcr", ".eh_fram", ".gcc_exc",
        ".got", ".got.plt", ".plt",
        // Delphi/Borland
        ".tls$", "code", "data", "bss",
        // Go language
        ".symtab", ".typelink", ".itablink", ".gosymtab", ".gopclntab",
        // Rust
        ".rdata$r", ".rdata$t",
        nullptr
    };
    for (int k = 0; stdSec[k]; ++k)
        if (nm == QString::fromLatin1(stdSec[k])) return true;
    // Also match sections starting with standard prefixes
    if (nm.startsWith(".rdata$") || nm.startsWith(".text$") ||
        nm.startsWith(".data$") || nm.startsWith(".CRT$") ||
        nm.startsWith(".debug$"))
        return true;
    return false;
}

int Scanner::detectFloxifFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                                 const void *secHdrV, int numSections, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 1. Named infector section detection ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    for (int i = 0; i < numSections; ++i) {
        int nameLen = 0;
        while (nameLen < 8 && sec[i].Name[nameLen] != '\0') nameLen++;
        const QString nm = QString::fromLatin1(reinterpret_cast<const char*>(sec[i].Name), nameLen).toLower();
        if (nm == ".flx" || nm == ".floxif") {
            score += 80;
            info.detectionName = QStringLiteral("Virus:Win32/Floxif.gen");
            info.family = "Floxif";
            info.severity = 10;
            info.repairable = true;
            info.repairMethod = "PE.SectionWipe+EP.Restore";
            info.reason += QStringLiteral("Floxif infector section '%1' detected; ").arg(nm);
            return score;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 2. EP redirect analysis ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // A normally compiled program NEVER starts with E9 JMP to a DIFFERENT section.
    // The ONLY legitimate cross-section E9 at EP is from known packers.
    for (int i = 0; i < numSections; ++i) {
        if (epRva >= sec[i].VirtualAddress &&
            epRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
        {
            qint64 epFileOff = qint64(sec[i].PointerToRawData) + qint64(epRva - sec[i].VirtualAddress);
            if (epFileOff >= 0 && epFileOff + 6 < mapSize) {
                const uchar *ep = base + epFileOff;

                if (ep[0] == 0xE9) {
                    qint32 rel = *reinterpret_cast<const qint32*>(ep + 1);
                    quint32 targetRva = epRva + 5 + quint32(rel);

                    for (int j = 0; j < numSections; ++j) {
                        if (targetRva >= sec[j].VirtualAddress &&
                            targetRva < sec[j].VirtualAddress + sec[j].Misc.VirtualSize)
                        {
                            if (j == i) {
                                // JMP within same section ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â check for in-section code cave
                                DWORD ch = sec[j].Characteristics;
                                bool rwx = (ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE);
                                
                                // Check if the JMP target is BEYOND VirtualSize (section padding = code cave)
                                quint32 targetOffInSection = targetRva - sec[j].VirtualAddress;
                                bool inCave = (sec[j].Misc.VirtualSize > 0 &&
                                               targetOffInSection >= sec[j].Misc.VirtualSize);

                                // Check if target code looks like virus stub (PUSHAD, CALL $+5, etc.)
                                qint64 tgtFileOff = qint64(sec[j].PointerToRawData) + qint64(targetOffInSection);
                                bool virusStub = false;
                                if (tgtFileOff >= 0 && tgtFileOff + 8 < mapSize) {
                                    const uchar *t = base + tgtFileOff;
                                    virusStub = (t[0] == 0x60) ||  // PUSHAD
                                                (t[0] == 0xE8 && t[1] == 0x00 && t[2] == 0x00 &&
                                                 t[3] == 0x00 && t[4] == 0x00) ||  // CALL $+5
                                                (t[0] == 0x9C) ||  // PUSHFD
                                                (t[0] == 0x55 && t[1] == 0x89 && t[2] == 0xE5 &&
                                                 t[3] == 0x60);  // push ebp; mov ebp,esp; pushad
                                }

                                if (inCave) {
                                    score += 65;
                                    info.reason += QStringLiteral("EP JMP to code cave in section padding (beyond VirtualSize); ");
                                    info.detectionName = QStringLiteral("Virus:Win32/Floxif.H!Cave");
                                    info.family = "Floxif";
                                    info.severity = 10;
                                    info.repairable = true;
                                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                                    info.entryPointPatch = "";
                                } else if (virusStub) {
                                    score += 60;
                                    info.reason += QStringLiteral("EP JMP to virus stub (PUSHAD/CALL $+5) within same section; ");
                                    info.detectionName = QStringLiteral("Virus:Win32/Floxif.H!InSec");
                                    info.family = "Floxif";
                                    info.severity = 10;
                                    info.repairable = true;
                                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                                    info.entryPointPatch = "";
                                } else if (rwx) {
                                    score += 50;
                                    info.reason += QStringLiteral("EP JMP within RWX section (possible in-section infection); ");
                                }
                                break;
                            }

                            int tNL = 0;
                            while (tNL < 8 && sec[j].Name[tNL] != '\0') tNL++;
                            QString tgtName = QString::fromLatin1(
                                reinterpret_cast<const char*>(sec[j].Name), tNL).toLower();

                            if (isKnownPackerSection(tgtName)) break;

                            DWORD tgtF = sec[j].Characteristics;
                            bool tgtExec  = (tgtF & IMAGE_SCN_MEM_EXECUTE) != 0;
                            bool tgtWrite = (tgtF & IMAGE_SCN_MEM_WRITE)   != 0;

                            if (tgtExec && tgtWrite) {
                                score += 70;
                            } else if (j == numSections - 1) {
                                score += 65;
                            } else if (tgtExec && !isStandardSection(tgtName)) {
                                score += 60;
                            } else if (!isStandardSection(tgtName)) {
                                score += 50;
                            } else {
                                // JMP to a standard section like .text ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â might be
                                // a legitimate trampoline. Still flag but lower score.
                                score += 35;
                            }

                            if (score >= 35) {
                                if (info.detectionName.isEmpty()) {
                                    info.detectionName = QStringLiteral("Virus:Win32/Floxif.gen!EP");
                                    info.family = "Floxif";
                                    info.severity = 10;
                                    info.repairable = true;
                                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                                    info.entryPointPatch = "";
                                }
                                info.reason += QStringLiteral("EP JMP redirect to section '%1' (file-infector pattern); ").arg(tgtName);
                            }
                            break;
                        }
                    }
                }
                else if (ep[0] == 0xFF && ep[1] == 0x25) {
                    DWORD epF = sec[i].Characteristics;
                    bool epWrite = (epF & IMAGE_SCN_MEM_WRITE) != 0;
                    int eNL = 0;
                    while (eNL < 8 && sec[i].Name[eNL] != '\0') eNL++;
                    QString epSN = QString::fromLatin1(
                        reinterpret_cast<const char*>(sec[i].Name), eNL).toLower();
                    if (epWrite || !isStandardSection(epSN) || i == numSections - 1) {
                        score += 50;
                        info.detectionName = QStringLiteral("Virus:Win32/Floxif.gen!EP");
                        info.family = "Floxif";
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        info.entryPointPatch = "";
                        info.reason += QStringLiteral("EP indirect JMP (FF25) in '%1' (infector redirect); ").arg(epSN);
                    }
                }
                // E8 (CALL rel32) at EP ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â check for cross-section CALL or CALL $+5
                else if (ep[0] == 0xE8) {
                    qint32 callRel = *reinterpret_cast<const qint32*>(ep + 1);
                    quint32 callTargetRva = epRva + 5 + quint32(callRel);

                    // CALL $+5 (delta-offset) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â ALWAYS virus technique, NEVER from compiler
                    if (callRel == 0) {
                        score += 70;
                        info.detectionName = QStringLiteral("Virus:Win32/Floxif.H!Delta");
                        info.family = "Floxif";
                        info.severity = 10;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        info.entryPointPatch = "";
                        info.reason += QStringLiteral("EP CALL $+5 (E8 00 00 00 00) delta-offset technique; ");
                    }
                    // CALL to a different section ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â suspicious
                    else {
                        for (int j = 0; j < numSections; ++j) {
                            if (callTargetRva >= sec[j].VirtualAddress &&
                                callTargetRva < sec[j].VirtualAddress + sec[j].Misc.VirtualSize)
                            {
                                if (j != i) {
                                    // Cross-section CALL ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â suspicious
                                    int tNL = 0;
                                    while (tNL < 8 && sec[j].Name[tNL] != '\0') tNL++;
                                    QString tgtName = QString::fromLatin1(
                                        reinterpret_cast<const char*>(sec[j].Name), tNL).toLower();

                                    if (!isKnownPackerSection(tgtName)) {
                                        DWORD tgtF = sec[j].Characteristics;
                                        bool tgtExec  = (tgtF & IMAGE_SCN_MEM_EXECUTE) != 0;
                                        bool tgtWrite = (tgtF & IMAGE_SCN_MEM_WRITE)   != 0;

                                        if (tgtExec && tgtWrite) {
                                            score += 60;
                                        } else if (j == numSections - 1) {
                                            score += 55;
                                        } else if (!isStandardSection(tgtName)) {
                                            score += 50;
                                        } else {
                                            score += 35;
                                        }

                                        if (score >= 35 && info.detectionName.isEmpty()) {
                                            info.detectionName = QStringLiteral("Virus:Win32/Floxif.H!CALL");
                                            info.family = "Floxif";
                                            info.severity = 10;
                                            info.repairable = true;
                                            info.repairMethod = "PE.SectionWipe+EP.Restore";
                                            info.entryPointPatch = "";
                                        }
                                        info.reason += QStringLiteral("EP CALL redirect to section '%1' (cross-section call); ").arg(tgtName);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            break;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 3. String marker scan ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    {
        static const char *markers[] = { "Floxif", "floxif", ".flx", "FLOXIF", "W32.Floxif" };
        for (auto *m : markers) {
            const int mLen = int(strlen(m));
            const qint64 scanLim = qMin(mapSize, qint64(2 * 1024 * 1024));
            for (qint64 off = 0; off + mLen <= scanLim; ++off) {
                if (memcmp(base + off, m, mLen) == 0) {
                    if (score < 40) score += 40;
                    if (info.detectionName.isEmpty()) {
                        info.detectionName = QStringLiteral("Virus:Win32/Floxif.gen!str");
                        info.family = "Floxif";
                        info.severity = 10;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                    }
                    info.reason += QStringLiteral("Floxif string '%1' found; ").arg(QString::fromLatin1(m));
                    goto floxif_string_done;
                }
            }
        }
        floxif_string_done:;
    }

    return score;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Advanced PE virus family detection ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Mikcer
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
int Scanner::detectMikcerFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                                 const void *secHdrV, int numSections, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 1. EP redirect: EB (short JMP) or 68+C3 (PUSH+RET) ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    for (int i = 0; i < numSections; ++i) {
        if (epRva >= sec[i].VirtualAddress &&
            epRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
        {
            qint64 epFileOff = qint64(sec[i].PointerToRawData) + qint64(epRva - sec[i].VirtualAddress);
            if (epFileOff >= 0 && epFileOff + 6 < mapSize) {
                const uchar *ep = base + epFileOff;

                // EB xx = JMP short
                if (ep[0] == 0xEB) {
                    qint8 rel = static_cast<qint8>(ep[1]);
                    quint32 targetRva = epRva + 2 + quint32(qint32(rel));
                    bool targetInEpSection = (targetRva >= sec[i].VirtualAddress &&
                                              targetRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize);

                    if (!targetInEpSection) {
                        // EB escape out of EP section ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â always suspicious
                        for (int j = 0; j < numSections; ++j) {
                            if (targetRva >= sec[j].VirtualAddress &&
                                targetRva < sec[j].VirtualAddress + sec[j].Misc.VirtualSize)
                            {
                                int tNL = 0;
                                while (tNL < 8 && sec[j].Name[tNL] != '\0') tNL++;
                                QString tgtName = QString::fromLatin1(
                                    reinterpret_cast<const char*>(sec[j].Name), tNL).toLower();

                                if (isKnownPackerSection(tgtName)) break;

                                DWORD tgtF = sec[j].Characteristics;
                                bool tgtExec = (tgtF & IMAGE_SCN_MEM_EXECUTE) != 0;

                                if (tgtExec || j == numSections - 1) {
                                    score += 55;
                                    info.detectionName = QStringLiteral("Virus:Win32/Mikcer.gen!EP");
                                    info.family = "Mikcer";
                                    info.severity = 9;
                                    info.repairable = true;
                                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                                    info.entryPointPatch = "";
                                    info.reason += QStringLiteral("Mikcer-style short JMP at EP to section '%1'; ").arg(tgtName);
                                } else {
                                    score += 40;
                                    info.reason += QStringLiteral("EP short JMP to non-exec section '%1'; ").arg(tgtName);
                                    info.family = "Mikcer";
                                    info.repairable = true;
                                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                                    info.entryPointPatch = "";
                                }
                                break;
                            }
                        }
                    } else {
                        // EB within same section ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â check if it jumps over a standard
                        // prologue (virus hides the original prologue after the JMP)
                        qint64 targetOff = epFileOff + 2 + qint64(rel);
                        if (targetOff >= 0 && targetOff + 3 < mapSize) {
                            const uchar *tgt = base + targetOff;
                            // If destination is NOT a standard prologue AND the section is RWX
                            DWORD ch = sec[i].Characteristics;
                            bool rwx = (ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE);
                            if (rwx &&
                                !(tgt[0] == 0x55 && tgt[1] == 0x8B && tgt[2] == 0xEC) &&
                                !(tgt[0] == 0x48 && tgt[1] == 0x83))
                            {
                                score += 35;
                                info.reason += QStringLiteral("EP short JMP in RWX section to non-standard code; ");
                                info.family = "Mikcer";
                                info.repairable = true;
                                info.repairMethod = "PE.SectionWipe+EP.Restore";
                                info.entryPointPatch = "";
                            }
                        }
                    }
                }

                // 68 xx xx xx xx C3 = PUSH addr + RET
                // This is ALWAYS suspicious at EP ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â no compiler generates PUSH+RET as startup.
                if (ep[0] == 0x68 && ep[5] == 0xC3) {
                    score += 60;
                    info.detectionName = QStringLiteral("Virus:Win32/Mikcer.B!EP");
                    info.family = "Mikcer";
                    info.severity = 9;
                    info.repairable = true;
                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                    info.entryPointPatch = "";
                    info.reason += QStringLiteral("Mikcer.B PUSH+RET redirect at EP (68+C3 pattern); ");
                }

                // E9 (JMP rel32) at EP ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â cross-section jump is Mikcer.B signature
                if (score == 0 && ep[0] == 0xE9) {
                    qint32 rel = *reinterpret_cast<const qint32*>(ep + 1);
                    quint32 targetRva = epRva + 5 + quint32(rel);

                    for (int j = 0; j < numSections; ++j) {
                        if (targetRva >= sec[j].VirtualAddress &&
                            targetRva < sec[j].VirtualAddress + sec[j].Misc.VirtualSize)
                        {
                            if (j != i) {
                                int tNL = 0;
                                while (tNL < 8 && sec[j].Name[tNL] != '\0') tNL++;
                                QString tgtName = QString::fromLatin1(
                                    reinterpret_cast<const char*>(sec[j].Name), tNL).toLower();
                                if (!isKnownPackerSection(tgtName)) {
                                    score += 55;
                                    info.detectionName = QStringLiteral("Virus:Win32/Mikcer.B!JMP");
                                    info.family = "Mikcer";
                                    info.severity = 9;
                                    info.repairable = true;
                                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                                    info.entryPointPatch = "";
                                    info.reason += QStringLiteral("Mikcer.B E9 JMP to section '%1' at EP; ").arg(tgtName);
                                }
                            } else {
                                // Same section ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â check for code cave or virus stub
                                quint32 offInSec = targetRva - sec[j].VirtualAddress;
                                qint64 tgtOff = qint64(sec[j].PointerToRawData) + qint64(offInSec);
                                bool inCave = (sec[j].Misc.VirtualSize > 0 && offInSec >= sec[j].Misc.VirtualSize);
                                bool virusStub = false;
                                if (tgtOff >= 0 && tgtOff + 6 < mapSize) {
                                    const uchar *t = base + tgtOff;
                                    virusStub = (t[0] == 0x60) || (t[0] == 0x9C) ||
                                                (t[0] == 0xE8 && t[1]==0 && t[2]==0 && t[3]==0 && t[4]==0);
                                }
                                if (inCave || virusStub) {
                                    score += 55;
                                    info.detectionName = QStringLiteral("Virus:Win32/Mikcer.B!Cave");
                                    info.family = "Mikcer";
                                    info.severity = 9;
                                    info.repairable = true;
                                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                                    info.entryPointPatch = "";
                                    info.reason += QStringLiteral("Mikcer.B E9 JMP to code cave/virus stub in same section; ");
                                }
                            }
                            break;
                        }
                    }
                }

                // E8 (CALL rel32) at EP ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â cross-section or CALL $+5 is Mikcer pattern
                if (score == 0 && ep[0] == 0xE8) {
                    qint32 callRel = *reinterpret_cast<const qint32*>(ep + 1);
                    if (callRel == 0) {
                        // CALL $+5 = always virus
                        score += 60;
                        info.detectionName = QStringLiteral("Virus:Win32/Mikcer.B!Delta");
                        info.family = "Mikcer";
                        info.severity = 9;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        info.entryPointPatch = "";
                        info.reason += QStringLiteral("Mikcer.B CALL $+5 delta-offset at EP; ");
                    } else {
                        quint32 callTarget = epRva + 5 + quint32(callRel);
                        for (int j = 0; j < numSections; ++j) {
                            if (callTarget >= sec[j].VirtualAddress &&
                                callTarget < sec[j].VirtualAddress + sec[j].Misc.VirtualSize)
                            {
                                if (j != i) {
                                    int tNL = 0;
                                    while (tNL < 8 && sec[j].Name[tNL] != '\0') tNL++;
                                    QString tgtName = QString::fromLatin1(
                                        reinterpret_cast<const char*>(sec[j].Name), tNL).toLower();
                                    if (!isKnownPackerSection(tgtName)) {
                                        score += 50;
                                        info.detectionName = QStringLiteral("Virus:Win32/Mikcer.B!CALL");
                                        info.family = "Mikcer";
                                        info.severity = 9;
                                        info.repairable = true;
                                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                                        info.entryPointPatch = "";
                                        info.reason += QStringLiteral("Mikcer.B cross-section CALL to '%1' at EP; ").arg(tgtName);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            break;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 2. Mikcer string markers ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    {
        static const char *markers[] = { "Mikcer", "mikcer", "MIKCER", "mkc32", ".mkc", "W32.Mikcer" };
        for (auto *m : markers) {
            const int mLen = int(strlen(m));
            const qint64 scanLim = qMin(mapSize, qint64(1024 * 1024));
            for (qint64 off = 0; off + mLen <= scanLim; ++off) {
                if (memcmp(base + off, m, mLen) == 0) {
                    if (score < 40) score += 40;
                    if (info.detectionName.isEmpty()) {
                        info.detectionName = QStringLiteral("Virus:Win32/Mikcer.gen!str");
                        info.family = "Mikcer";
                        info.severity = 9;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                    }
                    info.reason += QStringLiteral("Mikcer string marker found; ");
                    goto mikcer_string_done;
                }
            }
        }
        mikcer_string_done:;
    }

    return score;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Advanced PE virus family detection ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Sality
//  Sality uses CALL $+5 / PUSHAD delta-offset to find itself, then
//  appends or extends the last section with RWX code.
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
int Scanner::detectSalityFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                                 const void *secHdrV, int numSections, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 1. Named infector section ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    for (int i = 0; i < numSections; ++i) {
        int nameLen = 0;
        while (nameLen < 8 && sec[i].Name[nameLen] != '\0') nameLen++;
        const QString nm = QString::fromLatin1(reinterpret_cast<const char*>(sec[i].Name), nameLen).toLower();
        if (nm == ".sality" || nm == ".sal") {
            score += 80;
            info.detectionName = QStringLiteral("Virus:Win32/Sality.gen");
            info.family = "Sality";
            info.severity = 10;
            info.repairable = true;
            info.repairMethod = "PE.SectionWipe+EP.Restore";
            info.entryPointPatch = "";
            info.reason += QStringLiteral("Sality infector section '%1' detected; ").arg(nm);
            return score;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 2. EP byte pattern: CALL $+5; POP EBP/ESI; SUB ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Sality classic: E8 00 00 00 00 5D 81 ED  (CALL $+5; POP EBP; SUB EBP, imm32)
    // Sality variant: 60 E8 00 00 00 00 5E 81 EE (PUSHAD; CALL $+5; POP ESI; SUB ESI, imm32)
    for (int i = 0; i < numSections; ++i) {
        if (epRva >= sec[i].VirtualAddress &&
            epRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
        {
            qint64 epFileOff = qint64(sec[i].PointerToRawData) + qint64(epRva - sec[i].VirtualAddress);
            if (epFileOff < 0 || epFileOff + 16 > mapSize) break;

            const uchar *ep = base + epFileOff;

            // Pattern A: E8 00 00 00 00 5D 81 ED
            if (ep[0] == 0xE8 && ep[1] == 0x00 && ep[2] == 0x00 &&
                ep[3] == 0x00 && ep[4] == 0x00 && ep[5] == 0x5D &&
                ep[6] == 0x81 && ep[7] == 0xED)
            {
                score += 75;
                info.detectionName = QStringLiteral("Virus:Win32/Sality.gen!EP");
                info.family = "Sality";
                info.severity = 10;
                info.repairable = true;
                info.repairMethod = "PE.SectionWipe+EP.Restore";
                info.entryPointPatch = "";
                info.reason += QStringLiteral("Sality EP pattern: CALL $+5; POP EBP; SUB EBP,imm32; ");
            }

            // Pattern B: 60 E8 00 00 00 00 5E 81 EE (PUSHAD variant)
            if (ep[0] == 0x60 && ep[1] == 0xE8 && ep[2] == 0x00 &&
                ep[3] == 0x00 && ep[4] == 0x00 && ep[5] == 0x00 &&
                ep[6] == 0x5E && ep[7] == 0x81 && ep[8] == 0xEE)
            {
                score += 75;
                info.detectionName = QStringLiteral("Virus:Win32/Sality.AE!EP");
                info.family = "Sality";
                info.severity = 10;
                info.repairable = true;
                info.repairMethod = "PE.SectionWipe+EP.Restore";
                info.entryPointPatch = "";
                info.reason += QStringLiteral("Sality EP pattern: PUSHAD; CALL $+5; POP ESI; SUB ESI,imm32; ");
            }

            // Pattern C: 60 E8 00 00 00 00 5D 81 ED (PUSHAD; CALL; POP EBP)
            if (score == 0 && ep[0] == 0x60 && ep[1] == 0xE8 &&
                ep[2] == 0x00 && ep[3] == 0x00 && ep[4] == 0x00 &&
                ep[5] == 0x00 && ep[6] == 0x5D && ep[7] == 0x81)
            {
                score += 70;
                info.detectionName = QStringLiteral("Virus:Win32/Sality.AT!EP");
                info.family = "Sality";
                info.severity = 10;
                info.repairable = true;
                info.repairMethod = "PE.SectionWipe+EP.Restore";
                info.entryPointPatch = "";
                info.reason += QStringLiteral("Sality EP pattern: PUSHAD; CALL $+5; POP EBP; ");
            }

            break;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 3. Sality modifies the LAST section to be RWX + extends its raw size ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    if (score == 0 && numSections > 1) {
        const auto &last = sec[numSections - 1];
        DWORD ch = last.Characteristics;
        bool rwx = (ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE) && (ch & IMAGE_SCN_MEM_READ);
        // Sality signature: last section is RWX AND its VirtualSize is much larger than raw size
        if (rwx && last.Misc.VirtualSize > 0 && last.SizeOfRawData > 0) {
            // Check if EP jumps to this last section
            if (epRva >= last.VirtualAddress &&
                epRva < last.VirtualAddress + last.Misc.VirtualSize)
            {
                // EP in last RWX section ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â check for CALL $+5 pattern there
                qint64 epOff = qint64(last.PointerToRawData) + qint64(epRva - last.VirtualAddress);
                if (epOff >= 0 && epOff + 8 < mapSize) {
                    const uchar *ep = base + epOff;
                    if (ep[0] == 0xE8 && ep[1] == 0x00 && ep[2] == 0x00 &&
                        ep[3] == 0x00 && ep[4] == 0x00) {
                        score += 65;
                        info.detectionName = QStringLiteral("Virus:Win32/Sality.gen!LastSec");
                        info.family = "Sality";
                        info.severity = 10;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        info.entryPointPatch = "";
                        info.reason += QStringLiteral("Sality: CALL $+5 in RWX last section; ");
                    }
                }
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 4. String markers ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    {
        static const char *markers[] = { "Sality", "sality", "SALITY", "Win32.Sality", ".sality" };
        for (auto *m : markers) {
            const int mLen = int(strlen(m));
            const qint64 scanLim = qMin(mapSize, qint64(1024 * 1024));
            for (qint64 off = 0; off + mLen <= scanLim; ++off) {
                if (memcmp(base + off, m, mLen) == 0) {
                    if (score < 40) score += 40;
                    if (info.detectionName.isEmpty()) {
                        info.detectionName = QStringLiteral("Virus:Win32/Sality.gen!str");
                        info.family = "Sality";
                        info.severity = 10;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        info.entryPointPatch = "";
                    }
                    info.reason += QStringLiteral("Sality string marker found; ");
                    goto sality_string_done;
                }
            }
        }
        sality_string_done:;
    }

    return score;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Advanced PE virus family detection ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Virut
//  Virut uses polymorphic conditional JMP (JZ/JNZ 0F 8x) at EP,
//  hooks IAT entries, and appends encrypted body to last section.
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
int Scanner::detectVirutFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                                const void *secHdrV, int numSections, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 1. Named infector section ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    for (int i = 0; i < numSections; ++i) {
        int nameLen = 0;
        while (nameLen < 8 && sec[i].Name[nameLen] != '\0') nameLen++;
        const QString nm = QString::fromLatin1(reinterpret_cast<const char*>(sec[i].Name), nameLen).toLower();
        if (nm == ".virut" || nm == ".vrt") {
            score += 80;
            info.detectionName = QStringLiteral("Virus:Win32/Virut.gen");
            info.family = "Virut";
            info.severity = 10;
            info.repairable = true;
            info.repairMethod = "PE.SectionWipe+EP.Restore";
            info.entryPointPatch = "";
            info.reason += QStringLiteral("Virut infector section '%1' detected; ").arg(nm);
            return score;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 2. EP byte patterns: Virut conditional JMP ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Virut.CE: CC 90 E9 xx xx xx xx (INT3; NOP; JMP)
    // Virut polymorphic: 0F 84/85 xx xx xx xx at/near EP
    for (int i = 0; i < numSections; ++i) {
        if (epRva >= sec[i].VirtualAddress &&
            epRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
        {
            qint64 epFileOff = qint64(sec[i].PointerToRawData) + qint64(epRva - sec[i].VirtualAddress);
            if (epFileOff < 0 || epFileOff + 16 > mapSize) break;

            const uchar *ep = base + epFileOff;

            // Virut.CE: CC 90 E9 (INT3; NOP; JMP rel32) at EP
            if (ep[0] == 0xCC && ep[1] == 0x90 && ep[2] == 0xE9) {
                score += 70;
                info.detectionName = QStringLiteral("Virus:Win32/Virut.CE!EP");
                info.family = "Virut";
                info.severity = 10;
                info.repairable = true;
                info.repairMethod = "PE.SectionWipe+EP.Restore";
                info.entryPointPatch = "";
                info.reason += QStringLiteral("Virut.CE pattern: INT3+NOP+JMP at EP; ");
            }

            // Virut polymorphic: near-EP conditional JMP (0F 84 / 0F 85) to last section
            // Scan first 32 bytes at EP for a 0F 8x conditional JMP
            if (score == 0) {
                for (int off = 0; off < 24 && epFileOff + off + 6 < mapSize; ++off) {
                    if (ep[off] == 0x0F && (ep[off + 1] >= 0x80 && ep[off + 1] <= 0x8F)) {
                        // Found a Jcc near at EP area ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â check if target is in last section
                        qint32 rel = *reinterpret_cast<const qint32*>(ep + off + 2);
                        quint32 jccTarget = epRva + quint32(off) + 6 + quint32(rel);

                        if (numSections > 1) {
                            const auto &last = sec[numSections - 1];
                            if (jccTarget >= last.VirtualAddress &&
                                jccTarget < last.VirtualAddress + last.Misc.VirtualSize)
                            {
                                int tNL = 0;
                                while (tNL < 8 && last.Name[tNL] != '\0') tNL++;
                                QString tgtName = QString::fromLatin1(
                                    reinterpret_cast<const char*>(last.Name), tNL).toLower();

                                if (!isKnownPackerSection(tgtName)) {
                                    score += 65;
                                    info.detectionName = QStringLiteral("Virus:Win32/Virut.gen!JCC");
                                    info.family = "Virut";
                                    info.severity = 10;
                                    info.repairable = true;
                                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                                    info.entryPointPatch = "";
                                    info.reason += QStringLiteral("Virut: conditional JMP (0F %1) at EP+%2 to last section '%3'; ")
                                                       .arg(ep[off + 1], 2, 16, QChar('0'))
                                                       .arg(off).arg(tgtName);
                                }
                                break;
                            }
                        }
                    }
                }
            }

            // Virut pattern: E9 jmp at EP preceded by NOPs/INT3s (padding)
            if (score == 0 && epFileOff >= 2) {
                // Check if bytes BEFORE EP are CC CC or 90 90 (unusual padding)
                if ((base[epFileOff - 1] == 0xCC || base[epFileOff - 1] == 0x90) &&
                    (base[epFileOff - 2] == 0xCC || base[epFileOff - 2] == 0x90) &&
                    ep[0] == 0xE9)
                {
                    qint32 rel = *reinterpret_cast<const qint32*>(ep + 1);
                    quint32 targetRva = epRva + 5 + quint32(rel);
                    // Check target is in last section
                    if (numSections > 1) {
                        const auto &last = sec[numSections - 1];
                        if (targetRva >= last.VirtualAddress &&
                            targetRva < last.VirtualAddress + last.Misc.VirtualSize)
                        {
                            score += 60;
                            info.detectionName = QStringLiteral("Virus:Win32/Virut.gen!EP");
                            info.family = "Virut";
                            info.severity = 10;
                            info.repairable = true;
                            info.repairMethod = "PE.SectionWipe+EP.Restore";
                            info.entryPointPatch = "";
                            info.reason += QStringLiteral("Virut: NOP/INT3-padded JMP at EP to last section; ");
                        }
                    }
                }
            }

            break;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 3. String markers ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    {
        static const char *markers[] = { "Virut", "virut", "VIRUT", "Win32.Virut", ".vrt" };
        for (auto *m : markers) {
            const int mLen = int(strlen(m));
            const qint64 scanLim = qMin(mapSize, qint64(1024 * 1024));
            for (qint64 off = 0; off + mLen <= scanLim; ++off) {
                if (memcmp(base + off, m, mLen) == 0) {
                    if (score < 40) score += 40;
                    if (info.detectionName.isEmpty()) {
                        info.detectionName = QStringLiteral("Virus:Win32/Virut.gen!str");
                        info.family = "Virut";
                        info.severity = 10;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        info.entryPointPatch = "";
                    }
                    info.reason += QStringLiteral("Virut string marker found; ");
                    goto virut_string_done;
                }
            }
        }
        virut_string_done:;
    }

    return score;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Advanced PE virus family detection ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Ramnit / Nimnul
//  Ramnit stores the original prologue at the START of its section,
//  allowing precise recovery of the original EP bytes.
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
int Scanner::detectRamnitFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                                 const void *secHdrV, int numSections, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 1. Named infector section ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    for (int i = 0; i < numSections; ++i) {
        int nameLen = 0;
        while (nameLen < 8 && sec[i].Name[nameLen] != '\0') nameLen++;
        const QString nm = QString::fromLatin1(reinterpret_cast<const char*>(sec[i].Name), nameLen).toLower();
        if (nm == ".rmnet" || nm == ".ramnit" || nm == ".nimnul") {
            score += 80;
            info.detectionName = QStringLiteral("Virus:Win32/Ramnit.gen");
            info.family = "Ramnit";
            info.severity = 10;
            info.repairable = true;
            info.repairMethod = "PE.SectionWipe+EP.Restore";

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ KEY INSIGHT: Ramnit stores original prologue in first bytes of its section ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            qint64 secOff = sec[i].PointerToRawData;
            qint64 secSz  = sec[i].SizeOfRawData;
            if (secOff > 0 && secSz >= 16 && secOff + 16 <= mapSize) {
                const uchar *secData = base + secOff;
                // If first bytes look like a standard prologue, use them
                if ((secData[0] == 0x55 && secData[1] == 0x8B && secData[2] == 0xEC) ||
                    (secData[0] == 0x8B && secData[1] == 0xFF && secData[2] == 0x55) ||
                    (secData[0] == 0x6A) ||
                    (secData[0] == 0x48 && secData[1] == 0x89) ||
                    (secData[0] == 0x48 && secData[1] == 0x83 && secData[2] == 0xEC))
                {
                    // Extract first 5 bytes as the original prologue
                    QByteArray orig(reinterpret_cast<const char*>(secData), 5);
                    info.entryPointPatch = orig.toHex().toUpper();
                    info.reason += QStringLiteral("Ramnit: recovered original prologue '%1' from section '%2'; ")
                                       .arg(info.entryPointPatch, nm);
                } else {
                    info.entryPointPatch = "";
                }
            } else {
                info.entryPointPatch = "";
            }
            info.reason += QStringLiteral("Ramnit infector section '%1' detected; ").arg(nm);
            return score;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 2. EP JMP + stored prologue recovery ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Ramnit hooks EP with E9 JMP to its appended section, and the first bytes
    // of that section ARE the original prologue (saved before overwriting EP).
    for (int i = 0; i < numSections; ++i) {
        if (epRva >= sec[i].VirtualAddress &&
            epRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
        {
            qint64 epFileOff = qint64(sec[i].PointerToRawData) + qint64(epRva - sec[i].VirtualAddress);
            if (epFileOff < 0 || epFileOff + 6 > mapSize) break;

            const uchar *ep = base + epFileOff;

            if (ep[0] == 0xE9) {
                qint32 rel = *reinterpret_cast<const qint32*>(ep + 1);
                quint32 targetRva = epRva + 5 + quint32(rel);

                // Find target section
                for (int j = 0; j < numSections; ++j) {
                    if (j == i) continue;
                    if (targetRva >= sec[j].VirtualAddress &&
                        targetRva < sec[j].VirtualAddress + sec[j].Misc.VirtualSize)
                    {
                        int tNL = 0;
                        while (tNL < 8 && sec[j].Name[tNL] != '\0') tNL++;
                        QString tgtName = QString::fromLatin1(
                            reinterpret_cast<const char*>(sec[j].Name), tNL).toLower();

                        if (isKnownPackerSection(tgtName)) break;

                        // Check if the target section contains Ramnit-style code
                        qint64 tgtFileOff = qint64(sec[j].PointerToRawData) +
                                            qint64(targetRva - sec[j].VirtualAddress);
                        if (tgtFileOff >= 0 && tgtFileOff + 32 < mapSize) {
                            const uchar *tgt = base + tgtFileOff;

                            // Ramnit body typically starts with:
                            // 55 8B EC 83 EC (saved prologue + setup) or
                            // 60 E8 (PUSHAD; CALL $+5)
                            bool ramnitLike = false;

                            // Check if the virus stub has PUSHAD (60) or CALL $+5 pattern
                            // within first 16 bytes
                            for (int k = 0; k < 12 && tgtFileOff + k + 5 < mapSize; ++k) {
                                if (tgt[k] == 0x60 ||
                                    (tgt[k] == 0xE8 && tgt[k+1] == 0x00 && tgt[k+2] == 0x00 &&
                                     tgt[k+3] == 0x00 && tgt[k+4] == 0x00))
                                {
                                    ramnitLike = true;
                                    break;
                                }
                            }

                            if (ramnitLike || j == numSections - 1) {
                                DWORD tgtF = sec[j].Characteristics;
                                bool tgtExec = (tgtF & IMAGE_SCN_MEM_EXECUTE) != 0;
                                bool tgtWrite = (tgtF & IMAGE_SCN_MEM_WRITE) != 0;

                                if (tgtExec || tgtWrite || j == numSections - 1) {
                                    score += 65;
                                    info.detectionName = QStringLiteral("Virus:Win32/Ramnit.gen!EP");
                                    info.family = "Ramnit";
                                    info.severity = 10;
                                    info.repairable = true;
                                    info.repairMethod = "PE.SectionWipe+EP.Restore";

                                    // Try to recover prologue from start of infector section
                                    qint64 secStart = sec[j].PointerToRawData;
                                    if (secStart > 0 && secStart + 5 <= mapSize) {
                                        const uchar *sdat = base + secStart;
                                        if ((sdat[0] == 0x55 && sdat[1] == 0x8B) ||
                                            (sdat[0] == 0x8B && sdat[1] == 0xFF) ||
                                            (sdat[0] == 0x6A) ||
                                            (sdat[0] == 0x48 && sdat[1] == 0x89))
                                        {
                                            QByteArray orig(reinterpret_cast<const char*>(sdat), 5);
                                            info.entryPointPatch = orig.toHex().toUpper();
                                            info.reason += QStringLiteral("Ramnit: recovered prologue '%1'; ").arg(info.entryPointPatch);
                                        } else {
                                            info.entryPointPatch = "";
                                        }
                                    } else {
                                        info.entryPointPatch = "";
                                    }

                                    info.reason += QStringLiteral("Ramnit-style JMP at EP to section '%1'; ").arg(tgtName);
                                }
                            }
                        }
                        break;
                    }
                }
            }
            break;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 3. String markers ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    {
        static const char *markers[] = { "Ramnit", "ramnit", "RAMNIT", "Nimnul", "nimnul",
                                         "Win32.Ramnit", ".rmnet", "W32.Ramnit" };
        for (auto *m : markers) {
            const int mLen = int(strlen(m));
            const qint64 scanLim = qMin(mapSize, qint64(1024 * 1024));
            for (qint64 off = 0; off + mLen <= scanLim; ++off) {
                if (memcmp(base + off, m, mLen) == 0) {
                    if (score < 40) score += 40;
                    if (info.detectionName.isEmpty()) {
                        info.detectionName = QStringLiteral("Virus:Win32/Ramnit.gen!str");
                        info.family = "Ramnit";
                        info.severity = 10;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        info.entryPointPatch = "";
                    }
                    info.reason += QStringLiteral("Ramnit string marker found; ");
                    goto ramnit_string_done;
                }
            }
        }
        ramnit_string_done:;
    }

    return score;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Advanced PE virus family detection ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Neshta
//  Neshta uses code caves in .text section (~41KB appended) and
//  hooks EP with JMP. Does NOT add a new section.
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
int Scanner::detectNeshtaFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                                 const void *secHdrV, int numSections, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 1. Named section ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    for (int i = 0; i < numSections; ++i) {
        int nameLen = 0;
        while (nameLen < 8 && sec[i].Name[nameLen] != '\0') nameLen++;
        const QString nm = QString::fromLatin1(reinterpret_cast<const char*>(sec[i].Name), nameLen).toLower();
        if (nm == ".neshta") {
            score += 80;
            info.detectionName = QStringLiteral("Virus:Win32/Neshta.gen");
            info.family = "Neshta";
            info.severity = 9;
            info.repairable = true;
            info.repairMethod = "PE.SectionWipe+EP.Restore";
            info.entryPointPatch = "";
            info.reason += QStringLiteral("Neshta infector section detected; ");
            return score;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 2. Code cave in .text + EP hook ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Neshta injects ~41,472 bytes (0xA200) into the .text section's raw padding
    // and hooks EP with a JMP to this cave.
    for (int i = 0; i < numSections; ++i) {
        int nameLen = 0;
        while (nameLen < 8 && sec[i].Name[nameLen] != '\0') nameLen++;
        const QString nm = QString::fromLatin1(reinterpret_cast<const char*>(sec[i].Name), nameLen).toLower();

        if (nm != ".text" && nm != ".code") continue;

        const qint64 rawOff = sec[i].PointerToRawData;
        const qint64 rawSz  = sec[i].SizeOfRawData;
        const qint64 virtSz = sec[i].Misc.VirtualSize;

        if (rawOff <= 0 || rawSz <= 0 || rawOff + rawSz > mapSize) continue;
        if (virtSz <= 0 || rawSz <= virtSz) continue;

        // Neshta cave is typically ~41KB
        const qint64 caveSz = rawSz - virtSz;
        if (caveSz >= 38000 && caveSz <= 50000) {
            // Check EP hooks to somewhere in this cave
            if (epRva >= sec[i].VirtualAddress &&
                epRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
            {
                qint64 epFileOff = rawOff + qint64(epRva - sec[i].VirtualAddress);
                if (epFileOff >= 0 && epFileOff + 6 < mapSize) {
                    const uchar *ep = base + epFileOff;
                    if (ep[0] == 0xE9) {
                        qint32 rel = *reinterpret_cast<const qint32*>(ep + 1);
                        quint32 targetRva = epRva + 5 + quint32(rel);
                        // Target should be in the cave area (beyond VirtualSize but within RawSize)
                        quint32 caveStartRva = sec[i].VirtualAddress + quint32(virtSz);
                        quint32 caveEndRva = sec[i].VirtualAddress + quint32(rawSz);
                        if (targetRva >= caveStartRva && targetRva < caveEndRva) {
                            score += 70;
                            info.detectionName = QStringLiteral("Virus:Win32/Neshta.gen!Cave");
                            info.family = "Neshta";
                            info.severity = 9;
                            info.repairable = true;
                            info.repairMethod = "PE.SectionWipe+EP.Restore";
                            info.entryPointPatch = "";
                            info.reason += QStringLiteral("Neshta: EP JMP to ~%1KB code cave in .text section; ")
                                               .arg(caveSz / 1024);
                        }
                    }
                }
            }

            // Even without EP hook, ~41KB code cave with active bytes is suspicious
            if (score == 0) {
                const qint64 caveOff = rawOff + virtSz;
                if (caveOff + 256 <= mapSize) {
                    int nonZero = 0;
                    for (qint64 j = 0; j < 256; ++j) {
                        uchar b = base[caveOff + j];
                        if (b != 0x00 && b != 0xCC && b != 0x90) ++nonZero;
                    }
                    if (nonZero > 200) {
                        score += 45;
                        info.reason += QStringLiteral("Neshta: ~%1KB active code cave in .text section; ").arg(caveSz / 1024);
                        info.family = "Neshta";
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        info.entryPointPatch = "";
                    }
                }
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 3. String markers ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    {
        static const char *markers[] = { "Neshta", "neshta", "NESHTA", "Win32.Neshta",
                                         "Delphi-the best" }; // Neshta's embedded string
        for (auto *m : markers) {
            const int mLen = int(strlen(m));
            const qint64 scanLim = qMin(mapSize, qint64(2 * 1024 * 1024));
            for (qint64 off = 0; off + mLen <= scanLim; ++off) {
                if (memcmp(base + off, m, mLen) == 0) {
                    if (score < 50) score += 50;
                    if (info.detectionName.isEmpty()) {
                        info.detectionName = QStringLiteral("Virus:Win32/Neshta.gen!str");
                        info.family = "Neshta";
                        info.severity = 9;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        info.entryPointPatch = "";
                    }
                    info.reason += QStringLiteral("Neshta string '%1' found; ").arg(QString::fromLatin1(m));
                    goto neshta_string_done;
                }
            }
        }
        neshta_string_done:;
    }

    return score;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Advanced PE virus family detection ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Expiro
//  Expiro infects ALL executable sections, extends their raw data,
//  and hooks EP. It can also modify the Import Table.
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
int Scanner::detectExpiroFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                                 const void *secHdrV, int numSections, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 1. Named infector section ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    for (int i = 0; i < numSections; ++i) {
        int nameLen = 0;
        while (nameLen < 8 && sec[i].Name[nameLen] != '\0') nameLen++;
        const QString nm = QString::fromLatin1(reinterpret_cast<const char*>(sec[i].Name), nameLen).toLower();
        if (nm == ".expiro") {
            score += 80;
            info.detectionName = QStringLiteral("Virus:Win32/Expiro.gen");
            info.family = "Expiro";
            info.severity = 10;
            info.repairable = true;
            info.repairMethod = "PE.SectionWipe+EP.Restore";
            info.entryPointPatch = "";
            info.reason += QStringLiteral("Expiro infector section detected; ");
            return score;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 2. EP pattern: CALL $+5; POP EBX; SUB EBX (Expiro's delta offset) ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    for (int i = 0; i < numSections; ++i) {
        if (epRva >= sec[i].VirtualAddress &&
            epRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
        {
            qint64 epFileOff = qint64(sec[i].PointerToRawData) + qint64(epRva - sec[i].VirtualAddress);
            if (epFileOff < 0 || epFileOff + 16 > mapSize) break;

            const uchar *ep = base + epFileOff;

            // Expiro: E8 00 00 00 00 5B 81 EB (CALL $+5; POP EBX; SUB EBX,imm32)
            if (ep[0] == 0xE8 && ep[1] == 0x00 && ep[2] == 0x00 &&
                ep[3] == 0x00 && ep[4] == 0x00 && ep[5] == 0x5B &&
                ep[6] == 0x81 && ep[7] == 0xEB)
            {
                score += 70;
                info.detectionName = QStringLiteral("Virus:Win32/Expiro.gen!EP");
                info.family = "Expiro";
                info.severity = 10;
                info.repairable = true;
                info.repairMethod = "PE.SectionWipe+EP.Restore";
                info.entryPointPatch = "";
                info.reason += QStringLiteral("Expiro EP: CALL $+5; POP EBX; SUB EBX,imm32; ");
            }

            // Expiro.T variant: E8 00 00 00 00 58 (CALL $+5; POP EAX)
            if (score == 0 && ep[0] == 0xE8 && ep[1] == 0x00 && ep[2] == 0x00 &&
                ep[3] == 0x00 && ep[4] == 0x00 && ep[5] == 0x58)
            {
                score += 65;
                info.detectionName = QStringLiteral("Virus:Win32/Expiro.T!EP");
                info.family = "Expiro";
                info.severity = 10;
                info.repairable = true;
                info.repairMethod = "PE.SectionWipe+EP.Restore";
                info.entryPointPatch = "";
                info.reason += QStringLiteral("Expiro.T EP: CALL $+5; POP EAX; ");
            }

            break;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 3. Multi-section infection indicator ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    // Expiro is unique: it infects MULTIPLE executable sections (not just one)
    if (score == 0) {
        int rwxCount = 0;
        int highEntropyExec = 0;
        for (int i = 0; i < numSections; ++i) {
            DWORD ch = sec[i].Characteristics;
            bool exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool write = (ch & IMAGE_SCN_MEM_WRITE) != 0;
            if (exec && write) ++rwxCount;
            if (exec && sec[i].SizeOfRawData > 4096 && sec[i].PointerToRawData > 0) {
                qint64 off = sec[i].PointerToRawData;
                qint64 sz = qMin<qint64>(sec[i].SizeOfRawData, 65536);
                if (off + sz <= mapSize) {
                    double H = shannonEntropy(base + off, sz);
                    if (H > 7.2) ++highEntropyExec;
                }
            }
        }
        // 3+ RWX sections with high entropy = likely Expiro multi-section infection
        if (rwxCount >= 3 && highEntropyExec >= 2) {
            score += 55;
            info.detectionName = QStringLiteral("Virus:Win32/Expiro.gen!Multi");
            info.family = "Expiro";
            info.severity = 10;
            info.repairable = true;
            info.repairMethod = "PE.SectionWipe+EP.Restore";
            info.entryPointPatch = "";
            info.reason += QStringLiteral("Expiro: %1 RWX sections + %2 high-entropy exec sections; ")
                               .arg(rwxCount).arg(highEntropyExec);
        }
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 4. String markers ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    {
        static const char *markers[] = { "Expiro", "expiro", "EXPIRO", "Win32.Expiro" };
        for (auto *m : markers) {
            const int mLen = int(strlen(m));
            const qint64 scanLim = qMin(mapSize, qint64(1024 * 1024));
            for (qint64 off = 0; off + mLen <= scanLim; ++off) {
                if (memcmp(base + off, m, mLen) == 0) {
                    if (score < 40) score += 40;
                    if (info.detectionName.isEmpty()) {
                        info.detectionName = QStringLiteral("Virus:Win32/Expiro.gen!str");
                        info.family = "Expiro";
                        info.severity = 10;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        info.entryPointPatch = "";
                    }
                    info.reason += QStringLiteral("Expiro string marker found; ");
                    goto expiro_string_done;
                }
            }
        }
        expiro_string_done:;
    }

    return score;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  IAT (Import Address Table) hook detection
//  Checks that import entries point to legitimate code sections
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
int Scanner::detectIATHooks(const uchar *base, qint64 mapSize, quint32 numDirs,
                             const void *dataDirsV, const void *secHdrV, int numSections, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);
    auto dirs = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(dataDirsV);

    if (numDirs <= IMAGE_DIRECTORY_ENTRY_IMPORT) return 0;

    DWORD importRva  = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importSize = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (importRva == 0 || importSize == 0) return 0;

    // Find the file offset of the import directory
    qint64 importFileOff = -1;
    for (int i = 0; i < numSections; ++i) {
        if (importRva >= sec[i].VirtualAddress &&
            importRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
        {
            importFileOff = qint64(sec[i].PointerToRawData) + qint64(importRva - sec[i].VirtualAddress);
            break;
        }
    }
    if (importFileOff < 0 || importFileOff + 20 > mapSize) return 0;

    // Walk import descriptors
    int suspiciousImports = 0;
    int totalImports = 0;
    const qint64 maxDescriptors = 256; // safety cap

    for (qint64 d = 0; d < maxDescriptors; ++d) {
        qint64 descOff = importFileOff + d * 20;
        if (descOff + 20 > mapSize) break;

        auto desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + descOff);
        if (desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0) break; // end of imports

        ++totalImports;

        // Check if the DLL name RVA points to valid memory
        DWORD nameRva = desc->Name;
        if (nameRva == 0) continue;

        // Find file offset of DLL name
        for (int i = 0; i < numSections; ++i) {
            if (nameRva >= sec[i].VirtualAddress &&
                nameRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
            {
                qint64 nameOff = qint64(sec[i].PointerToRawData) + qint64(nameRva - sec[i].VirtualAddress);
                if (nameOff >= 0 && nameOff + 4 < mapSize) {
                    // Check if the DLL name is in a writable section (suspicious)
                    DWORD ch = sec[i].Characteristics;
                    bool isWrite = (ch & IMAGE_SCN_MEM_WRITE) != 0;
                    bool isExec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
                    // Import names in a writable+executable section = suspicious
                    if (isWrite && isExec) {
                        ++suspiciousImports;
                    }
                }
                break;
            }
        }

        // Check if FirstThunk entries point to suspicious sections
        DWORD ftRva = desc->FirstThunk;
        if (ftRva == 0) continue;

        for (int i = 0; i < numSections; ++i) {
            if (ftRva >= sec[i].VirtualAddress &&
                ftRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
            {
                qint64 ftOff = qint64(sec[i].PointerToRawData) + qint64(ftRva - sec[i].VirtualAddress);
                if (ftOff >= 0 && ftOff + 8 < mapSize) {
                    // Read first thunk entry
                    DWORD thunkVal = *reinterpret_cast<const DWORD*>(base + ftOff);
                    if (thunkVal != 0) {
                        // Check if thunk points to last section (infector-added)
                        if (numSections > 1) {
                            const auto &last = sec[numSections - 1];
                            if (thunkVal >= last.VirtualAddress &&
                                thunkVal < last.VirtualAddress + last.Misc.VirtualSize)
                            {
                                int tNL = 0;
                                while (tNL < 8 && last.Name[tNL] != '\0') tNL++;
                                QString tgtName = QString::fromLatin1(
                                    reinterpret_cast<const char*>(last.Name), tNL).toLower();
                                if (!isStandardSection(tgtName) && !isKnownPackerSection(tgtName)) {
                                    ++suspiciousImports;
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    if (suspiciousImports >= 3) {
        score += 35;
        info.reason += QStringLiteral("IAT hooks: %1/%2 imports point to suspicious sections; ")
                           .arg(suspiciousImports).arg(totalImports);
    } else if (suspiciousImports >= 1) {
        score += 15;
        info.reason += QStringLiteral("IAT anomaly: %1 import(s) in suspicious location; ")
                           .arg(suspiciousImports);
    }

    return score;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Entry Point anomaly detection ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â catches all EP-hooking infectors
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
int Scanner::detectEntryPointAnomaly(const uchar *base, qint64 mapSize, quint32 epRva,
                                      const void *secHdrV, int numSections, bool is64, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    for (int i = 0; i < numSections; ++i) {
        if (epRva >= sec[i].VirtualAddress &&
            epRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
        {
            qint64 epFileOff = qint64(sec[i].PointerToRawData) + qint64(epRva - sec[i].VirtualAddress);
            if (epFileOff < 0 || epFileOff + 16 > mapSize) break;

            const uchar *ep = base + epFileOff;

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Standard prologues: EP is normal, no anomaly ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            // x86: 55 8B EC / 8B FF 55 / 6A xx / E8 (CALL ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â CRT init) / CC (int3 padding)
            // x64: 48 89 / 48 83 EC / 40 5x / 48 8D / 48 8B / CC
            if (!is64) {
                if ((ep[0] == 0x55 && ep[1] == 0x8B && ep[2] == 0xEC) ||
                    (ep[0] == 0x8B && ep[1] == 0xFF && ep[2] == 0x55) ||
                    (ep[0] == 0x6A) ||    // push imm8 (CRT init)
                    (ep[0] == 0x83) ||    // sub/add/cmp reg, imm8 (normal prologue)
                    (ep[0] == 0x53) ||    // push ebx
                    (ep[0] == 0x56) ||    // push esi
                    (ep[0] == 0x57) ||    // push edi
                    (ep[0] == 0xCC))      // int3 padding
                    break; // Normal ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â no anomaly

                // E8 at EP ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â CALL rel32. Check if cross-section or CALL $+5
                if (ep[0] == 0xE8) {
                    qint32 callDelta = *reinterpret_cast<const qint32*>(ep + 1);
                    if (callDelta == 0) {
                        // CALL $+5 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â virus (will be caught below)
                    } else {
                        quint32 callTarget = epRva + 5 + quint32(callDelta);
                        // Check if CALL stays in same section (normal CRT)
                        if (callTarget >= sec[i].VirtualAddress &&
                            callTarget < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
                            break; // Same-section CALL = normal CRT startup
                        }
                        // Cross-section CALL ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â suspicious, fall through to be caught
                        score += 35;
                        info.reason += QStringLiteral("EP anomaly: cross-section CALL at entry; ");
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                        if (info.entryPointPatch.isEmpty())
                            info.entryPointPatch = "";
                    }
                }
            } else {
                if ((ep[0] == 0x48 && ep[1] == 0x89) ||
                    (ep[0] == 0x48 && ep[1] == 0x83 && ep[2] == 0xEC) ||
                    (ep[0] == 0x40 && (ep[1] >= 0x50 && ep[1] <= 0x57)) ||
                    (ep[0] == 0x48 && ep[1] == 0x8D) ||
                    (ep[0] == 0x48 && ep[1] == 0x8B) ||
                    (ep[0] == 0xCC) ||
                    (ep[0] == 0x4C))      // mov r8-r15, ... (x64 CRT)
                    break; // Normal x64 prologue
            }

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ E9 (JMP rel32) at EP ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â could be normal or malicious ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            // Normal: MSVC /INCREMENTAL linking creates JMP thunks that land
            //         in the SAME .text section. This is harmless.
            // Malicious: Virus hooks EP with JMP that lands in LAST section
            //            or an appended section with RWX flags.
            if (ep[0] == 0xE9) {
                qint32 jmpDelta = *reinterpret_cast<const qint32*>(ep + 1);
                quint32 jmpTargetRva = epRva + 5 + quint32(jmpDelta);

                // Find which section the JMP target lands in
                int targetSectionIdx = -1;
                for (int s = 0; s < numSections; ++s) {
                    if (jmpTargetRva >= sec[s].VirtualAddress &&
                        jmpTargetRva < sec[s].VirtualAddress + sec[s].Misc.VirtualSize) {
                        targetSectionIdx = s;
                        break;
                    }
                }

                // Suspicious if JMP goes to ANY different section (not just last)
                if (targetSectionIdx >= 0 && targetSectionIdx != i) {
                    int tNL = 0;
                    while (tNL < 8 && sec[targetSectionIdx].Name[tNL] != '\0') tNL++;
                    QString tgtName = QString::fromLatin1(reinterpret_cast<const char*>(sec[targetSectionIdx].Name), tNL).toLower();
                    
                    if (!isKnownPackerSection(tgtName)) {
                        DWORD targetFlags = sec[targetSectionIdx].Characteristics;
                        bool hasExec  = (targetFlags & IMAGE_SCN_MEM_EXECUTE) != 0;
                        bool hasWrite = (targetFlags & IMAGE_SCN_MEM_WRITE) != 0;

                        // Last section or RWX = high confidence
                        if (targetSectionIdx == numSections - 1 && (hasExec || hasWrite)) {
                            score += 45;
                            info.reason += QStringLiteral("EP JMP to suspicious last section '%1' (appended code); ").arg(tgtName);
                        } else if (hasExec && hasWrite) {
                            score += 40;
                            info.reason += QStringLiteral("EP JMP to RWX section '%1'; ").arg(tgtName);
                        } else if (!isStandardSection(tgtName)) {
                            score += 35;
                            info.reason += QStringLiteral("EP JMP to non-standard section '%1'; ").arg(tgtName);
                        }
                        // Also check if target looks like virus stub
                        qint64 tgtOff = qint64(sec[targetSectionIdx].PointerToRawData) +
                                        qint64(jmpTargetRva - sec[targetSectionIdx].VirtualAddress);
                        if (tgtOff >= 0 && tgtOff + 6 < mapSize) {
                            const uchar *tgt = base + tgtOff;
                            if ((tgt[0] == 0x60) || // PUSHAD
                                (tgt[0] == 0xE8 && tgt[1] == 0x00 && tgt[2] == 0x00 &&
                                 tgt[3] == 0x00 && tgt[4] == 0x00) || // CALL $+5
                                (tgt[0] == 0x9C)) // PUSHFD
                            {
                                score += 20;
                                info.reason += QStringLiteral("Target has virus stub (PUSHAD/CALL $+5); ");
                            }
                        }
                        if (info.repairable && info.entryPointPatch.isEmpty())
                            info.entryPointPatch = "";
                    }
                }
                // If JMP stays in same section ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â check for code cave
                if (targetSectionIdx == i) {
                    quint32 offInSec = jmpTargetRva - sec[i].VirtualAddress;
                    if (sec[i].Misc.VirtualSize > 0 && offInSec >= sec[i].Misc.VirtualSize) {
                        score += 40;
                        info.reason += QStringLiteral("EP JMP to code cave (beyond VirtualSize in same section); ");
                        if (info.repairable && info.entryPointPatch.isEmpty())
                            info.entryPointPatch = "";
                    }
                }
                break;
            }

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ EB (JMP short) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â only suspicious if EP is in last section ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            if (ep[0] == 0xEB && i == numSections - 1) {
                score += 25;
                info.reason += QStringLiteral("EP anomaly: short JMP at entry in last section; ");
                break;
            }

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ FF 25 (indirect JMP) or 68+C3 (PUSH+RET) at EP ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â always suspicious ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            if ((ep[0] == 0xFF && ep[1] == 0x25) ||
                (ep[0] == 0x68 && ep[5] == 0xC3))
            {
                score += 30;
                info.reason += QStringLiteral("EP anomaly: indirect redirect (FF25/PUSH+RET) at entry; ");
                if (info.repairable && info.entryPointPatch.isEmpty())
                    info.entryPointPatch = "";
            }

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ E8 00 00 00 00 (CALL $+5) at EP ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â definitive virus indicator ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            if (ep[0] == 0xE8 && ep[1] == 0x00 && ep[2] == 0x00 &&
                ep[3] == 0x00 && ep[4] == 0x00) {
                score += 50;
                info.reason += QStringLiteral("EP anomaly: CALL $+5 delta-offset technique; ");
                info.repairable = true;
                info.repairMethod = "PE.SectionWipe+EP.Restore";
                if (info.entryPointPatch.isEmpty())
                    info.entryPointPatch = "";
            }

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ 60 (PUSHAD) or 9C (PUSHFD) at EP ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â virus save-all-registers technique ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            if (ep[0] == 0x60) {
                score += 45;
                info.reason += QStringLiteral("EP anomaly: PUSHAD at entry (virus save-registers); ");
                info.repairable = true;
                info.repairMethod = "PE.SectionWipe+EP.Restore";
                if (info.entryPointPatch.isEmpty())
                    info.entryPointPatch = "";
            }
            if (ep[0] == 0x9C) {
                score += 40;
                info.reason += QStringLiteral("EP anomaly: PUSHFD at entry (virus save-flags); ");
                info.repairable = true;
                info.repairMethod = "PE.SectionWipe+EP.Restore";
                if (info.entryPointPatch.isEmpty())
                    info.entryPointPatch = "";
            }
            break;
        }
    }
    return score;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Code cave injection detection
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
int Scanner::detectCodeCaveInjection(const uchar *base, qint64 mapSize,
                                      const void *secHdrV, int numSections, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    for (int i = 0; i < numSections; ++i) {
        const DWORD ch = sec[i].Characteristics;
        if (!(ch & IMAGE_SCN_MEM_EXECUTE)) continue; // only scan executable sections

        const qint64 rawOff = sec[i].PointerToRawData;
        const qint64 rawSz  = sec[i].SizeOfRawData;
        const qint64 virtSz = sec[i].Misc.VirtualSize;
        if (rawOff <= 0 || rawSz <= 0 || rawOff + rawSz > mapSize) continue;

        // Code cave = gap between VirtualSize and SizeOfRawData that contains
        // executable code (not all zeros/NOPs/INT3s)
        if (virtSz > 0 && rawSz > virtSz) {
            const qint64 caveOff = rawOff + virtSz;
            const qint64 caveSz  = rawSz - virtSz;
            if (caveSz > 32 && caveOff + caveSz <= mapSize) {
                // Check if the cave has non-trivial content
                int nonZero = 0;
                const qint64 checkSz = qMin(caveSz, qint64(4096));
                for (qint64 j = 0; j < checkSz; ++j) {
                    uchar b = base[caveOff + j];
                    if (b != 0x00 && b != 0xCC && b != 0x90) ++nonZero;
                }
                if (nonZero > int(checkSz * 0.5)) {
                    // High ratio of non-trivial bytes in the cave
                    const double H = shannonEntropy(base + caveOff, checkSz);
                    if (H > 6.5) {
                        score += 15;
                        int nameLen = 0;
                        while (nameLen < 8 && sec[i].Name[nameLen] != '\0') nameLen++;
                        QString nm = QString::fromLatin1(reinterpret_cast<const char*>(sec[i].Name), nameLen);
                        info.reason += QStringLiteral("Code cave injection in section %1 (H=%2, %3 active bytes); ")
                                           .arg(nm).arg(H, 0, 'f', 2).arg(nonZero);
                    }
                }
            }
        }
    }
    return score;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Overlay payload detection
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
int Scanner::detectOverlayPayload(qint64 fileSize, qint64 maxSectionEnd,
                                    quint32 sizeOfImage, ThreatInfo &info)
{
    if (maxSectionEnd <= 0) return 0;
    qint64 overlaySize = fileSize - maxSectionEnd;
    if (overlaySize > qint64(sizeOfImage) && overlaySize > 4096) {
        int score = 20;
        info.reason += QStringLiteral("Suspicious overlay (%1 KB beyond PE image); ")
                           .arg(overlaySize / 1024);
        return score;
    }
    return 0;
}

int Scanner::detectByteSignatures(const uchar *base, qint64 mapSize, quint32 epRva, const void *secHdrV, int numSections, ThreatInfo &info)
{
    int score = 0;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);
    qint64 epFileOff = -1;

    for (int i = 0; i < numSections; ++i) {
        if (epRva >= sec[i].VirtualAddress &&
            epRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            epFileOff = qint64(sec[i].PointerToRawData) + qint64(epRva - sec[i].VirtualAddress);
            break;
        }
    }

    // Helper lambda: parse a hex pattern string (with ?? wildcards) into bytes + mask
    auto parsePattern = [](const QString &pat, QByteArray &outBytes, QByteArray &outMask) {
        outBytes.clear();
        outMask.clear();
        // Remove ALL spaces and whitespace from the pattern
        QString upper;
        for (const QChar &c : pat) {
            if (!c.isSpace()) upper += c.toUpper();
        }
        for (int i = 0; i + 1 < upper.length(); i += 2) {
            const QChar c0 = upper[i], c1 = upper[i+1];
            if (c0 == '?' && c1 == '?') {
                outBytes.append(char(0));
                outMask.append(char(0)); // 0 = wildcard, don't compare
            } else {
                bool ok = false;
                const uchar val = uchar(upper.mid(i, 2).toUInt(&ok, 16));
                outBytes.append(char(val));
                outMask.append(ok ? char(1) : char(0)); // 1 = must match
            }
        }
    };

    for (const auto &bs : m_byteSignatures) {
        QByteArray patBytes, patMask;
        parsePattern(bs.pattern, patBytes, patMask);
        const int patLen = patBytes.size();
        if (patLen < 2) continue;

        // Count FIXED (non-wildcard) bytes Ã¢â‚¬â€ this determines matching specificity
        int fixedCount = 0;
        for (int j = 0; j < patLen; ++j) {
            if (patMask[j]) fixedCount++;
        }
        if (fixedCount < 4) continue; // Too few fixed bytes = unreliable

        // Helper: try matching at a specific offset
        auto matchAt = [&](qint64 off) -> bool {
            if (off < 0 || off + patLen > mapSize) return false;
            for (int j = 0; j < patLen; ++j) {
                if (patMask[j] && base[off + j] != uchar(patBytes[j]))
                    return false;
            }
            return true;
        };

        // Strategy: EP-first, then global only if very specific
        bool matched = false;
        qint64 matchOff = -1;
        int matchSection = -1;

        // 1. Always try matching at EP first (most reliable)
        if (epFileOff >= 0 && matchAt(epFileOff)) {
            matched = true;
            matchOff = epFileOff;
            matchSection = -1; // EP
        }

        // 2. Global scan ONLY if 8+ fixed bytes (very specific)
        if (!matched && fixedCount >= 8) {
            for (int si = 0; si < numSections && !matched; ++si) {
                qint64 rawOff = sec[si].PointerToRawData;
                qint64 rawSz  = sec[si].SizeOfRawData;
                if (rawOff <= 0 || rawSz <= 0 || rawOff + rawSz > mapSize) continue;

                qint64 scanEnd = qMin(rawOff + rawSz, mapSize);
                for (qint64 off = rawOff; off + patLen <= scanEnd; ++off) {
                    if (matchAt(off)) {
                        matched = true;
                        matchOff = off;
                        matchSection = si;
                        break;
                    }
                }
            }
        }

        if (matched) {
            score += 100;
            info.detectionName = bs.name;
            info.family = bs.family;
            info.severity = bs.severity;
            info.repairable = bs.repairable;
            info.repairMethod = bs.repairMethod;
            info.entryPointPatch = bs.entryPatch;
            if (matchSection < 0) {
                info.reason = QStringLiteral("Byte signature at EP: %1").arg(bs.name);
            } else {
                info.reason = QStringLiteral("Byte signature '%1' in section %2 at 0x%3")
                                  .arg(bs.name).arg(matchSection).arg(matchOff, 0, 16);
            }
            return score;
        }
    }
    return score;
}
#endif // _WIN32

int Scanner::peHeuristics(const QString &path, ThreatInfo &info)
{
    int score = 0;
    QStringList notes;

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return 0;
    if (f.size() < 64) return 0;

    const qint64 fileSize = f.size();
    const qint64 mapSize  = qMin<qint64>(fileSize, 8LL * 1024 * 1024);
    uchar *base = f.map(0, mapSize);
    if (!base) { f.close(); return 0; }

#ifdef _WIN32
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        f.unmap(base); f.close(); return 0;
    }
    if (dos->e_lfanew <= 0 || dos->e_lfanew + qint64(sizeof(IMAGE_NT_HEADERS32)) > mapSize) {
        f.unmap(base); f.close(); return 0;
    }
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        f.unmap(base); f.close(); return 0;
    }

    const WORD numSections = nt->FileHeader.NumberOfSections;
    const WORD optMagic = *reinterpret_cast<const WORD*>(
        base + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    const bool is64 = (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    DWORD epRva, sizeOfImage;
    if (is64) {
        auto nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        epRva = nt64->OptionalHeader.AddressOfEntryPoint;
        sizeOfImage = nt64->OptionalHeader.SizeOfImage;
    } else {
        epRva = nt->OptionalHeader.AddressOfEntryPoint;
        sizeOfImage = nt->OptionalHeader.SizeOfImage;
    }

    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const uchar*>(nt) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        nt->FileHeader.SizeOfOptionalHeader);

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Floxif family detection ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    int floxifScore = detectFloxifFamily(base, mapSize, epRva, sec, numSections, info);
    score += floxifScore;

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Mikcer family detection ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    if (floxifScore == 0) {
        int mikcerScore = detectMikcerFamily(base, mapSize, epRva, sec, numSections, info);
        score += mikcerScore;

        // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Sality family detection ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
        if (mikcerScore == 0) {
            int salityScore = detectSalityFamily(base, mapSize, epRva, sec, numSections, info);
            score += salityScore;

            // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Virut family detection ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
            if (salityScore == 0) {
                int virutScore = detectVirutFamily(base, mapSize, epRva, sec, numSections, info);
                score += virutScore;

                // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Ramnit family detection ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
                if (virutScore == 0) {
                    int ramnitScore = detectRamnitFamily(base, mapSize, epRva, sec, numSections, info);
                    score += ramnitScore;

                    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Neshta family detection ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
                    if (ramnitScore == 0) {
                        int neshtaScore = detectNeshtaFamily(base, mapSize, epRva, sec, numSections, info);
                        score += neshtaScore;

                        // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Expiro family detection ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
                        if (neshtaScore == 0) {
                            score += detectExpiroFamily(base, mapSize, epRva, sec, numSections, info);
                        }
                    }
                }
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: IAT hook detection (additive, runs for all files) ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    {
        DWORD numDataDirs = 0;
        const IMAGE_DATA_DIRECTORY *dataDirs = nullptr;
        if (is64) {
            auto nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            numDataDirs = nt64->OptionalHeader.NumberOfRvaAndSizes;
            dataDirs    = nt64->OptionalHeader.DataDirectory;
        } else {
            numDataDirs = nt->OptionalHeader.NumberOfRvaAndSizes;
            dataDirs    = nt->OptionalHeader.DataDirectory;
        }
        score += detectIATHooks(base, mapSize, numDataDirs, dataDirs, sec, numSections, info);
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: DLL-specific detection ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    // DLLs have predictable DllMain prologues. If EP doesn't match, it's very suspicious.
    if (info.detectionName.isEmpty()) {
        const bool isDll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
        if (isDll && epRva != 0) {
            for (int i = 0; i < numSections; ++i) {
                if (epRva >= sec[i].VirtualAddress &&
                    epRva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
                {
                    qint64 epFileOff = qint64(sec[i].PointerToRawData) + qint64(epRva - sec[i].VirtualAddress);
                    if (epFileOff >= 0 && epFileOff + 8 < mapSize) {
                        const uchar *ep = base + epFileOff;

                        // Standard DllMain prologues:
                        //   8B FF 55 8B EC  (mov edi,edi; push ebp; mov ebp,esp)
                        //   55 8B EC        (push ebp; mov ebp,esp)
                        //   48 89 5C 24     (x64: mov [rsp+xx], rbx)
                        //   48 83 EC        (x64: sub rsp, imm8)
                        bool normalDll = false;
                        if (!is64) {
                            normalDll = (ep[0] == 0x8B && ep[1] == 0xFF && ep[2] == 0x55) ||
                                        (ep[0] == 0x55 && ep[1] == 0x8B && ep[2] == 0xEC) ||
                                        (ep[0] == 0x6A) ||    // push imm8 (SEH setup)
                                        (ep[0] == 0xB8) ||    // mov eax, imm32 (returns TRUE)
                                        (ep[0] == 0x83) ||    // sub/cmp
                                        (ep[0] == 0xCC);      // int3 padding
                        } else {
                            normalDll = (ep[0] == 0x48 && ep[1] == 0x89) ||
                                        (ep[0] == 0x48 && ep[1] == 0x83) ||
                                        (ep[0] == 0x40) ||
                                        (ep[0] == 0x4C) ||
                                        (ep[0] == 0xCC);
                        }

                        if (!normalDll) {
                            // DLL EP doesn't match known prologues ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â suspicious
                            int dllScore = 0;
                            if (ep[0] == 0xE9) {
                                dllScore = 55; // JMP at DLL EP = very suspicious
                                info.reason += QStringLiteral("DLL EP starts with JMP (E9) instead of DllMain prologue; ");
                            } else if (ep[0] == 0xE8 && ep[1] == 0x00 && ep[2] == 0x00 &&
                                       ep[3] == 0x00 && ep[4] == 0x00) {
                                dllScore = 65; // CALL $+5 at DLL EP = very suspicious
                                info.reason += QStringLiteral("DLL EP starts with CALL $+5 (delta-offset technique); ");
                            } else if (ep[0] == 0x60) {
                                dllScore = 60; // PUSHAD at DLL EP = very suspicious
                                info.reason += QStringLiteral("DLL EP starts with PUSHAD; ");
                            } else if (ep[0] == 0xEB) {
                                dllScore = 50; // Short JMP
                                info.reason += QStringLiteral("DLL EP starts with short JMP (EB); ");
                            } else if (ep[0] == 0x68 && ep[5] == 0xC3) {
                                dllScore = 60; // PUSH+RET
                                info.reason += QStringLiteral("DLL EP uses PUSH+RET redirect; ");
                            } else if (ep[0] == 0xFF && ep[1] == 0x25) {
                                dllScore = 50; // Indirect JMP
                                info.reason += QStringLiteral("DLL EP uses indirect JMP (FF 25); ");
                            }

                            if (dllScore > 0) {
                                score += dllScore;
                                if (info.detectionName.isEmpty()) {
                                    info.detectionName = QStringLiteral("Virus:Win32/Floxif.H!DLL");
                                    info.family = "Floxif";
                                    info.severity = 10;
                                    info.repairable = true;
                                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                                    info.entryPointPatch = "";  // auto-detect DLL/EXE
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Entry point anomaly ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    if (info.detectionName.isEmpty()) {
        score += detectEntryPointAnomaly(base, mapSize, epRva, sec, numSections, is64, info);
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Smart Byte Signature Matching ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    // Evaluates short patterns at the EP, and long patterns globally
    if (info.detectionName.isEmpty()) {
        int bsScore = detectByteSignatures(base, mapSize, epRva, sec, numSections, info);
        if (bsScore > 0) {
            score = 100;
            f.unmap(base);
            f.close();
            return score;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Deep In-Section Virus Body Scan ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    // Scans executable sections for virus body patterns ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â catches infections
    // where EP looks normal but virus code is INSIDE .text or appended sections
    if (info.detectionName.isEmpty() || score < 50) {
        for (int si = 0; si < numSections; ++si) {
            const DWORD ch = sec[si].Characteristics;
            if (!(ch & IMAGE_SCN_MEM_EXECUTE)) continue;  // only scan executable sections

            const qint64 rawOff = sec[si].PointerToRawData;
            const qint64 rawSz  = sec[si].SizeOfRawData;
            if (rawOff <= 0 || rawSz <= 0 || rawOff + rawSz > mapSize) continue;

            int nameLen = 0;
            while (nameLen < 8 && sec[si].Name[nameLen] != '\0') nameLen++;
            QString secName = QString::fromLatin1(
                reinterpret_cast<const char*>(sec[si].Name), nameLen).toLower();

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Check 1: .text with WRITE flag = modified by virus ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            if ((secName == ".text" || secName == ".code") &&
                (ch & IMAGE_SCN_MEM_WRITE) != 0) {
                score += 30;
                notes << QStringLiteral("Section %1 has suspicious WRITE flag (normally read-only)").arg(secName);
            }

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Check 2: Scan section body for virus stub patterns ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            // Focus on the END of the section (where viruses append code)
            // and the area around code caves
            const qint64 scanStart = rawOff;
            const qint64 scanLimit = qMin(rawSz, qint64(512 * 1024)); // limit to 512KB

            // Scan for virus body signatures: PUSHAD; CALL $+5; POP reg; SUB reg,X
            // This is the universal "delta-offset" technique used by ALL file infectors
            for (qint64 off = scanStart; off + 12 <= scanStart + scanLimit; ++off) {
                const uchar *p = base + off;

                // Pattern 1: 60 E8 00 00 00 00 5x (PUSHAD; CALL $+5; POP reg)
                if (p[0] == 0x60 && p[1] == 0xE8 && p[2] == 0x00 &&
                    p[3] == 0x00 && p[4] == 0x00 && p[5] == 0x00 &&
                    (p[6] >= 0x58 && p[6] <= 0x5F)) { // POP reg
                    score += 55;
                    if (info.detectionName.isEmpty()) {
                        info.detectionName = QStringLiteral("Virus:Win32/Floxif.gen!Body");
                        info.family = "Floxif";
                        info.severity = 10;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                    }
                    info.reason += QStringLiteral("Virus body found in section %1 at +0x%2 (PUSHAD+CALL$+5+POP); ")
                                       .arg(secName).arg(off - rawOff, 0, 16);
                    goto bodyDone;
                }

                // Pattern 2: E8 00 00 00 00 5x 81 Ex (CALL $+5; POP reg; SUB/ADD reg, imm32)
                if (p[0] == 0xE8 && p[1] == 0x00 && p[2] == 0x00 &&
                    p[3] == 0x00 && p[4] == 0x00 &&
                    (p[5] >= 0x58 && p[5] <= 0x5F) &&
                    (p[6] == 0x81 || p[6] == 0x2D || p[6] == 0x05)) {
                    // Skip if this is within the first 32 bytes of EP (already detected)
                    qint64 epOff = -1;
                    for (int e = 0; e < numSections; ++e) {
                        if (epRva >= sec[e].VirtualAddress &&
                            epRva < sec[e].VirtualAddress + sec[e].Misc.VirtualSize) {
                            epOff = qint64(sec[e].PointerToRawData) + qint64(epRva - sec[e].VirtualAddress);
                            break;
                        }
                    }
                    if (epOff < 0 || off < epOff || off > epOff + 32) {
                        score += 50;
                        if (info.detectionName.isEmpty()) {
                            info.detectionName = QStringLiteral("Virus:Win32/Floxif.gen!Delta");
                            info.family = "Floxif";
                            info.severity = 10;
                            info.repairable = true;
                            info.repairMethod = "PE.SectionWipe+EP.Restore";
                        }
                        info.reason += QStringLiteral("Virus delta-offset code in %1 at +0x%2; ")
                                           .arg(secName).arg(off - rawOff, 0, 16);
                        goto bodyDone;
                    }
                }

                // Pattern 3: 9C 60 (PUSHFD; PUSHAD) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Sality/Virut signature
                if (p[0] == 0x9C && p[1] == 0x60) {
                    // Verify it's not just random data by checking for more virus patterns nearby
                    bool hasFollowUp = false;
                    for (int k = 2; k < 20 && off + k + 5 <= scanStart + scanLimit; ++k) {
                        if (p[k] == 0xE8 && p[k+1] == 0x00 && p[k+2] == 0x00 &&
                            p[k+3] == 0x00 && p[k+4] == 0x00) {
                            hasFollowUp = true;
                            break;
                        }
                    }
                    if (hasFollowUp) {
                        score += 50;
                        if (info.detectionName.isEmpty()) {
                            info.detectionName = QStringLiteral("Virus:Win32/Generic.Infector!Body");
                            info.family = "Infector";
                            info.severity = 9;
                            info.repairable = true;
                            info.repairMethod = "PE.SectionWipe+EP.Restore";
                        }
                        info.reason += QStringLiteral("PUSHFD+PUSHAD+CALL$+5 virus body in %1 at +0x%2; ")
                                           .arg(secName).arg(off - rawOff, 0, 16);
                        goto bodyDone;
                    }
                }
            }

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Check 3: Scan for virus API strings in executable sections ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            // Real viruses resolve APIs dynamically ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â these strings inside .text are suspicious
            {
                // Infector APIs
                static const char *virusApis[] = {
                    "GetProcAddress",
                    "LoadLibraryA",
                    "VirtualProtect",
                    "VirtualAlloc",
                    "CreateFileA",
                    "WriteFile",
                    "WinExec",
                    "CreateProcessA",
                    "ShellExecuteA",
                    nullptr
                };
                // Downloader APIs (TrojanDownloader indicator)
                static const char *downloaderApis[] = {
                    "URLDownloadToFileA",
                    "URLDownloadToFileW",
                    "InternetOpenA",
                    "InternetOpenUrlA",
                    "InternetReadFile",
                    "HttpOpenRequestA",
                    "HttpSendRequestA",
                    "urlmon.dll",
                    "wininet.dll",
                    nullptr
                };

                int apiHits = 0;
                bool hasDownloader = false;
                const qint64 strLimit = qMin(rawSz, qint64(256 * 1024));

                for (const char **api = virusApis; *api; ++api) {
                    const int apiLen = int(strlen(*api));
                    for (qint64 off = rawOff; off + apiLen <= rawOff + strLimit; ++off) {
                        if (memcmp(base + off, *api, apiLen) == 0) {
                            apiHits++;
                            break; // found this API, move to next
                        }
                    }
                }

                for (const char **api = downloaderApis; *api; ++api) {
                    const int apiLen = int(strlen(*api));
                    for (qint64 off = rawOff; off + apiLen <= rawOff + strLimit; ++off) {
                        if (memcmp(base + off, *api, apiLen) == 0) {
                            apiHits++;
                            hasDownloader = true;
                            break;
                        }
                    }
                }

                // Multiple virus APIs in executable section = strong indicator
                if (apiHits >= 3) {
                    score += 35;
                    if (hasDownloader && info.detectionName.isEmpty()) {
                        info.detectionName = QStringLiteral("TrojanDownloader:Win32/Generic!Embedded");
                        info.family = "Downloader";
                        info.severity = 9;
                        info.repairable = true;
                        info.repairMethod = "PE.SectionWipe+EP.Restore";
                    }
                    info.reason += QStringLiteral("%1 virus/downloader APIs in executable section %2; ")
                                       .arg(apiHits).arg(secName);
                    goto bodyDone;
                } else if (apiHits >= 2) {
                    score += 20;
                    info.reason += QStringLiteral("%1 suspicious APIs in %2; ").arg(apiHits).arg(secName);
                }
            }

            // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Check 4: Data appended AFTER VirtualSize in executable section ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
            if (sec[si].Misc.VirtualSize > 0 && rawSz > qint64(sec[si].Misc.VirtualSize) + 256) {
                // There's significant data beyond VirtualSize ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â could be virus code cave
                qint64 caveOff = rawOff + sec[si].Misc.VirtualSize;
                qint64 caveLen = rawSz - sec[si].Misc.VirtualSize;
                if (caveLen > 64 && caveOff + caveLen <= mapSize) {
                    // Check if cave has non-trivial content
                    int nonZero = 0;
                    qint64 checkLen = qMin(caveLen, qint64(4096));
                    for (qint64 j = 0; j < checkLen; ++j) {
                        uchar b = base[caveOff + j];
                        if (b != 0x00 && b != 0xCC && b != 0x90) ++nonZero;
                    }
                    if (nonZero > int(checkLen * 0.4)) {
                        score += 25;
                        info.reason += QStringLiteral("Active code cave in %1 (%2 bytes beyond VirtualSize, %3 active); ")
                                           .arg(secName).arg(caveLen).arg(nonZero);
                    }
                }
            }
        }
        bodyDone:;
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: PE Checksum Mismatch ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    // If the PE checksum is wrong, the file was modified post-compilation (infection indicator)
    if (info.detectionName.isEmpty()) {
        DWORD storedChecksum = 0;
        if (is64) {
            storedChecksum = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew)->OptionalHeader.CheckSum;
        } else {
            storedChecksum = nt->OptionalHeader.CheckSum;
        }
        if (storedChecksum != 0) {
            // Recompute checksum
            quint64 sum = 0;
            const quint16 *w = reinterpret_cast<const quint16*>(base);
            const qint64 words = mapSize / 2;
            for (qint64 ci = 0; ci < words; ++ci) {
                sum += w[ci];
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            sum = (sum & 0xFFFF) + (sum >> 16);
            DWORD computed = DWORD(sum) + DWORD(mapSize);
            if (computed != storedChecksum && score > 0) {
                score += 10;
                notes << QStringLiteral("PE checksum mismatch (stored=0x%1, computed=0x%2) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â file modified post-compilation")
                          .arg(storedChecksum, 8, 16, QChar('0')).arg(computed, 8, 16, QChar('0'));
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Code cave injection ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    score += detectCodeCaveInjection(base, mapSize, sec, numSections, info);

    int idxOfEp = -1;
    qint64 maxSectionEnd = 0;
    for (int i = 0; i < numSections; ++i) {
        const auto &s = sec[i];
        int nameLen = 0;
        while (nameLen < 8 && s.Name[nameLen] != '\0') nameLen++;
        const QByteArray name(reinterpret_cast<const char*>(s.Name), nameLen);
        const QString nm = QString::fromLatin1(name).toLower();

        // a) Named-infector sections (true file-infector families) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Verax
        // can DISINFECT these by zeroing the section + clearing its name.
        static const char *infectorSections[] = {
            ".flx", ".floxif",
            ".sality", ".sal",
            ".virut",  ".vrt",
            ".rmnet",  ".ramnit",
            ".parite",
            ".expiro",
            ".polip",
            ".mabezat",
            ".tenga",
            ".lamer",
            ".jeefo",
            ".hidrag",
            ".mydoom",
            ".bagle",
            ".neshta",
            ".viking",
            ".alman",
            ".induc",
            ".vetor",
            ".mikcer", ".mkc"
        };
        // Commercial packers ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â suspicious but NOT repairable. Verax flags
        // them as Heuristic.Suspect and the user can decide.
        static const char *packerSections[] = {
            ".aspack", ".upx0", ".upx1", ".mpress1", ".mpress2",
            ".themida", ".vmp0", ".vmp1", ".vmp2", ".pec", ".petite"
        };
        bool sectionMatched = false;
        for (auto *bad : infectorSections) {
            if (nm == QString::fromLatin1(bad)) {
                score += 60;
                notes << QStringLiteral("Malicious file-infector segment: %1").arg(nm);
                // Family = section name without the leading dot, upper-cased.
                const QString famName = nm.mid(1).toUpper();
                if (info.detectionName.isEmpty()) {
                    info.detectionName = QStringLiteral("Win32.Infector.") + famName;
                    info.family   = famName;
                    info.severity = 9;
                    info.repairable = true;
                    info.repairMethod = "PE.SectionWipe+EP.Restore";
                    // Try to get EP patch from DB
                    SigHit dbHit = SignatureDb::instance().lookupByFamily(famName);
                    if (!dbHit.entryPointPatch.isEmpty())
                        info.entryPointPatch = dbHit.entryPointPatch;
                    else
                        info.entryPointPatch = "";
                }
                sectionMatched = true;
                break;
            }
        }
        if (!sectionMatched) {
            for (auto *bad : packerSections) {
                if (nm == QString::fromLatin1(bad)) {
                    score += 35;
                    notes << QStringLiteral("Packed by %1 (commercial packer)").arg(nm.mid(1));
                    // Packers are NOT viruses ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â don't set repairable or detection name
                    // Only flag as suspicious
                    break;
                }
            }
        }

        // b) Entry-point tracking
        if (epRva >= s.VirtualAddress && epRva < s.VirtualAddress + s.Misc.VirtualSize) {
            idxOfEp = i;
        }

        // c) Executable + Writable (RWX) section ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â classic shellcode / unpacking stub
        const DWORD ch = s.Characteristics;
        const bool exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool write = (ch & IMAGE_SCN_MEM_WRITE)   != 0;
        if (exec && write) {
            score += 10;
            notes << QStringLiteral("Section %1 has executable+writable (RWX) flags").arg(nm);
        }

        // d) Per-section entropy ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â packed/encrypted code sits at ~7.5ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“8.0 bits/byte
        const qint64 secOff = s.PointerToRawData;
        const qint64 secSz  = qMin<qint64>(s.SizeOfRawData, 256 * 1024); // sample
        if (secOff > 0 && secSz > 4096 && secOff + secSz <= mapSize) {
            const double H = shannonEntropy(base + secOff, secSz);
            if (H > 7.5 && exec) {
                score += 15;
                notes << QStringLiteral("High entropy executable section %1 (H=%2)")
                            .arg(nm).arg(H, 0, 'f', 2);
            }
        }

        const qint64 endOff = qint64(s.PointerToRawData) + qint64(s.SizeOfRawData);
        if (endOff > maxSectionEnd) maxSectionEnd = endOff;
    }

    if (idxOfEp == numSections - 1 && numSections > 1 && score < 60) {
        score += 20;
        notes << QStringLiteral("Entry point inside last section (post-unpacker stub)");
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â ADVANCED: Overlay detection ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    score += detectOverlayPayload(fileSize, maxSectionEnd, sizeOfImage, info);

    // e) Overlay larger than image ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â installer-trojans / droppers (legacy)
    if (maxSectionEnd > 0 && fileSize - maxSectionEnd > qint64(sizeOfImage)) {
        if (!info.reason.contains("overlay")) {
            score += 15;
            notes << QStringLiteral("Large overlay (%1 KB) trailing the PE image")
                        .arg((fileSize - maxSectionEnd) / 1024);
        }
    }

    // f) Suspicious imports
    static const char *injectionTrio[] = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"
    };
    static const char *evasionApis[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "SetUnhandledExceptionFilter"
    };
    static const char *droppers[] = {
        "URLDownloadToFile", "InternetOpenUrl", "WinExec", "ShellExecute"
    };
    auto findStr = [&](const char *needle) -> bool {
        const int n = int(qstrlen(needle));
        for (qint64 i = 0; i + n < mapSize; ++i) {
            if (base[i] == uchar(needle[0]) &&
                memcmp(base + i, needle, n) == 0) return true;
        }
        return false;
    };
    int injectionHits = 0;
    for (auto *s : injectionTrio) if (findStr(s)) ++injectionHits;
    if (injectionHits >= 2) {
        score += 35 + 10 * (injectionHits - 2);
        notes << QStringLiteral("Code-injection import combination (%1/3 markers)").arg(injectionHits);
    }
    int evasionHits = 0;
    for (auto *s : evasionApis) if (findStr(s)) ++evasionHits;
    if (evasionHits >= 2) {
        score += 15;
        notes << QStringLiteral("Anti-debug / evasion API surface (%1 markers)").arg(evasionHits);
    }
    int dropperHits = 0;
    for (auto *s : droppers) if (findStr(s)) ++dropperHits;
    if (dropperHits >= 1) {
        score += 10;
        notes << QStringLiteral("Network / launch APIs (%1 markers)").arg(dropperHits);
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â Check DB for repairable status if we detected by section name ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    if (!info.family.isEmpty() && !info.repairable) {
        if (SignatureDb::instance().isFamilyRepairable(info.family)) {
            info.repairable = true;
            SigHit dbHit = SignatureDb::instance().lookupByFamily(info.family);
            if (!dbHit.repairMethod.isEmpty()) info.repairMethod = dbHit.repairMethod;
            if (!dbHit.entryPointPatch.isEmpty()) info.entryPointPatch = dbHit.entryPointPatch;
        }
    }
#endif

    f.unmap(base);
    f.close();

    if (!notes.isEmpty()) {
        if (!info.reason.isEmpty()) info.reason += "; ";
        info.reason += notes.join("; ");
    }
    return score;
}

// ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
//  Script content heuristics ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â .bat .cmd .ps1 .vbs .js .hta .wsf .sh
// ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
int Scanner::scriptHeuristics(const QString &path, ThreatInfo &info)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return 0;
    // Cap at 2 MiB ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â script malware is almost never larger; full enterprise
    // PowerShell modules can be, but they will already be hashed for SigDb.
    const QByteArray data = f.read(2 * 1024 * 1024);
    f.close();
    if (data.isEmpty()) return 0;

    QString text = QString::fromUtf8(data);

    // PowerShell often ships base64-encoded with -EncodedCommand. We try a
    // light decode so the pattern set below matches the original commands.
    static const QRegularExpression encRx(
        QStringLiteral("(?:-enc(?:odedcommand)?|FromBase64String\\s*\\()\\s*['\"]?([A-Za-z0-9+/=]{40,})['\"]?"),
        QRegularExpression::CaseInsensitiveOption);
    const auto encMatch = encRx.match(text);
    if (encMatch.hasMatch()) {
        const QByteArray decoded = QByteArray::fromBase64(encMatch.captured(1).toUtf8());
        // Many encoders use UTF-16LE; try both.
        const QString u16 = QString::fromUtf16(
            reinterpret_cast<const ushort*>(decoded.constData()),
            decoded.size() / 2);
        const QString u8 = QString::fromUtf8(decoded);
        text += "\n" + u16 + "\n" + u8;
    }

    struct Pattern { const char *rx; int weight; const char *label; };
    static const Pattern patterns[] = {
        // Download + execute (multi-stage droppers)
        { "(?i)DownloadString\\s*\\(\\s*['\"]https?://", 50, "Inline web download in script" },
        { "(?i)Net\\.WebClient\\s*\\)?\\.DownloadFile",     45, "WebClient.DownloadFile call" },
        { "(?i)Invoke-Expression\\s*\\(",                    35, "Invoke-Expression on dynamic data" },
        { "(?i)\\bIEX\\b\\s*\\(",                            35, "IEX shorthand for Invoke-Expression" },
        { "(?i)Start-BitsTransfer\\s+-Source",               30, "BITS transfer from a remote source" },
        { "(?i)bitsadmin\\s+/transfer",                      30, "bitsadmin /transfer command" },
        { "(?i)certutil\\s+-(?:decode|urlcache)",            30, "certutil abuse (decode/urlcache)" },
        { "(?i)mshta\\s+http",                               40, "mshta remote HTA execution" },
        { "(?i)regsvr32\\s+/s\\s+/u\\s+/i:http",             40, "regsvr32 /i: remote scriptlet" },

        // PowerShell stealth / bypass
        { "(?i)\\-(?:nop|noprofile)\\b.*\\-(?:w(?:indowstyle)?\\s+hidden|enc)", 30, "PowerShell hidden + encoded" },
        { "(?i)ExecutionPolicy\\s+Bypass",                    20, "ExecutionPolicy Bypass" },
        { "(?i)\\[System\\.Reflection\\.Assembly\\]::Load",   35, "Reflective .NET assembly load" },
        { "(?i)Add-MpPreference\\s+-ExclusionPath",           45, "Defender exclusion injection" },
        { "(?i)Set-MpPreference\\s+-DisableRealtimeMonitoring",55,"Defender real-time tampering" },

        // VBS / JScript droppers
        { "(?i)CreateObject\\(\\s*['\"]WScript\\.Shell['\"]\\s*\\)\\..*\\.Run", 40, "WScript.Shell.Run" },
        { "(?i)ADODB\\.Stream",                              35, "ADODB.Stream binary write" },
        { "(?i)MSXML2\\.XMLHTTP",                             25, "XMLHTTP request from script" },

        // Persistence / lateral
        { "(?i)schtasks\\s+/create",                          25, "Scheduled task creation" },
        { "(?i)reg\\s+add\\s+.*\\\\Run\\b",                  30, "Registry Run key persistence" },
        { "(?i)wmic\\s+process\\s+call\\s+create",           30, "WMI process spawn" },

        // Obfuscation tells
        { "[A-Za-z0-9+/]{200,}=",                             20, "Long base64-like blob" },
        { "(?i)char\\(\\s*\\d{2,3}\\s*\\)\\s*&\\s*char\\(",   15, "Char()&Char() string assembly" },

        // Ransomware volume shadow / recovery tampering (living-off-the-land)
        { "(?i)vssadmin(\\.exe)?\\s+delete\\s+shadows",       75, "Ransomware Shadow Copy deletion" },
        { "(?i)wmic(\\.exe)?\\s+shadowcopy\\s+delete",        75, "WMI Shadow Copy deletion" },
        { "(?i)wbadmin(\\.exe)?\\s+delete\\s+(?:catalog|systemstatebackup)", 70, "Backup catalog deletion" },
        { "(?i)bcdedit(\\.exe)?\\s+.*(?:recoveryenabled\\s+no|ignoreallfailures)", 70, "Boot recovery disabling" },
        { "(?i)cipher(\\.exe)?\\s+/w:",                       50, "Unallocated drive space wiping" },

        // Credential dumping / LSASS tampering (Mimikatz, comsvcs, procdump)
        { "(?i)sekurlsa::logonpasswords",                     85, "Mimikatz credential dumping" },
        { "(?i)lsadump::(?:sam|secrets|dcsync)",              85, "LSASS/SAM dumping pattern" },
        { "(?i)privilege::debug",                             45, "SeDebugPrivilege escalation" },
        { "(?i)comsvcs\\.dll.*MiniDump",                      80, "comsvcs.dll LSASS MiniDump abuse" },
        { "(?i)rundll32(\\.exe)?\\s+.*comsvcs.*#24",          80, "rundll32 comsvcs MiniDump export" },
        { "(?i)procdump(\\.exe)?\\s+.*lsass",                 80, "ProcDump targeting LSASS" },
        { "(?i)Invoke-Mimikatz",                              80, "PowerShell Invoke-Mimikatz" },
        { "(?i)Invoke-Shellcode",                             75, "PowerShell reflective shellcode injector" },
    };

    int score = 0;
    QStringList notes;
    for (const auto &p : patterns) {
        QRegularExpression rx(QString::fromLatin1(p.rx));
        if (rx.match(text).hasMatch()) {
            score += p.weight;
            notes << QString::fromLatin1(p.label);
        }
    }

    if (score >= 60 && info.detectionName.isEmpty()) {
        info.detectionName = QStringLiteral("Script.Heur");
        info.family = QStringLiteral("Script");
        info.severity = qMax(info.severity, 8);
    }
    if (!notes.isEmpty()) {
        if (!info.reason.isEmpty()) info.reason += "; ";
        info.reason += QStringLiteral("Script: ") + notes.join("; ");
    }
    return score;
}

// ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
//  Document heuristics ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Office Open XML macro detection.
//  .docm/.xlsm/.pptm are zip containers. We scan the central directory
//  for vbaProject.bin / oleObject*.bin entries which carry macros / OLE.
// ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
int Scanner::documentHeuristics(const QString &path, ThreatInfo &info)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return 0;
    if (f.size() < 22) { f.close(); return 0; }

    // EOCD record is the last 22 bytes if there is no zip comment. Find it
    // by scanning the last 64 KiB (zip allows up to 65535-byte comment).
    const qint64 tailLen = qMin<qint64>(f.size(), 65557);
    f.seek(f.size() - tailLen);
    const QByteArray tail = f.read(tailLen);
    int eocd = tail.lastIndexOf(QByteArray::fromHex("504b0506"));
    if (eocd < 0) { f.close(); return 0; }

    QDataStream eo(QByteArray(tail.constData() + eocd, tail.size() - eocd));
    eo.setByteOrder(QDataStream::LittleEndian);
    quint32 sig = 0; eo >> sig;
    quint16 dsk = 0, dskCD = 0, entHere = 0, entTotal = 0;
    quint32 cdSize = 0, cdOff = 0;
    eo >> dsk >> dskCD >> entHere >> entTotal >> cdSize >> cdOff;
    if (cdSize == 0 || cdOff == 0 || cdOff + cdSize > f.size()) { f.close(); return 0; }

    f.seek(cdOff);
    const QByteArray cd = f.read(cdSize);
    f.close();

    int score = 0;
    QStringList notes;
    int p = 0;
    while (p + 46 <= cd.size()) {
        if (memcmp(cd.constData() + p, "PK\x01\x02", 4) != 0) break;
        QDataStream e(QByteArray(cd.constData() + p, 46));
        e.setByteOrder(QDataStream::LittleEndian);
        quint32 hsig = 0; e >> hsig;
        quint16 vmade = 0, vneed = 0, gpb = 0, method = 0, mtime = 0, mdate = 0;
        quint32 crc = 0, compSize = 0, uncSize = 0;
        quint16 nameLen = 0, extraLen = 0, commLen = 0, dskStart = 0, intAttr = 0;
        quint32 extAttr = 0, offLocal = 0;
        e >> vmade >> vneed >> gpb >> method >> mtime >> mdate
          >> crc >> compSize >> uncSize
          >> nameLen >> extraLen >> commLen >> dskStart >> intAttr >> extAttr >> offLocal;
        if (p + 46 + nameLen > cd.size()) break;
        const QByteArray name(cd.constData() + p + 46, nameLen);
        const QString nm = QString::fromUtf8(name).toLower();

        if (nm.endsWith(QLatin1String("vbaproject.bin"))) {
            score += 50;
            notes << QStringLiteral("Contains VBA macro project (vbaProject.bin)");
        }
        if (nm.contains(QLatin1String("oleobject")) && nm.endsWith(QLatin1String(".bin"))) {
            score += 25;
            notes << QStringLiteral("Embedded OLE object: %1").arg(nm);
        }
        if (nm.endsWith(QLatin1String(".dll")) || nm.endsWith(QLatin1String(".exe"))) {
            score += 60;
            notes << QStringLiteral("Document carries an executable: %1").arg(nm);
        }
        p += 46 + nameLen + extraLen + commLen;
    }

    if (score >= 50 && info.detectionName.isEmpty()) {
        info.detectionName = QStringLiteral("Document.Macro");
        info.family = QStringLiteral("Office");
        info.severity = qMax(info.severity, 7);
    }
    if (!notes.isEmpty()) {
        if (!info.reason.isEmpty()) info.reason += "; ";
        info.reason += QStringLiteral("Document: ") + notes.join("; ");
    }
    return score;
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
//  Archive heuristics Ã¢â‚¬â€ quickly walk the ZIP central directory and
//  flag suspicious entry combinations (executable inside an archive
//  named like a document, etc.).
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
int Scanner::archiveHeuristics(const QString &path, ThreatInfo &info)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return 0;
    if (f.size() < 22) { f.close(); return 0; }

    const qint64 tailLen = qMin<qint64>(f.size(), 65557);
    f.seek(f.size() - tailLen);
    const QByteArray tail = f.read(tailLen);
    int eocd = tail.lastIndexOf(QByteArray::fromHex("504b0506"));
    if (eocd < 0) { f.close(); return 0; }

    QDataStream eo(QByteArray(tail.constData() + eocd, tail.size() - eocd));
    eo.setByteOrder(QDataStream::LittleEndian);
    quint32 sig = 0; eo >> sig;
    quint16 dsk = 0, dskCD = 0, entHere = 0, entTotal = 0;
    quint32 cdSize = 0, cdOff = 0;
    eo >> dsk >> dskCD >> entHere >> entTotal >> cdSize >> cdOff;
    if (cdSize == 0 || cdOff == 0 || cdOff + cdSize > f.size()) { f.close(); return 0; }

    f.seek(cdOff);
    const QByteArray cd = f.read(cdSize);
    f.close();

    int score = 0;
    QStringList notes;
    int execs = 0, scripts = 0, lnk = 0, dbl = 0;
    int p = 0;
    while (p + 46 <= cd.size()) {
        if (memcmp(cd.constData() + p, "PK\x01\x02", 4) != 0) break;
        QDataStream e(QByteArray(cd.constData() + p, 46));
        e.setByteOrder(QDataStream::LittleEndian);
        quint32 hsig = 0; e >> hsig;
        quint16 vmade=0,vneed=0,gpb=0,method=0,mtime=0,mdate=0;
        quint32 crc=0,compSize=0,uncSize=0;
        quint16 nameLen=0,extraLen=0,commLen=0,dskStart=0,intAttr=0;
        quint32 extAttr=0,offLocal=0;
        e >> vmade >> vneed >> gpb >> method >> mtime >> mdate
          >> crc >> compSize >> uncSize
          >> nameLen >> extraLen >> commLen >> dskStart >> intAttr >> extAttr >> offLocal;
        if (p + 46 + nameLen > cd.size()) break;
        const QString nm = QString::fromUtf8(
            QByteArray(cd.constData() + p + 46, nameLen)).toLower();

        if (nm.endsWith(QLatin1String(".exe")) || nm.endsWith(QLatin1String(".dll")) ||
            nm.endsWith(QLatin1String(".scr")) || nm.endsWith(QLatin1String(".com")) ||
            nm.endsWith(QLatin1String(".pif"))) ++execs;
        if (nm.endsWith(QLatin1String(".bat")) || nm.endsWith(QLatin1String(".cmd")) ||
            nm.endsWith(QLatin1String(".vbs")) || nm.endsWith(QLatin1String(".js"))  ||
            nm.endsWith(QLatin1String(".ps1")) || nm.endsWith(QLatin1String(".hta"))) ++scripts;
        if (nm.endsWith(QLatin1String(".lnk"))) ++lnk;

        static const QRegularExpression dblRx(
            QStringLiteral("\\.(pdf|docx?|xlsx?|jpg|png|txt)\\.(exe|scr|cmd|bat|com|pif|vbs|js)$"));
        if (dblRx.match(nm).hasMatch()) ++dbl;

        p += 46 + nameLen + extraLen + commLen;
    }

    if (dbl > 0) {
        score += 50;
        notes << QStringLiteral("Archive carries %1 double-extension entry/entries").arg(dbl);
    }
    if (execs > 0 && lnk > 0) {
        score += 35;
        notes << QStringLiteral("Archive bundles .lnk + .exe (classic spear-phish payload)");
    }
    if (execs > 5) {
        score += 15;
        notes << QStringLiteral("Archive contains many executables (%1)").arg(execs);
    }
    if (scripts > 0 && execs > 0) {
        score += 20;
        notes << QStringLiteral("Archive mixes scripts (%1) and executables (%2)").arg(scripts).arg(execs);
    }

    if (!notes.isEmpty()) {
        if (!info.reason.isEmpty()) info.reason += "; ";
        info.reason += QStringLiteral("Archive: ") + notes.join("; ");
    }
    return score;
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
//  ADVANCED CLEAN THREAT ENGINE
//  Intelligently repairs infected PE files (EXE/DLL) without backup.
//  Steps: Taskkill Ã¢â€ â€™ Full permissions Ã¢â€ â€™ Map PE Ã¢â€ â€™ Wipe infector sections Ã¢â€ â€™
//  Restore EP Ã¢â€ â€™ Truncate overlay Ã¢â€ â€™ Fix checksum Ã¢â€ â€™ Verify integrity
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

bool Scanner::killProcessesUsingFile(const QString &path)
{
#ifdef _WIN32
    const QString nativePath = QDir::toNativeSeparators(path).toLower();
    const QString fileName = QFileInfo(path).fileName().toLower();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    bool killed = false;

    if (Process32FirstW(snap, &pe)) {
        do {
            const QString procName = QString::fromWCharArray(pe.szExeFile).toLower();
            if (procName == fileName) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    // Double-check by module path
                    wchar_t procPath[MAX_PATH] = {0};
                    DWORD pathLen = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProc, 0, procPath, &pathLen)) {
                        QString fullPath = QString::fromWCharArray(procPath, pathLen).toLower();
                        fullPath = QDir::toNativeSeparators(fullPath);
                        if (fullPath == nativePath) {
                            TerminateProcess(hProc, 1);
                            killed = true;
                            Logger::info(QStringLiteral("Clean Threat: Killed process PID=%1 (%2)")
                                         .arg(pe.th32ProcessID).arg(procName));
                        }
                    }
                    CloseHandle(hProc);
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (killed) {
        // Wait for the process to fully release file handles
        QThread::msleep(500);
    }
    return true;
#else
    Q_UNUSED(path);
    return true;
#endif
}

bool Scanner::setFullPermissions(const QString &path)
{
    QFile file(path);
    bool ok = file.setPermissions(
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner |
        QFileDevice::ReadUser  | QFileDevice::WriteUser  | QFileDevice::ExeUser  |
        QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup |
        QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther);
    if (!ok) {
        Logger::warn(QStringLiteral("Clean Threat: Failed to set full permissions on %1").arg(path));
    }
    return ok;
}

bool Scanner::repairEntryPoint(uchar *base, qint64 fileSize, bool is64,
                                const QString &epPatchHex, quint32 epRva,
                                const void *secHdrV, int numSections)
{
#ifdef _WIN32
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    for (int i = 0; i < numSections; ++i) {
        DWORD vsz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (epRva < sec[i].VirtualAddress || epRva >= sec[i].VirtualAddress + vsz)
            continue;

        qint64 epOff = qint64(sec[i].PointerToRawData) + qint64(epRva - sec[i].VirtualAddress);
        if (epOff < 0 || epOff + 16 > fileSize) return false;
        uchar *ep = base + epOff;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Already valid? Don't touch Ã¢â€â‚¬Ã¢â€â‚¬
        if (!is64) {
            if ((ep[0] == 0x55 && ep[1] == 0x8B && ep[2] == 0xEC) ||
                (ep[0] == 0x8B && ep[1] == 0xFF && ep[2] == 0x55) ||
                (ep[0] == 0x6A) || (ep[0] == 0x83 && ep[1] == 0xEC) ||
                (ep[0] == 0xB8) || (ep[0] == 0x55 && ep[1] == 0x89 && ep[2] == 0xE5))
                return true;
        } else {
            if ((ep[0] == 0x48 && (ep[1] == 0x89 || ep[1] == 0x83)) ||
                ep[0] == 0x40 || ep[0] == 0x4C)
                return true;
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Determine redirect length Ã¢â€â‚¬Ã¢â€â‚¬
        int rLen = 0;
        if (ep[0] == 0xE9)                      rLen = 5;
        else if (ep[0] == 0xE8)                  rLen = 5;
        else if (ep[0] == 0xEB)                  rLen = 2;
        else if (ep[0] == 0xFF && ep[1] == 0x25) rLen = 6;
        else if (ep[0] == 0x68 && ep[5] == 0xC3) rLen = 6;
        else if (ep[0] == 0x60)                  rLen = 1;
        else if (ep[0] == 0x9C)                  rLen = 1;
        else if (ep[0] == 0x00 && ep[1] == 0x00) rLen = 5;
        else return true; // Unknown opcode Ã¢â‚¬â€ leave alone

        if (rLen < 5) rLen = 5; // Minimum safe patch

        // Ã¢â€â‚¬Ã¢â€â‚¬ Detect DLL Ã¢â€â‚¬Ã¢â€â‚¬
        bool isDll = false;
        {
            auto d = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (d->e_magic == IMAGE_DOS_SIGNATURE && d->e_lfanew > 0) {
                auto fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + d->e_lfanew + sizeof(DWORD));
                isDll = (fh->Characteristics & IMAGE_FILE_DLL) != 0;
            }
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Build patch Ã¢â€â‚¬Ã¢â€â‚¬
        QByteArray patch;

        // 1. User/recovered prologue
        if (!epPatchHex.isEmpty())
            patch = QByteArray::fromHex(epPatchHex.toLatin1());

        // 2. Analyze bytes AFTER redirect to guess correct prologue
        if (patch.isEmpty() && !is64) {
            uchar a = ep[rLen]; // First byte after the redirect
            uchar b = (rLen + 1 < 16) ? ep[rLen + 1] : 0;
            uchar c = (rLen + 2 < 16) ? ep[rLen + 2] : 0;

            // DLL pattern: 83 7D 0C = cmp [ebp+0Ch], DLL_PROCESS_ATTACH
            if (a == 0x83 && b == 0x7D && c == 0x0C) {
                patch = QByteArray::fromHex("8BFF558BEC"); // DLL hotpatch
            }
            // EXE pattern: 68 ?? ?? ?? ?? = push SEH handler (after 558BEC6AFF)
            else if (a == 0x68) {
                patch = isDll ? QByteArray::fromHex("8BFF558BEC") : QByteArray::fromHex("558BEC6AFF");
            }
            // 64 A1 00 00 00 00 = mov eax,[fs:0] (SEH chain, after push -1 + push handlers)
            else if (a == 0x64) {
                patch = QByteArray::fromHex("558BEC6AFF");
            }
            // 51/53/56/57 = push ecx/ebx/esi/edi (register saves after prologue)
            else if (a == 0x51 || a == 0x53 || a == 0x56 || a == 0x57) {
                patch = isDll ? QByteArray::fromHex("8BFF558BEC") : QByteArray::fromHex("558BEC6AFF");
            }
            // 83 EC xx = sub esp,xx (stack allocation — after push ebp; mov ebp,esp)
            else if (a == 0x83 && b == 0xEC) {
                patch = isDll ? QByteArray::fromHex("8BFF558BEC") : QByteArray::fromHex("558BEC");
                while (patch.size() < rLen) patch.append(char(0x90));
            }
            // 8B/89 = mov reg,reg (register operations after prologue)
            else if (a == 0x8B || a == 0x89 || a == 0xA1) {
                patch = isDll ? QByteArray::fromHex("8BFF558BEC") : QByteArray::fromHex("558BEC");
                while (patch.size() < rLen) patch.append(char(0x90));
            }
        }

        // 3. Default prologue
        if (patch.isEmpty()) {
            if (is64)
                patch = QByteArray::fromHex("4883EC2848");
            else if (isDll)
                patch = QByteArray::fromHex("8BFF558BEC");
            else
                patch = QByteArray::fromHex("558BEC6AFF");
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Write EXACTLY rLen bytes Ã¢â€â‚¬Ã¢â€â‚¬
        while (patch.size() < rLen) patch.append(char(0x90));
        int writeLen = rLen; // Only overwrite the redirect, preserve rest
        if (epOff + writeLen > fileSize) return false;
        memcpy(ep, patch.constData(), writeLen);

        Logger::info(QStringLiteral("EP fix: 0x%1 | %2 | %3B (redir=%4, dll=%5)")
                     .arg(epOff, 0, 16)
                     .arg(QString::fromLatin1(patch.left(writeLen).toHex().toUpper()))
                     .arg(writeLen).arg(rLen).arg(isDll));
        return true;
    }
    return false;
#else
    Q_UNUSED(base); Q_UNUSED(fileSize); Q_UNUSED(is64);
    Q_UNUSED(epPatchHex); Q_UNUSED(epRva); Q_UNUSED(secHdrV); Q_UNUSED(numSections);
    return false;
#endif
}

bool Scanner::truncateOverlay(const QString &path, qint64 legitEnd)
{
    if (legitEnd <= 0) return false;
    QFile f(path);
    if (!f.open(QIODevice::ReadWrite)) return false;
    if (f.size() <= legitEnd) { f.close(); return true; }
    bool ok = f.resize(legitEnd);
    f.close();
    if (ok) {
        Logger::info(QStringLiteral("Clean Threat: Truncated overlay at 0x%1 in %2")
                     .arg(legitEnd, 0, 16).arg(path));
    }
    return ok;
}

bool Scanner::recalcPeChecksum(uchar *base, qint64 fileSize, bool is64)
{
#ifdef _WIN32
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    // Recalculate PE checksum
    // The checksum is stored at OptionalHeader.CheckSum. We zero it, then compute.
    DWORD *pChecksum = nullptr;
    DWORD *pSizeOfImage = nullptr;
    if (is64) {
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        pChecksum = &nt->OptionalHeader.CheckSum;
        pSizeOfImage = &nt->OptionalHeader.SizeOfImage;
    } else {
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
        pChecksum = &nt->OptionalHeader.CheckSum;
        pSizeOfImage = &nt->OptionalHeader.SizeOfImage;
    }

    *pChecksum = 0;

    // Simple PE checksum algorithm (same as Windows loader uses)
    quint64 sum = 0;
    const quint16 *w = reinterpret_cast<const quint16*>(base);
    const qint64 words = fileSize / 2;
    for (qint64 i = 0; i < words; ++i) {
        sum += w[i];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (fileSize & 1) {
        sum += base[fileSize - 1];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    *pChecksum = DWORD(sum + fileSize);

    Logger::info(QStringLiteral("Clean Threat: PE checksum recalculated to 0x%1")
                 .arg(*pChecksum, 0, 16));
    return true;
#else
    Q_UNUSED(base); Q_UNUSED(fileSize); Q_UNUSED(is64);
    return false;
#endif
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Backup before repair ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â creates a .verax_bak copy
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
bool Scanner::backupBeforeRepair(const QString &path)
{
    const QString bak = path + QStringLiteral(".verax_bak");
    if (QFile::exists(bak)) QFile::remove(bak);
    bool ok = QFile::copy(path, bak);
    if (ok) {
        Logger::info(QStringLiteral("Backup created: %1").arg(bak));
    } else {
        Logger::error(QStringLiteral("Backup FAILED for: %1").arg(path));
    }
    return ok;
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Detect Original Prologue ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â recover original EP bytes from
//  the infector's section (Ramnit/Floxif store them at the start)
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
bool Scanner::detectOriginalPrologue(const uchar *base, qint64 mapSize, quint32 epRva,
                                      const void *secHdrV, int numSections, bool is64, QByteArray &outPrologue)
{
#ifdef _WIN32
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secHdrV);

    // 1. Find which section contains the EP
    int epSecIdx = -1;
    for (int i = 0; i < numSections; ++i) {
        DWORD vsz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (epRva >= sec[i].VirtualAddress && epRva < sec[i].VirtualAddress + vsz) {
            epSecIdx = i;
            break;
        }
    }
    if (epSecIdx < 0) return false;

    // 2. Check if EP has a JMP/CALL (E9/E8) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â if so, find the target section
    qint64 epFileOff = qint64(sec[epSecIdx].PointerToRawData) +
                       qint64(epRva - sec[epSecIdx].VirtualAddress);
    if (epFileOff < 0 || epFileOff + 6 > mapSize) return false;

    const uchar *ep = base + epFileOff;
    if (ep[0] != 0xE9 && ep[0] != 0xE8) return false;

    qint32 rel = *reinterpret_cast<const qint32*>(ep + 1);
    quint32 targetRva = epRva + 5 + quint32(rel);

    // 3. Find the target section and look for saved prologue
    for (int i = 0; i < numSections; ++i) {
        if (i == epSecIdx) continue;
        DWORD vsz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (targetRva < sec[i].VirtualAddress || targetRva >= sec[i].VirtualAddress + vsz) continue;

        qint64 secStart = sec[i].PointerToRawData;
        if (secStart <= 0 || secStart + 16 > mapSize) break;
        const uchar *sdata = base + secStart;

        bool found = false;
        int prologueLen = 5;

        if (!is64) {
            if (sdata[0] == 0x55 && sdata[1] == 0x8B && sdata[2] == 0xEC) {
                found = true;
                if (sdata[3] == 0x83 && sdata[4] == 0xEC) prologueLen = 7;
                else if (sdata[3] == 0x6A) prologueLen = 5;
                else prologueLen = 5;
            } else if (sdata[0] == 0x8B && sdata[1] == 0xFF && sdata[2] == 0x55) {
                found = true; prologueLen = 5;
            } else if (sdata[0] == 0x6A) {
                found = true; prologueLen = 5;
            } else if (sdata[0] == 0x55 && sdata[1] == 0x89 && sdata[2] == 0xE5) {
                found = true; prologueLen = 5;
            }
        } else {
            if (sdata[0] == 0x48 && sdata[1] == 0x89 && sdata[2] == 0x5C) {
                found = true; prologueLen = 5;
            } else if (sdata[0] == 0x48 && sdata[1] == 0x83 && sdata[2] == 0xEC) {
                found = true; prologueLen = 4;
            } else if (sdata[0] == 0x40 && sdata[1] == 0x53) {
                found = true; prologueLen = 5;
            } else if (sdata[0] == 0x48 && sdata[1] == 0x8B && sdata[2] == 0xC4) {
                found = true; prologueLen = 5;
            }
        }

        if (found) {
            outPrologue = QByteArray(reinterpret_cast<const char*>(sdata), prologueLen);
            Logger::info(QStringLiteral("Recovered prologue from section %1: %2")
                .arg(i).arg(QString::fromLatin1(outPrologue.toHex().toUpper())));
            return true;
        }
        break;
    }
    return false;
#else
    Q_UNUSED(base); Q_UNUSED(mapSize); Q_UNUSED(epRva);
    Q_UNUSED(secHdrV); Q_UNUSED(numSections); Q_UNUSED(is64);
    Q_UNUSED(outPrologue);
    return false;
#endif
}

// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
//  Advanced Clean Threat ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â full PE disinfection engine
// ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
bool Scanner::advancedCleanThreat(const QString &path, ThreatInfo &info)
{
#ifdef _WIN32
    Logger::info(QStringLiteral("=== Clean Threat: %1 ===").arg(path));
    Logger::info(QStringLiteral("  Detection: %1 | Family: %2 | Method: %3")
                 .arg(info.detectionName, info.family, info.repairMethod));

    bool backupOk = backupBeforeRepair(path);
    const QString backupPath = path + QStringLiteral(".verax_bak");
    killProcessesUsingFile(path);
    setFullPermissions(path);

    QFile f(path);
    if (!f.open(QIODevice::ReadWrite)) {
        Logger::error(QStringLiteral("Clean Threat FAILED: cannot open %1").arg(path));
        return false;
    }
    const qint64 fileSize = f.size();
    if (fileSize < 64) { f.close(); return false; }

    uchar *base = f.map(0, fileSize);
    if (!base) { f.close(); return false; }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Parse PE ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { f.unmap(base); f.close(); return false; }
    if (dos->e_lfanew <= 0 || dos->e_lfanew + qint64(sizeof(IMAGE_NT_HEADERS64)) > fileSize) {
        f.unmap(base); f.close(); return false;
    }

    auto fileHdr = reinterpret_cast<IMAGE_FILE_HEADER*>(base + dos->e_lfanew + sizeof(DWORD));
    if (*reinterpret_cast<DWORD*>(base + dos->e_lfanew) != IMAGE_NT_SIGNATURE) {
        f.unmap(base); f.close(); return false;
    }

    WORD optMagic = *reinterpret_cast<WORD*>(
        base + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    const bool is64 = (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    const bool isDll = (fileHdr->Characteristics & IMAGE_FILE_DLL) != 0;

    DWORD entryRva = 0, numDirs = 0, secAlign = 0, fileAlign = 0x200;
    DWORD *pEntryRva = nullptr, *pSizeOfImage = nullptr;
    IMAGE_DATA_DIRECTORY *dirs = nullptr;

    if (is64) {
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        entryRva  = nt->OptionalHeader.AddressOfEntryPoint;
        numDirs   = nt->OptionalHeader.NumberOfRvaAndSizes;
        dirs      = nt->OptionalHeader.DataDirectory;
        secAlign  = nt->OptionalHeader.SectionAlignment;
        fileAlign = nt->OptionalHeader.FileAlignment;
        pEntryRva    = &nt->OptionalHeader.AddressOfEntryPoint;
        pSizeOfImage = &nt->OptionalHeader.SizeOfImage;
    } else {
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
        entryRva  = nt->OptionalHeader.AddressOfEntryPoint;
        numDirs   = nt->OptionalHeader.NumberOfRvaAndSizes;
        dirs      = nt->OptionalHeader.DataDirectory;
        secAlign  = nt->OptionalHeader.SectionAlignment;
        fileAlign = nt->OptionalHeader.FileAlignment;
        pEntryRva    = &nt->OptionalHeader.AddressOfEntryPoint;
        pSizeOfImage = &nt->OptionalHeader.SizeOfImage;
    }

    WORD numSections = fileHdr->NumberOfSections;
    auto sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<uchar*>(fileHdr) + sizeof(IMAGE_FILE_HEADER) + fileHdr->SizeOfOptionalHeader);

    Logger::info(QStringLiteral("  PE: %1-bit %2 | EP=0x%3 | Secs=%4 | Size=%5")
                 .arg(is64 ? 64 : 32).arg(isDll ? "DLL" : "EXE")
                 .arg(entryRva, 0, 16).arg(numSections).arg(fileSize));

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Known infector section names ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    static const char *infectorNames[] = {
        ".flx",".floxif",".sality",".sal",".virut",".vrt",".rmnet",".ramnit",
        ".parite",".expiro",".polip",".mabezat",".tenga",".lamer",".jeefo",
        ".hidrag",".mydoom",".bagle",".neshta",".viking",".alman",".induc",
        ".vetor",".mikcer",".mkc"
    };

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Helpers ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    auto rvaInSec = [](DWORD rva, const IMAGE_SECTION_HEADER &s) -> bool {
        DWORD vsz = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        return rva >= s.VirtualAddress && rva < s.VirtualAddress + vsz;
    };
    auto findTextIdx = [&]() -> int {
        for (int i = 0; i < numSections; ++i) {
            int nL = 0; while (nL < 8 && sec[i].Name[nL]) nL++;
            QString n = QString::fromLatin1(reinterpret_cast<const char*>(sec[i].Name), nL).toLower();
            if (n == ".text" || n == ".code") return i;
        }
        return 0;
    };
    auto overlapsCritical = [&](DWORD sRva, DWORD sSz) -> bool {
        static const int crit[] = {
            IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_EXPORT,
            IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DIRECTORY_ENTRY_IAT,
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_TLS,
            IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
        };
        for (int idx : crit) {
            if (DWORD(idx) >= numDirs) continue;
            DWORD dR = dirs[idx].VirtualAddress, dS = dirs[idx].Size;
            if (dS > 0 && !(sRva + sSz <= dR || dR + dS <= sRva)) return true;
        }
        return false;
    };
    auto getSectionName = [&](int i) -> QString {
        int nL = 0; while (nL < 8 && sec[i].Name[nL]) nL++;
        return QString::fromLatin1(reinterpret_cast<const char*>(sec[i].Name), nL).toLower();
    };

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    //  Step A: Recover original prologue BEFORE removal
    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    // ===================================================
    //  Step A0: BEFORE any changes - analyze EP state
    //  Check if the virus actually modified the Entry Point
    // ===================================================
    bool epHasRedirect = false;   // true = virus replaced EP bytes with JMP/CALL
    QByteArray originalEpBytes;   // save original 16 bytes at EP for analysis

    for (int i = 0; i < numSections; ++i) {
        if (!rvaInSec(entryRva, sec[i])) continue;
        qint64 epOff = qint64(sec[i].PointerToRawData) + qint64(entryRva - sec[i].VirtualAddress);
        if (epOff < 0 || epOff + 16 > fileSize) break;
        uchar *ep = base + epOff;
        originalEpBytes = QByteArray(reinterpret_cast<const char*>(ep), 16);

        // Check: does EP start with a virus redirect instruction?
        epHasRedirect = (ep[0] == 0xE9 || ep[0] == 0xE8 || ep[0] == 0xEB ||
                         ep[0] == 0x60 || ep[0] == 0x9C ||
                         (ep[0] == 0xFF && ep[1] == 0x25) ||
                         (ep[0] == 0x68 && ep[5] == 0xC3));

        Logger::info(QStringLiteral("  EP analysis: opcode=0x%1 redirect=%2")
                     .arg(ep[0], 2, 16, QChar('0')).arg(epHasRedirect ? "YES" : "NO"));
        break;
    }

    // ===================================================
    //  Step A1: Try to recover original prologue from virus section
    //  (only useful if EP was redirected)
    // ===================================================
    QByteArray recoveredPrologue;
    if (epHasRedirect) {
        detectOriginalPrologue(base, fileSize, entryRva, sec, numSections, is64, recoveredPrologue);
        if (!recoveredPrologue.isEmpty()) {
            info.entryPointPatch = QString::fromLatin1(recoveredPrologue.toHex().toUpper());
            Logger::info(QStringLiteral("  Recovered prologue: %1").arg(info.entryPointPatch));
        }
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    //  Step B: REMOVE infector sections
    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    bool repaired = false;
    qint64 curSize = fileSize;
    bool epNeedsRedirect = false;

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 1: Remove NAMED infector sections ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    for (int i = 0; i < numSections; ) {
        QString nm = getSectionName(i);

        bool isInfector = false;
        for (auto *bad : infectorNames) {
            if (nm == QString::fromLatin1(bad)) { isInfector = true; break; }
        }
        if (!isInfector) { ++i; continue; }

        DWORD rawOff = sec[i].PointerToRawData;
        DWORD rawSz  = sec[i].SizeOfRawData;
        DWORD secVA  = sec[i].VirtualAddress;
        DWORD secVSz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : rawSz;

        if (entryRva != 0 && rvaInSec(entryRva, sec[i]))
            epNeedsRedirect = true;

        // Critical dir overlap ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ zero only, don't remove
        if (overlapsCritical(secVA, secVSz)) {
            Logger::warn(QStringLiteral("  '%1' overlaps critical dir ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â zeroing only").arg(nm));
            if (rawOff > 0 && rawSz > 0 && qint64(rawOff) + rawSz <= curSize) {
                memset(base + rawOff, 0, rawSz);
                sec[i].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
                repaired = true;
            }
            ++i; continue;
        }

        if (rawOff == 0 || rawSz == 0 || qint64(rawOff) + rawSz > curSize) { ++i; continue; }

        // Shift file data
        qint64 secEnd = qint64(rawOff) + rawSz;
        if (secEnd < curSize)
            memmove(base + rawOff, base + secEnd, curSize - secEnd);
        curSize -= rawSz;

        // Shift section headers
        if (i < numSections - 1)
            memmove(&sec[i], &sec[i + 1], (numSections - 1 - i) * sizeof(IMAGE_SECTION_HEADER));
        numSections--;
        fileHdr->NumberOfSections = numSections;
        memset(&sec[numSections], 0, sizeof(IMAGE_SECTION_HEADER));

        // Fix PointerToRawData for remaining sections
        for (int k = i; k < numSections; ++k) {
            if (sec[k].PointerToRawData > rawOff)
                sec[k].PointerToRawData -= rawSz;
        }

        Logger::info(QStringLiteral("  Pass 1: REMOVED '%1' (%2 bytes)").arg(nm).arg(rawSz));
        repaired = true;
        // Don't increment ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â next section shifted into slot i
    }

    // ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Pass 2: Remove suspicious RWX non-standard sections ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    if (!repaired) {
        for (int i = numSections - 1; i >= 1; --i) {
            QString nm = getSectionName(i);
            if (isStandardSection(nm) || isKnownPackerSection(nm)) continue;

            DWORD ch = sec[i].Characteristics;
            bool isExec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool isWrite = (ch & IMAGE_SCN_MEM_WRITE) != 0;
            bool suspicious = (isExec && isWrite);

            // Not RWX ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â check if EP redirects here
            if (isExec && !isWrite && entryRva != 0) {
                for (int e = 0; e < numSections; ++e) {
                    if (!rvaInSec(entryRva, sec[e]) || e == i) continue;
                    qint64 epOff = qint64(sec[e].PointerToRawData) + qint64(entryRva - sec[e].VirtualAddress);
                    if (epOff < 0 || epOff + 6 > curSize) break;
                    uchar *epB = base + epOff;
                    if (epB[0] == 0xE9 || epB[0] == 0xE8) {
                        quint32 tgt = entryRva + 5 + quint32(*reinterpret_cast<qint32*>(epB + 1));
                        DWORD vs = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
                        if (tgt >= sec[i].VirtualAddress && tgt < sec[i].VirtualAddress + vs)
                            suspicious = true;
                    }
                    break;
                }
            }

            if (!suspicious) continue;

            DWORD rawOff = sec[i].PointerToRawData;
            DWORD rawSz  = sec[i].SizeOfRawData;
            DWORD secVA  = sec[i].VirtualAddress;
            DWORD secVSz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : rawSz;

            if (rawOff == 0 || rawSz == 0 || qint64(rawOff) + rawSz > curSize) continue;
            if (overlapsCritical(secVA, secVSz)) continue;
            if (rvaInSec(entryRva, sec[i])) epNeedsRedirect = true;

            qint64 secEnd = qint64(rawOff) + rawSz;
            if (secEnd < curSize)
                memmove(base + rawOff, base + secEnd, curSize - secEnd);
            curSize -= rawSz;

            if (i < numSections - 1)
                memmove(&sec[i], &sec[i + 1], (numSections - 1 - i) * sizeof(IMAGE_SECTION_HEADER));
            numSections--;
            fileHdr->NumberOfSections = numSections;
            memset(&sec[numSections], 0, sizeof(IMAGE_SECTION_HEADER));

            for (int k = i; k < numSections; ++k) {
                if (sec[k].PointerToRawData > rawOff)
                    sec[k].PointerToRawData -= rawSz;
            }

            Logger::info(QStringLiteral("  Pass 2: REMOVED '%1' (%2 bytes)").arg(nm).arg(rawSz));
            repaired = true;
        }
    }

    // ===================================================
    //  Pass 3: Trim inflated sections (virus appended code to last section)
    //  Floxif/Mikcer increase SizeOfRawData of last section without adding new one
    // ===================================================
    if (numSections > 0 && fileAlign > 0) {
        // Check the last section for inflation
        auto &lastSec = sec[numSections - 1];
        DWORD vsize = lastSec.Misc.VirtualSize;
        DWORD rawSize = lastSec.SizeOfRawData;
        DWORD rawOff = lastSec.PointerToRawData;

        if (vsize > 0 && rawSize > 0 && rawOff > 0) {
            // Calculate correct raw size: VirtualSize rounded up to FileAlignment
            DWORD correctRaw = (vsize + fileAlign - 1) & ~(fileAlign - 1);

            // If actual raw size is MUCH larger than needed, virus appended data
            // Allow small margin (1 page = 0x1000) for legitimate padding
            if (rawSize > correctRaw + 0x1000) {
                qint64 excess = qint64(rawSize) - correctRaw;
                QString sn = getSectionName(numSections - 1);

                Logger::info(QStringLiteral("  Pass 3: '%1' inflated: rawSz=0x%2 correctRaw=0x%3 excess=%4 bytes")
                             .arg(sn).arg(rawSize, 0, 16).arg(correctRaw, 0, 16).arg(excess));

                // Zero the excess bytes (virus body)
                qint64 excessStart = qint64(rawOff) + correctRaw;
                if (excessStart + excess <= curSize) {
                    memset(base + excessStart, 0, excess);
                }

                // Shrink the section's raw size
                lastSec.SizeOfRawData = correctRaw;
                curSize -= excess;
                repaired = true;

                Logger::info(QStringLiteral("  Pass 3: Trimmed '%1' rawSz: 0x%2 -> 0x%3 (-%4 bytes)")
                             .arg(sn).arg(rawSize, 0, 16).arg(correctRaw, 0, 16).arg(excess));
            }
        }

        // Also check ALL sections for inflation (not just last)
        for (int i = 0; i < numSections - 1; ++i) {
            DWORD vs = sec[i].Misc.VirtualSize;
            DWORD rs = sec[i].SizeOfRawData;
            if (vs == 0 || rs == 0) continue;

            DWORD correctRaw = (vs + fileAlign - 1) & ~(fileAlign - 1);
            // For non-last sections, check against next section's offset
            DWORD nextOff = sec[i + 1].PointerToRawData;
            DWORD expectedEnd = sec[i].PointerToRawData + correctRaw;

            // If raw size pushes past next section AND is inflated
            if (rs > correctRaw + 0x1000 && expectedEnd <= nextOff) {
                qint64 excess = qint64(rs) - correctRaw;
                QString sn = getSectionName(i);

                // Zero excess
                qint64 excessStart = qint64(sec[i].PointerToRawData) + correctRaw;
                if (excessStart + excess <= curSize) {
                    memset(base + excessStart, 0, excess);
                }
                sec[i].SizeOfRawData = correctRaw;
                repaired = true;

                Logger::info(QStringLiteral("  Pass 3: Trimmed '%1' rawSz: 0x%2 -> 0x%3")
                             .arg(sn).arg(rs, 0, 16).arg(correctRaw, 0, 16));
            }
        }
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    //  Step C: Fix Entry Point RVA
    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    // ===================================================
    //  Step C: Fix EP ONLY if virus actually modified it
    // ===================================================
    {
        // Case 1: EP section was deleted -> must find the REAL EP in .text
        bool epValid = false;
        for (int i = 0; i < numSections; ++i) {
            if (rvaInSec(entryRva, sec[i])) { epValid = true; break; }
        }

        if (!epValid || epNeedsRedirect) {
            int textIdx = findTextIdx();
            qint64 textRaw = sec[textIdx].PointerToRawData;
            qint64 textRawSz = sec[textIdx].SizeOfRawData;
            DWORD textVA = sec[textIdx].VirtualAddress;
            DWORD newEP = textVA; // fallback to section start

            // SCAN .text for CRT startup patterns to find the REAL entry point
            if (textRaw > 0 && textRawSz > 0 && textRaw + textRawSz <= curSize) {
                // EXE CRT: 55 8B EC 6A FF 68 (push ebp; mov ebp,esp; push -1; push handler)
                const uchar exeCrt[] = {0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68};
                // DLL CRT: 8B FF 55 8B EC 83 7D 0C (mov edi,edi; push ebp; mov ebp,esp; cmp [ebp+0Ch])
                const uchar dllCrt[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x0C};

                const uchar *pattern = isDll ? dllCrt : exeCrt;
                int patLen = isDll ? 8 : 6;
                bool found = false;

                // Scan from END of .text backwards (CRT startup is usually near the end)
                for (qint64 off = textRaw + textRawSz - patLen; off >= textRaw; --off) {
                    bool match = true;
                    for (int j = 0; j < patLen; ++j) {
                        if (base[off + j] != pattern[j]) { match = false; break; }
                    }
                    if (match) {
                        // Found! Convert file offset to RVA
                        newEP = textVA + DWORD(off - textRaw);
                        found = true;
                        Logger::info(QStringLiteral("  EP: Found CRT startup at file 0x%1 -> RVA 0x%2")
                                     .arg(off, 0, 16).arg(newEP, 0, 16));
                        break;
                    }
                }

                // If EXE pattern not found, try DLL pattern too (and vice versa)
                if (!found) {
                    pattern = isDll ? exeCrt : dllCrt;
                    patLen = isDll ? 6 : 8;
                    for (qint64 off = textRaw + textRawSz - patLen; off >= textRaw; --off) {
                        bool match = true;
                        for (int j = 0; j < patLen; ++j) {
                            if (base[off + j] != pattern[j]) { match = false; break; }
                        }
                        if (match) {
                            newEP = textVA + DWORD(off - textRaw);
                            found = true;
                            Logger::info(QStringLiteral("  EP: Found alt CRT at file 0x%1 -> RVA 0x%2")
                                         .arg(off, 0, 16).arg(newEP, 0, 16));
                            break;
                        }
                    }
                }

                if (!found) {
                    Logger::warn(QStringLiteral("  EP: No CRT pattern found, using .text start 0x%1")
                                 .arg(textVA, 0, 16));
                }
            }

            Logger::info(QStringLiteral("  EP: redirect 0x%1 -> 0x%2")
                         .arg(entryRva, 0, 16).arg(newEP, 0, 16));
            entryRva = newEP;
            *pEntryRva = newEP;
            repairEntryPoint(base, curSize, is64, info.entryPointPatch, entryRva, sec, numSections);
            repaired = true;
        }
        // Case 2: EP has virus redirect (JMP/CALL) -> restore original prologue
        else if (epHasRedirect) {
            Logger::info(QStringLiteral("  EP: virus redirect detected, restoring prologue"));
            if (repairEntryPoint(base, curSize, is64, info.entryPointPatch, entryRva, sec, numSections))
                repaired = true;
        }
        // Case 3: EP is normal -> DON'T TOUCH IT
        else {
            Logger::info(QStringLiteral("  EP: no redirect, leaving original EP intact"));
        }
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    //  Step D: In-section virus body cleanup
    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    for (int i = 0; i < numSections; ++i) {
        DWORD ch = sec[i].Characteristics;
        if (!(ch & IMAGE_SCN_MEM_EXECUTE)) continue;

        qint64 rawOff = sec[i].PointerToRawData;
        qint64 rawSz  = sec[i].SizeOfRawData;
        DWORD vSz = sec[i].Misc.VirtualSize;
        if (rawOff <= 0 || rawSz <= 0 || rawOff + rawSz > curSize) continue;

        // Zero code cave beyond VirtualSize
        if (vSz > 0 && rawSz > qint64(vSz) + 64) {
            qint64 caveOff = rawOff + vSz;
            qint64 caveLen = rawSz - vSz;
            if (caveOff + caveLen <= curSize) {
                int active = 0;
                qint64 chkLen = qMin(caveLen, qint64(256));
                for (qint64 j = 0; j < chkLen; ++j) {
                    uchar b = base[caveOff + j];
                    if (b != 0 && b != 0xCC && b != 0x90) active++;
                }
                if (active > int(chkLen * 0.3)) {
                    memset(base + caveOff, 0, caveLen);
                    Logger::info(QStringLiteral("  Pass D: zeroed cave sec %1 (%2 bytes)").arg(i).arg(caveLen));
                    repaired = true;
                }
            }
        }

        // Zero virus stubs
        qint64 scanLim = qMin(rawSz, qint64(512 * 1024));
        for (qint64 off = rawOff; off + 8 <= rawOff + scanLim; ++off) {
            uchar *p = base + off;
            // PUSHAD+CALL$+5+POP
            if (p[0] == 0x60 && p[1] == 0xE8 && p[2] == 0 && p[3] == 0 && p[4] == 0 && p[5] == 0 &&
                p[6] >= 0x58 && p[6] <= 0x5F) {
                qint64 zLen = qMin(qint64(256), rawOff + rawSz - off);
                memset(p, 0, zLen);
                repaired = true;
                off += zLen - 1;
            }
            // PUSHFD+PUSHAD+CALL$+5
            if (p[0] == 0x9C && p[1] == 0x60 && p[2] == 0xE8 &&
                p[3] == 0 && p[4] == 0 && p[5] == 0 && p[6] == 0) {
                qint64 zLen = qMin(qint64(256), rawOff + rawSz - off);
                memset(p, 0, zLen);
                repaired = true;
                off += zLen - 1;
            }
        }

        // Remove WRITE flag from .text/.code
        QString sn = getSectionName(i);
        if ((sn == ".text" || sn == ".code") && (ch & IMAGE_SCN_MEM_WRITE)) {
            sec[i].Characteristics = ch & ~IMAGE_SCN_MEM_WRITE;
            repaired = true;
        }
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    //  Step E: Fix SizeOfImage + Checksum
    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    // ===================================================
    //  Step E: Fix SizeOfImage + Checksum + Remove overlay virus
    // ===================================================
    if (repaired && numSections > 0 && secAlign > 0) {
        const auto &last = sec[numSections - 1];
        DWORD vs = last.Misc.VirtualSize ? last.Misc.VirtualSize : last.SizeOfRawData;
        DWORD aligned = (vs + secAlign - 1) & ~(secAlign - 1);
        *pSizeOfImage = last.VirtualAddress + aligned;
        Logger::info(QStringLiteral("  SizeOfImage = 0x%1").arg(*pSizeOfImage, 0, 16));
    }

    // Calculate last section end (PE data boundary)
    qint64 lastSecEnd = 0;
    for (int i = 0; i < numSections; ++i) {
        qint64 end = qint64(sec[i].PointerToRawData) + sec[i].SizeOfRawData;
        if (end > lastSecEnd) lastSecEnd = end;
    }

    // Check for overlay virus body
    // Overlay = everything after last section in the file
    qint64 correctSize = curSize;  // default: use memmove-tracked size
    if (lastSecEnd > 0 && curSize > lastSecEnd) {
        qint64 overlaySize = curSize - lastSecEnd;

        // Check PE Security Directory for legitimate Authenticode certificate
        // Security directory index = 4, and its VA is a FILE OFFSET (not RVA!)
        qint64 certEnd = lastSecEnd; // default: no cert → overlay starts at section end
        if (DWORD(IMAGE_DIRECTORY_ENTRY_SECURITY) < numDirs) {
            DWORD secDirVA = dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            DWORD secDirSz = dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            if (secDirVA > 0 && secDirSz > 0 && qint64(secDirVA) + secDirSz <= curSize) {
                // Legitimate certificate exists → keep it
                certEnd = qint64(secDirVA) + secDirSz;
                Logger::info(QStringLiteral("  Certificate: offset=0x%1 size=%2 end=0x%3")
                             .arg(secDirVA, 0, 16).arg(secDirSz).arg(certEnd, 0, 16));
            }
        }

        // If file extends beyond cert (or beyond sections if no cert) → virus overlay
        if (curSize > certEnd && certEnd >= lastSecEnd) {
            qint64 virusOverlay = curSize - certEnd;
            if (virusOverlay > 0) {
                Logger::info(QStringLiteral("  Overlay virus: %1 bytes after 0x%2 (cert/sections end)")
                             .arg(virusOverlay).arg(certEnd, 0, 16));
                correctSize = certEnd;
                repaired = true;
            }
        }
    }

    if (repaired) {
        recalcPeChecksum(base, qMin(curSize, correctSize), is64);
    }

    f.unmap(base);
    f.close();

    // ===================================================
    //  Step F: Truncate — remove virus sections AND overlay
    // ===================================================
    qint64 finalSize = qMin(curSize, correctSize);
    if (finalSize < fileSize && finalSize > 0 && repaired) {
        QFile tf(path);
        if (tf.open(QIODevice::ReadWrite)) {
            tf.resize(finalSize);
            tf.close();
            Logger::info(QStringLiteral("  Truncated: %1 -> %2 bytes (-%3)")
                         .arg(fileSize).arg(finalSize).arg(fileSize - finalSize));
        }
    }

    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    //  Step G: Verify PE integrity
    // ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â
    if (repaired) {
        QFile vf(path);
        if (vf.open(QIODevice::ReadOnly)) {
            qint64 vs = vf.size();
            if (vs >= 64) {
                uchar *vb = vf.map(0, qMin<qint64>(vs, 4096));
                if (vb) {
                    auto vd = reinterpret_cast<const IMAGE_DOS_HEADER*>(vb);
                    if (vd->e_magic != IMAGE_DOS_SIGNATURE ||
                        vd->e_lfanew <= 0 || vd->e_lfanew + 4 > vs ||
                        *reinterpret_cast<const DWORD*>(vb + vd->e_lfanew) != IMAGE_NT_SIGNATURE) {
                        Logger::error("Clean Threat: PE CORRUPTED after repair!");
                        repaired = false;
                    } else {
                        Logger::info("Clean Threat: PE OK ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“");
                    }
                    vf.unmap(vb);
                }
            }
            vf.close();
        }
    }

    Logger::info(QStringLiteral("=== Clean Threat %1: %2 ===")
                 .arg(repaired ? "OK" : "FAIL").arg(path));

    // Restore from backup if failed
    // if (!repaired && backupOk && QFile::exists(backupPath)) {
    //     QFile::remove(path);
    //     QFile::rename(backupPath, path);
    //     Logger::info("  Restored from backup");
    // }
    // if (repaired && QFile::exists(backupPath)) {
    //     Logger::info(QStringLiteral("  Backup at: %1").arg(backupPath));
    // }

    if (!repaired && backupOk && QFile::exists(backupPath)) {
            QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner |
                                        QFileDevice::ReadUser  | QFileDevice::WriteUser  | QFileDevice::ExeUser  |
                                        QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup |
                                        QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther);
            QFile::setPermissions(backupPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner |
                                              QFileDevice::ReadUser  | QFileDevice::WriteUser  | QFileDevice::ExeUser  |
                                              QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup |
                                              QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther);
            QFile::remove(path);
            QFile::rename(backupPath, path);
            Logger::info("  Restored from backup");
        }
        if (repaired && QFile::exists(backupPath)) {
            QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner |
                                        QFileDevice::ReadUser  | QFileDevice::WriteUser  | QFileDevice::ExeUser  |
                                        QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup |
                                        QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther);
            QFile::setPermissions(backupPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner |
                                              QFileDevice::ReadUser  | QFileDevice::WriteUser  | QFileDevice::ExeUser  |
                                              QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup |
                                              QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther);

            QString backupHash = info.sha256;
            if (backupHash.isEmpty()) {
                backupHash = HashUtils::sha256Hex(backupPath).toLower().trimmed();
            }

            QString vaultResult = Quarantine::instance().moveToVault(backupPath, backupHash, info.detectionName);

            if (!vaultResult.isEmpty()) {
                Logger::info(QStringLiteral("  Backup securely ciphered and archived into vault: %1").arg(vaultResult));
            } else {
                QFile::remove(backupPath);
                Logger::warn(QStringLiteral("  Vault archiving failed. Backup force-deleted to maintain system safety."));
            }
        }

    return repaired;
#else
    Q_UNUSED(path); Q_UNUSED(info);
    return false;
#endif
}

bool Scanner::disinfectPE(const QString &path)
{
#ifdef _WIN32
    ThreatInfo tempInfo;
    tempInfo.repairMethod = "PE.SectionWipe+EP.Restore";
    tempInfo.entryPointPatch = "";
    tempInfo.repairable = true;
    return advancedCleanThreat(path, tempInfo);
#else
    Q_UNUSED(path);
    return false;
#endif
}

} // namespace verax

