// SignatureDb.cpp - SQLite store + JSON fallback using Qt's bundled QSQLITE
#include "SignatureDb.h"
#include "Logger.h"
#include "../../Version.h"
#include "qsettings.h"

#include <QSqlQuery>
#include <QSqlError>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QTimer>

namespace verax {

SignatureDb& SignatureDb::instance() {
    static SignatureDb s;
    return s;
}

SignatureDb::SignatureDb(QObject *parent) : QObject(parent) {}

static QString dbDir() {
    const QString d = Logger::userDataDir() + QStringLiteral("/db");
    QDir().mkpath(d);
    return d;
}

bool SignatureDb::open()
{
    if (m_jsonFallback) return true; // Already in JSON mode
    if (m_db.isOpen()) return true;

    m_path = dbDir() + QStringLiteral("/verax.sqlite");

    if (QSqlDatabase::contains("verax_main")) {
        m_db = QSqlDatabase::database("verax_main");
    } else {
        m_db = QSqlDatabase::addDatabase("QSQLITE", "verax_main");
    }

    m_db.setDatabaseName(m_path);
    if (!m_db.open()) {
        Logger::error(QStringLiteral("Cannot open DB: %1 - %2")
                          .arg(m_path, m_db.lastError().text()));
        // Try fallback: use JSON file instead
        Logger::info(QStringLiteral("Switching to JSON fallback mode"));
        return initJsonFallback();
    }
    QSqlQuery q(m_db);
    q.exec("PRAGMA journal_mode=WAL;");
    q.exec("PRAGMA synchronous=NORMAL;");
    q.exec("PRAGMA foreign_keys=ON;");
    return true;
}

void SignatureDb::close() {
    if (m_db.isOpen()) m_db.close();
    m_jsonFallback = false;
}

bool SignatureDb::isOpen() const {
    return m_db.isOpen() || m_jsonFallback;
}

// ═══════════════════════════════════════════════════════════════════
//  JSON Fallback Implementation
// ═══════════════════════════════════════════════════════════════════
bool SignatureDb::initJsonFallback()
{
    m_jsonFallback = true;
    m_jsonPath = dbDir() + QStringLiteral("/verax_signatures.json");

    // Try to load existing local JSON cache first
    QFile localFile(m_jsonPath);
    if (localFile.open(QIODevice::ReadOnly)) {
        QJsonParseError err{};
        const QJsonDocument doc = QJsonDocument::fromJson(localFile.readAll(), &err);
        localFile.close();
        if (!doc.isNull() && doc.isObject()) {
            m_jsonEntries = doc.object().value("entries").toArray();
            Logger::info(QStringLiteral("JSON fallback: loaded %1 entries from local cache")
                             .arg(m_jsonEntries.size()));
        }
    }

    // Always sync from seed.json (adds anything missing)
    const int added = syncSeedToJson(QStringLiteral(":/signatures/seed.json"));
    if (added > 0)
        Logger::info(QStringLiteral("JSON fallback: synced %1 new entries from seed").arg(added));

    return true;
}

int SignatureDb::syncSeedToJson(const QString &qrcPath)
{
    QFile f(qrcPath);
    if (!f.open(QIODevice::ReadOnly)) return 0;

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &err);
    f.close();
    if (doc.isNull() || !doc.isObject()) return 0;

    const QJsonArray seedEntries = doc.object().value("entries").toArray();
    int added = 0;

    // Build a set of existing hashes for fast lookup
    QSet<QString> existingHashes;
    for (const auto &v : m_jsonEntries) {
        existingHashes.insert(v.toObject().value("sha256").toString().toLower());
    }

    for (const auto &v : seedEntries) {
        QJsonObject o = v.toObject();
        QString hash = o.value("sha256").toString().toLower().trimmed();
        if (hash.length() != 64) continue;

        if (!existingHashes.contains(hash)) {
            m_jsonEntries.append(o);
            existingHashes.insert(hash);
            ++added;
        } else {
            // Update existing entry if seed has repairable=true but cache doesn't
            if (o.value("repairable").toBool(false)) {
                for (int i = 0; i < m_jsonEntries.size(); ++i) {
                    QJsonObject ex = m_jsonEntries[i].toObject();
                    if (ex.value("sha256").toString().toLower() == hash) {
                        if (!ex.value("repairable").toBool(false)) {
                            ex["repairable"] = true;
                            ex["repair_method"] = o.value("repair_method").toString();
                            ex["entry_point_patch"] = o.value("entry_point_patch").toString();
                            m_jsonEntries[i] = ex;
                        }
                        break;
                    }
                }
            }
        }
    }

    if (added > 0) saveJsonCache();
    return added;
}

void SignatureDb::saveJsonCache() const
{
    QJsonObject root;
    root["schema_version"] = 5;
    root["generated_at"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    root["entries"] = m_jsonEntries;

    QFile f(m_jsonPath);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
        f.close();
    }
}

void SignatureDb::mergeJsonEntries(const QJsonArray &newEntries)
{
    QSet<QString> existingHashes;
    for (const auto &v : m_jsonEntries)
        existingHashes.insert(v.toObject().value("sha256").toString().toLower());

    for (const auto &v : newEntries) {
        QJsonObject o = v.toObject();
        QString hash = o.value("sha256").toString().toLower().trimmed();
        if (hash.length() != 64) continue;
        if (!existingHashes.contains(hash)) {
            m_jsonEntries.append(o);
            existingHashes.insert(hash);
        }
    }
    saveJsonCache();
}

SigHit SignatureDb::lookupJson(const QString &sha256Hex) const
{
    SigHit hit;
    const QString cleanHash = sha256Hex.toLower().trimmed();
    for (const auto &v : m_jsonEntries) {
        const QJsonObject o = v.toObject();
        if (o.value("sha256").toString().toLower().trimmed() == cleanHash) {
            hit.name           = o.value("name").toString();
            hit.family         = o.value("family").toString();
            hit.severity       = o.value("severity").toInt(5);
            hit.repairable     = o.value("repairable").toBool(false);
            hit.repairMethod   = o.value("repair_method").toString();
            hit.entryPointPatch= o.value("entry_point_patch").toString();
            break;
        }
    }
    return hit;
}

SigHit SignatureDb::lookupByFamilyJson(const QString &family) const
{
    SigHit hit;
    const QString fam = family.toLower();
    for (const auto &v : m_jsonEntries) {
        const QJsonObject o = v.toObject();
        if (o.value("family").toString().toLower() == fam && o.value("repairable").toBool(false)) {
            hit.name           = o.value("name").toString();
            hit.family         = o.value("family").toString();
            hit.severity       = o.value("severity").toInt(5);
            hit.repairable     = true;
            hit.repairMethod   = o.value("repair_method").toString();
            hit.entryPointPatch= o.value("entry_point_patch").toString();
            break;
        }
    }
    return hit;
}

bool SignatureDb::isFamilyRepairableJson(const QString &family) const
{
    const QString fam = family.toLower();
    for (const auto &v : m_jsonEntries) {
        const QJsonObject o = v.toObject();
        if (o.value("family").toString().toLower() == fam && o.value("repairable").toBool(false))
            return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════
//  Schema Migration
// ═══════════════════════════════════════════════════════════════════
void SignatureDb::migrateSchema()
{
    if (!m_db.isOpen()) return;
    QSqlQuery q(m_db);
    q.exec("PRAGMA table_info(signatures)");
    bool hasRepairable = false, hasRepairMethod = false, hasByteSigs = false, hasEpPatch = false;
    while (q.next()) {
        const QString col = q.value(1).toString();
        if (col == "repairable")       hasRepairable = true;
        if (col == "repair_method")    hasRepairMethod = true;
        if (col == "byte_signatures")  hasByteSigs = true;
        if (col == "entry_point_patch") hasEpPatch = true;
    }
    if (!hasRepairable)
        q.exec("ALTER TABLE signatures ADD COLUMN repairable INTEGER DEFAULT 0");
    if (!hasRepairMethod)
        q.exec("ALTER TABLE signatures ADD COLUMN repair_method TEXT DEFAULT ''");
    if (!hasByteSigs)
        q.exec("ALTER TABLE signatures ADD COLUMN byte_signatures TEXT DEFAULT ''");
    if (!hasEpPatch)
        q.exec("ALTER TABLE signatures ADD COLUMN entry_point_patch TEXT DEFAULT ''");
    q.exec("CREATE INDEX IF NOT EXISTS idx_sigs_repairable ON signatures(repairable)");
}

bool SignatureDb::initSchema()
{
    if (m_jsonFallback) {
        // JSON mode: just sync seed
        const int n = syncSeedToJson(QStringLiteral(":/signatures/seed.json"));
        if (n > 0)
            Logger::info(QStringLiteral("JSON fallback synced %1 signatures from seed").arg(n));
        return true;
    }

    if (!isOpen() && !open()) return false;
    if (m_jsonFallback) return true; // open() switched to JSON fallback

    QFile f(QStringLiteral(":/sql/schema.sql"));
    if (!f.open(QIODevice::ReadOnly)) {
        Logger::error("schema.sql missing from qrc");
        return false;
    }
    const QString sql = QString::fromUtf8(f.readAll());

    QSqlQuery q(m_db);
    for (const QString &stmt : sql.split(';', Qt::SkipEmptyParts)) {
        const QString trimmed = stmt.trimmed();
        if (trimmed.isEmpty()) continue;
        if (!q.exec(trimmed)) {
            Logger::warn(QStringLiteral("schema stmt failed: %1 - %2")
                             .arg(trimmed.left(60), q.lastError().text()));
        }
    }

    migrateSchema();

    const int n = syncSeedToDb();
    if (n > 0)
        Logger::info(QStringLiteral("Synced %1 new signatures from seed.json").arg(n));

    return true;
}

// ═══════════════════════════════════════════════════════════════════
//  Lookup Methods (with JSON fallback)
// ═══════════════════════════════════════════════════════════════════
SigHit SignatureDb::lookup(const QString &sha256Hex) const
{
    if (m_jsonFallback) return lookupJson(sha256Hex);

    SigHit hit;
    if (!m_db.isOpen()) return hit;

    QString cleanHash = sha256Hex.toLower().trimmed();

    QSqlQuery q(m_db);
    q.prepare("SELECT name, family, severity, repairable, repair_method, entry_point_patch "
              "FROM signatures WHERE LOWER(sha256) = ? LIMIT 1");
    q.bindValue(0, cleanHash);

    if (q.exec() && q.next()) {
        hit.name           = q.value(0).toString();
        hit.family         = q.value(1).toString();
        hit.severity       = q.value(2).toInt();
        hit.repairable     = q.value(3).toInt() != 0;
        hit.repairMethod   = q.value(4).toString();
        hit.entryPointPatch= q.value(5).toString();
    }
    return hit;
}

SigHit SignatureDb::lookupByFamily(const QString &family) const
{
    if (m_jsonFallback) return lookupByFamilyJson(family);

    SigHit hit;
    if (!m_db.isOpen() || family.isEmpty()) return hit;

    QSqlQuery q(m_db);
    q.prepare("SELECT name, family, severity, repairable, repair_method, entry_point_patch "
              "FROM signatures WHERE LOWER(family) = ? AND repairable = 1 LIMIT 1");
    q.bindValue(0, family.toLower());
    if (q.exec() && q.next()) {
        hit.name           = q.value(0).toString();
        hit.family         = q.value(1).toString();
        hit.severity       = q.value(2).toInt();
        hit.repairable     = q.value(3).toInt() != 0;
        hit.repairMethod   = q.value(4).toString();
        hit.entryPointPatch= q.value(5).toString();
    }
    return hit;
}

bool SignatureDb::isFamilyRepairable(const QString &family) const
{
    if (m_jsonFallback) return isFamilyRepairableJson(family);

    if (!m_db.isOpen() || family.isEmpty()) return false;
    QSqlQuery q(m_db);
    q.prepare("SELECT COUNT(*) FROM signatures WHERE LOWER(family) = ? AND repairable = 1");
    q.bindValue(0, family.toLower());
    if (q.exec() && q.next())
        return q.value(0).toInt() > 0;
    return false;
}

QList<ByteSig> SignatureDb::loadByteSignatures() const
{
    QList<ByteSig> result;
    if (m_jsonFallback) {
        for (const auto &v : m_jsonEntries) {
            const QJsonObject o = v.toObject();
            const QJsonValue bsJv = o.value("byte_signatures");
            QStringList patList;
            if (bsJv.isArray()) {
                for (const auto &bv : bsJv.toArray())
                    patList << bv.toString();
            } else {
                const QString patStr = bsJv.toString();
                if (!patStr.isEmpty())
                    patList = patStr.split(',', Qt::SkipEmptyParts);
            }
            for (const QString &pat : patList) {
                ByteSig bs;
                bs.pattern      = pat.trimmed().toUpper();
                bs.name         = o.value("name").toString();
                bs.family       = o.value("family").toString();
                bs.severity     = o.value("severity").toInt(5);
                bs.repairable   = o.value("repairable").toBool(false);
                bs.repairMethod = o.value("repair_method").toString();
                bs.entryPatch   = o.value("entry_point_patch").toString();
                if (!bs.pattern.isEmpty())
                    result.append(bs);
            }
        }
        return result;
    }

    if (!m_db.isOpen()) return result;

    QSqlQuery q(m_db);
    q.exec("SELECT byte_signatures, name, family, severity, repairable, repair_method, entry_point_patch "
           "FROM signatures WHERE byte_signatures IS NOT NULL AND byte_signatures != ''");
    while (q.next()) {
        const QString patterns = q.value(0).toString();
        const QStringList patList = patterns.split(',', Qt::SkipEmptyParts);
        for (const QString &pat : patList) {
            ByteSig bs;
            bs.pattern      = pat.trimmed().toUpper();
            bs.name         = q.value(1).toString();
            bs.family       = q.value(2).toString();
            bs.severity     = q.value(3).toInt();
            bs.repairable   = q.value(4).toInt() != 0;
            bs.repairMethod = q.value(5).toString();
            bs.entryPatch   = q.value(6).toString();
            if (!bs.pattern.isEmpty())
                result.append(bs);
        }
    }
    return result;
}

bool SignatureDb::matchByteSignature(const uchar *data, qint64 size,
                                      const QList<ByteSig> &sigs, ByteSig &matched) const
{
    if (!data || size <= 0) return false;

    for (const ByteSig &bs : sigs) {
        const QString &pat = bs.pattern;
        if (pat.length() < 2) continue;

        QByteArray patBytes;
        QByteArray patMask;
        for (int i = 0; i + 1 < pat.length(); i += 2) {
            const QChar c1 = pat[i], c2 = pat[i+1];
            if (c1 == '?' || c2 == '?') {
                patBytes.append(char(0));
                patMask.append(char(0));
            } else {
                bool ok;
                const int b = pat.mid(i, 2).toInt(&ok, 16);
                if (!ok) break;
                patBytes.append(char(b));
                patMask.append(char(1));
            }
        }
        if (patBytes.isEmpty()) continue;

        const int patLen = patBytes.size();
        const qint64 scanLimit = qMin(size, qint64(65536));
        for (qint64 off = 0; off + patLen <= scanLimit; ++off) {
            bool found = true;
            for (int j = 0; j < patLen; ++j) {
                if (patMask[j] && data[off + j] != uchar(patBytes[j])) {
                    found = false;
                    break;
                }
            }
            if (found) {
                matched = bs;
                return true;
            }
        }
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════
//  Seed Import & Sync (SQLite mode)
// ═══════════════════════════════════════════════════════════════════
int SignatureDb::importSeedJson(const QString &qrcPath)
{
    if (m_jsonFallback) return syncSeedToJson(qrcPath);

    QFile f(qrcPath);
    if (!f.open(QIODevice::ReadOnly)) {
        qDebug() << "SignatureDb: Failed to open embedded resource file:" << qrcPath;
        return 0;
    }

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &err);
    if (doc.isNull() || !doc.isObject()) {
        qDebug() << "SignatureDb: JSON parsing error:" << err.errorString();
        return 0;
    }

    const QJsonArray entries = doc.object().value("entries").toArray();
    int added = 0;

    QSqlQuery q(m_db);
    m_db.transaction();

    q.prepare("INSERT OR REPLACE INTO signatures "
              "(sha256, name, family, severity, first_seen, source, repairable, repair_method, byte_signatures, entry_point_patch) "
              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

    const qint64 now = QDateTime::currentSecsSinceEpoch();
    for (const auto &v : entries) {
        const QJsonObject o = v.toObject();
        QString rawHash = o.value("sha256").toString().toLower().trimmed();

        if (rawHash.length() != 64) {
            qDebug() << "SignatureDb: Skipping malformed hash entry for" << o.value("name").toString() << "Length:" << rawHash.length();
            continue;
        }

        q.bindValue(0, rawHash);
        q.bindValue(1, o.value("name").toString());
        q.bindValue(2, o.value("family").toString());
        q.bindValue(3, o.value("severity").toInt(5));
        q.bindValue(4, now);
        q.bindValue(5, o.value("source").toString("seed"));
        q.bindValue(6, o.value("repairable").toBool(false) ? 1 : 0);
        q.bindValue(7, o.value("repair_method").toString());
        const QJsonValue bsJsonVal = o.value("byte_signatures");
        QString bsStr;
        if (bsJsonVal.isArray()) {
            QStringList sl;
            for (const auto &bv : bsJsonVal.toArray())
                sl << bv.toString();
            bsStr = sl.join(",");
        } else {
            bsStr = bsJsonVal.toString();
        }
        q.bindValue(8, bsStr);
        q.bindValue(9, o.value("entry_point_patch").toString());

        if (q.exec()) {
            ++added;
        } else {
            qDebug() << "SignatureDb: SQL insertion execution failed:" << q.lastError().text();
        }
    }
    m_db.commit();

    qDebug() << "SignatureDb: Dynamic verification complete. Seeded total of" << added << "signatures into SQLite store.";
    return added;
}

int SignatureDb::syncSeedToDb(const QString &qrcPath)
{
    return importSeedJson(qrcPath);
}

// ═══════════════════════════════════════════════════════════════════
//  Metadata & History
// ═══════════════════════════════════════════════════════════════════
int SignatureDb::totalSignatures() const
{
    if (m_jsonFallback) return m_jsonEntries.size();
    if (!m_db.isOpen()) return 0;
    QSqlQuery q(m_db);
    if (q.exec("SELECT COUNT(*) FROM signatures") && q.next())
        return q.value(0).toInt();
    return 0;
}

SignatureStatus SignatureDb::status() const
{
    if (m_isUpdating) {
        return SignatureStatus::UPDATE_IN_PROGRESS;
    }
    const QString iso = lastUpdate();
    if (iso.isEmpty()) {
        return SignatureStatus::UPDATE_REQUIRED;
    }
    QDateTime dt = QDateTime::fromString(iso, Qt::ISODate);
    if (!dt.isValid()) {
        return SignatureStatus::UPDATE_REQUIRED;
    }
    qint64 daysOld = dt.daysTo(QDateTime::currentDateTime());
    if (daysOld < 0) {
        return SignatureStatus::UP_TO_DATE;
    }
    if (daysOld <= 7) {
        return SignatureStatus::UP_TO_DATE;
    }
    if (daysOld <= 30) {
        return SignatureStatus::OUT_OF_DATE;
    }
    return SignatureStatus::UPDATE_REQUIRED;
}

QString SignatureDb::statusString() const
{
    switch (status()) {
    case SignatureStatus::UP_TO_DATE:
        return QStringLiteral("UP_TO_DATE");
    case SignatureStatus::OUT_OF_DATE:
        return QStringLiteral("OUT_OF_DATE");
    case SignatureStatus::UPDATE_REQUIRED:
        return QStringLiteral("UPDATE_REQUIRED");
    case SignatureStatus::UPDATE_IN_PROGRESS:
        return QStringLiteral("UPDATE_IN_PROGRESS");
    case SignatureStatus::UPDATE_FAILED:
        return QStringLiteral("UPDATE_FAILED");
    }
    return QStringLiteral("UNKNOWN");
}

QString SignatureDb::lastUpdate() const {
    if (m_jsonFallback) return QSettings().value("db/last_update").toString();
    return getMeta("last_update");
}

void SignatureDb::setLastUpdate(const QString &iso) {
    if (m_jsonFallback) {
        QSettings().setValue("db/last_update", iso);
    } else {
        setMeta("last_update", iso);
    }
}

QString SignatureDb::getMeta(const QString &key) const
{
    if (m_jsonFallback || !m_db.isOpen()) return {};
    QSqlQuery q(m_db);
    q.prepare("SELECT value FROM settings WHERE key = ?");
    q.bindValue(0, key);
    if (q.exec() && q.next()) return q.value(0).toString();
    return {};
}

void SignatureDb::setMeta(const QString &key, const QString &value)
{
    if (m_jsonFallback || !m_db.isOpen()) return;
    QSqlQuery q(m_db);
    q.prepare("INSERT INTO settings (key, value) VALUES (?, ?) "
              "ON CONFLICT(key) DO UPDATE SET value = excluded.value");
    q.bindValue(0, key);
    q.bindValue(1, value);
    q.exec();
}

void SignatureDb::pushHistory(qint64 startedAt, qint64 finishedAt,
                              int filesScanned, int threatsFound,
                              const QString &reportJson)
{
    if (m_jsonFallback || !m_db.isOpen()) return;
    QSqlQuery q(m_db);
    q.prepare("INSERT INTO scan_history "
              "(started_at, finished_at, files_scanned, threats_found, report_json) "
              "VALUES (?, ?, ?, ?, ?)");
    q.bindValue(0, startedAt);
    q.bindValue(1, finishedAt);
    q.bindValue(2, filesScanned);
    q.bindValue(3, threatsFound);
    q.bindValue(4, reportJson);
    q.exec();
}

SignatureDb::LastScanInfo SignatureDb::lastScanInfo() const
{
    LastScanInfo info;
    if (m_jsonFallback || !m_db.isOpen()) return info;
    QSqlQuery q(m_db);
    if (q.exec("SELECT finished_at, files_scanned, threats_found FROM scan_history ORDER BY id DESC LIMIT 1") && q.next()) {
        info.finishedAt = q.value(0).toLongLong();
        info.filesScanned = q.value(1).toInt();
        info.threatsFound = q.value(2).toInt();
    }
    return info;
}

// ═══════════════════════════════════════════════════════════════════
//  Online Update (works with both DB and JSON fallback)
// ═══════════════════════════════════════════════════════════════════
void SignatureDb::updateOnline(const QString &baseUrl)
{
    m_isUpdating = true;
    emit statusChanged(SignatureStatus::UPDATE_IN_PROGRESS);

    if (!m_nam) m_nam = new QNetworkAccessManager(this);

    QString finalUrl = baseUrl;
    if (!finalUrl.contains(QLatin1Char('?'))) {
        finalUrl += QStringLiteral("?t=%1").arg(QDateTime::currentMSecsSinceEpoch());
    } else {
        finalUrl += QStringLiteral("&t=%1").arg(QDateTime::currentMSecsSinceEpoch());
    }

    QNetworkRequest req((QUrl(finalUrl)));
    req.setHeader(QNetworkRequest::UserAgentHeader,
                  QStringLiteral("%1/%2").arg(APP_NAME).arg(APP_VERSION_STR));
    req.setRawHeader("Accept", "application/json");

    QNetworkReply *r = m_nam->get(req);

    QTimer *to = new QTimer(this);
    to->setSingleShot(true);
    to->setInterval(30000);
    connect(to, &QTimer::timeout, r, &QNetworkReply::abort);
    to->start();

    connect(r, &QNetworkReply::downloadProgress, this,
            [this](qint64 rec, qint64 tot){
                if (tot > 0) emit updateProgress(int((rec * 100) / tot));
            });

    connect(r, &QNetworkReply::finished, this, [this, r, to]{
        to->stop(); to->deleteLater();
        const QByteArray body = r->readAll();
        const QString err = r->error() == QNetworkReply::NoError
                                ? QString() : r->errorString();
        r->deleteLater();

        if (!err.isEmpty()) {
            m_isUpdating = false;
            Logger::warn(QStringLiteral("Signature update failed: %1").arg(err));
            emit statusChanged(SignatureStatus::UPDATE_FAILED);
            emit updateFinished(0, totalSignatures(), err);
            return;
        }

        QJsonParseError jerr{};
        const QJsonDocument doc = QJsonDocument::fromJson(body, &jerr);
        if (doc.isNull() || !doc.isObject()) {
            m_isUpdating = false;
            emit statusChanged(SignatureStatus::UPDATE_FAILED);
            emit updateFinished(0, totalSignatures(), "Bad JSON");
            return;
        }

        const QJsonObject rootObj = doc.object();

        QSettings settings;
        if (rootObj.contains(QStringLiteral("schema_version"))) {
            settings.setValue(QStringLiteral("db/schema_version"), rootObj.value("schema_version").toInt());
        }
        if (rootObj.contains(QStringLiteral("generated_at"))) {
            settings.setValue(QStringLiteral("db/generated_at"), rootObj.value("generated_at").toString());
        }

        const QJsonArray entries = rootObj.value("entries").toArray();

        if (m_jsonFallback) {
            // JSON mode: merge into in-memory cache + save to file
            const int before = m_jsonEntries.size();
            mergeJsonEntries(entries);
            const int added = m_jsonEntries.size() - before;
            setLastUpdate(QDateTime::currentDateTime().toString(Qt::ISODate));
            emit updateFinished(added, m_jsonEntries.size(), QString());
            return;
        }

        // SQLite mode: smart merge
        int added = 0;
        QSqlQuery q(m_db);
        m_db.transaction();

        q.prepare("INSERT OR REPLACE INTO signatures "
                  "(sha256, name, family, severity, first_seen, source, repairable, repair_method, byte_signatures, entry_point_patch) "
                  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

        const qint64 now = QDateTime::currentSecsSinceEpoch();
        for (const auto &v : entries) {
            const QJsonObject o = v.toObject();
            QString rawHash = o.value("sha256").toString().toLower().trimmed();
            if (rawHash.length() != 64) continue;

            q.bindValue(0, rawHash);
            q.bindValue(1, o.value("name").toString());
            q.bindValue(2, o.value("family").toString());
            q.bindValue(3, o.value("severity").toInt(5));
            q.bindValue(4, now);
            q.bindValue(5, o.value("source").toString("online"));
            q.bindValue(6, o.value("repairable").toBool(false) ? 1 : 0);
            q.bindValue(7, o.value("repair_method").toString());

            const QJsonValue bsJv = o.value("byte_signatures");
            QString bsStr;
            if (bsJv.isArray()) {
                QStringList sl;
                for (const auto &bv : bsJv.toArray())
                    sl << bv.toString();
                bsStr = sl.join(",");
            } else {
                bsStr = bsJv.toString();
            }
            q.bindValue(8, bsStr);
            q.bindValue(9, o.value("entry_point_patch").toString());

            if (q.exec()) ++added;
        }
        m_db.commit();

        setLastUpdate(QDateTime::currentDateTime().toString(Qt::ISODate));
        m_isUpdating = false;
        emit statusChanged(SignatureStatus::UP_TO_DATE);
        emit updateFinished(added, totalSignatures(), QString());
    });
}


} // namespace verax
