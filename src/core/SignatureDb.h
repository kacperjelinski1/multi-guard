// SignatureDb.h - SQLite signature store + JSON fallback + online updater
// By Ali Sakkaf - https://alisakkaf.com
#pragma once
#include <QObject>
#include <QMutex>
#include <QString>
#include <QList>
#include <QSqlDatabase>
#include <QJsonArray>
#include <QJsonObject>
#include <QStandardPaths>
#include <QStandardPaths>
class QNetworkAccessManager;

namespace verax {

struct SigHit {
    QString name;
    QString family;
    int     severity = 5;
    bool    repairable = false;
    QString repairMethod;
    QString entryPointPatch;
};

// Byte signature for in-memory pattern matching (loaded from DB)
struct ByteSig {
    QString pattern;       // hex string with ?? wildcards e.g. "E9????????"
    QString name;
    QString family;
    int     severity = 5;
    bool    repairable = false;
    QString repairMethod;
    QString entryPatch;    // original prologue bytes hex e.g. "558BEC"
};

enum class SignatureStatus {
    UP_TO_DATE,
    OUT_OF_DATE,
    UPDATE_REQUIRED,
    UPDATE_IN_PROGRESS,
    UPDATE_FAILED
};

class SignatureDb : public QObject {
    Q_OBJECT
public:
    static SignatureDb& instance();

    bool    open();
    void    close();
    bool    isOpen() const;
    bool    isJsonFallback() const { return m_jsonFallback; }

    // Status bazy sygnatur
    SignatureStatus status() const;
    QString         statusString() const;

    // Schema bootstrap + seed import (works with both DB and JSON)
    bool    initSchema();
    int     importSeedJson(const QString &qrcPath = QStringLiteral(":/signatures/seed.json"));

    // Query: returns valid SigHit if hash known-bad
    SigHit  lookup(const QString &sha256Hex) const;

    // Byte-signature matching: scans raw bytes against loaded byte patterns
    QList<ByteSig> loadByteSignatures() const;
    bool    matchByteSignature(const uchar *data, qint64 size,
                               const QList<ByteSig> &sigs, ByteSig &matched) const;
    SigHit  lookupByFamily(const QString &family) const;

    // Check if a family is repairable
    bool    isFamilyRepairable(const QString &family) const;

    // Counts + metadata
    int     totalSignatures() const;
    QString lastUpdate() const;
    void    setLastUpdate(const QString &iso);

    // Async network update; emits finished(added, total).
    void    updateOnline(const QString &url);

    // Sync seed.json to user DB/JSON: adds only entries not already present
    int     syncSeedToDb(const QString &qrcPath = QStringLiteral(":/signatures/seed.json"));

    // Generic key/value store on the "settings" table
    QString getMeta(const QString &key) const;
    void    setMeta(const QString &key, const QString &value);

    // Scan history
    void    pushHistory(qint64 startedAt, qint64 finishedAt,
                        int filesScanned, int threatsFound,
                        const QString &reportJson);

    struct LastScanInfo {
        qint64 finishedAt = 0;
        int filesScanned = 0;
        int threatsFound = 0;
    };
    LastScanInfo lastScanInfo() const;

signals:
    void updateProgress(int pct);
    void updateFinished(int added, int total, const QString &error);
    void statusChanged(verax::SignatureStatus newStatus);

private:
    explicit SignatureDb(QObject *parent = nullptr);
    void    migrateSchema();

    // JSON fallback methods (when SQLite is unavailable)
    bool    initJsonFallback();
    int     syncSeedToJson(const QString &qrcPath);
    SigHit  lookupJson(const QString &sha256Hex) const;
    SigHit  lookupByFamilyJson(const QString &family) const;
    bool    isFamilyRepairableJson(const QString &family) const;
    void    saveJsonCache() const;
    void    mergeJsonEntries(const QJsonArray &newEntries);

    QSqlDatabase currentDatabase() const;
    mutable QMutex m_mutex{QMutex::Recursive};
    QSqlDatabase  m_db;
    QString       m_path;
    QNetworkAccessManager *m_nam = nullptr;

    // JSON fallback state
    bool          m_jsonFallback = false;
    QString       m_jsonPath;
    QJsonArray    m_jsonEntries;      // in-memory cache
    bool          m_isUpdating = false;
};

} // namespace verax
