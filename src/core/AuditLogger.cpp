#include "AuditLogger.h"
#include "Logger.h"

#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QDir>
#include <QDateTime>

namespace verax {

AuditLogger& AuditLogger::instance()
{
    static AuditLogger s;
    return s;
}

AuditLogger::AuditLogger(QObject *parent)
    : QObject(parent)
{
    initDb();
}

void AuditLogger::initDb()
{
    const QString dbDir = Logger::userDataDir() + QStringLiteral("/db");
    QDir().mkpath(dbDir);
    const QString dbPath = dbDir + QStringLiteral("/audit.sqlite");

    QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), QStringLiteral("AuditLoggerConnection"));
    db.setDatabaseName(dbPath);

    if (db.open()) {
        QSqlQuery q(db);
        q.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS audit_log ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  timestamp TEXT NOT NULL,"
            "  type TEXT NOT NULL,"
            "  description TEXT NOT NULL,"
            "  details TEXT,"
            "  severity INTEGER NOT NULL"
            ");"
        ));
        q.exec(QStringLiteral("PRAGMA journal_mode = WAL;"));
    } else {
        Logger::error(QStringLiteral("AuditLogger: Failed to open DB: %1").arg(db.lastError().text()));
    }
}

void AuditLogger::logEvent(const QString &type, const QString &description,
                           const QString &details, int severity)
{
    AuditEvent ev;
    ev.timestamp   = QDateTime::currentDateTime();
    ev.type        = type;
    ev.description = description;
    ev.details     = details;
    ev.severity    = severity;

    QSqlDatabase db = QSqlDatabase::database(QStringLiteral("AuditLoggerConnection"));
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.prepare(QStringLiteral(
            "INSERT INTO audit_log (timestamp, type, description, details, severity) "
            "VALUES (:ts, :type, :desc, :details, :sev);"
        ));
        q.bindValue(QStringLiteral(":ts"),      ev.timestamp.toString(Qt::ISODate));
        q.bindValue(QStringLiteral(":type"),    type);
        q.bindValue(QStringLiteral(":desc"),    description);
        q.bindValue(QStringLiteral(":details"), details);
        q.bindValue(QStringLiteral(":sev"),     severity);
        if (q.exec()) {
            ev.id = q.lastInsertId().toLongLong();
        }
    }

    m_memoryCache.prepend(ev);
    if (m_memoryCache.size() > 500) {
        m_memoryCache.removeLast();
    }

    emit eventLogged(ev);
}

QVector<AuditEvent> AuditLogger::recentEvents(int limit) const
{
    QVector<AuditEvent> list;
    QSqlDatabase db = QSqlDatabase::database(QStringLiteral("AuditLoggerConnection"));
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.prepare(QStringLiteral(
            "SELECT id, timestamp, type, description, details, severity "
            "FROM audit_log ORDER BY id DESC LIMIT :lim;"
        ));
        q.bindValue(QStringLiteral(":lim"), limit);
        if (q.exec()) {
            while (q.next()) {
                AuditEvent ev;
                ev.id          = q.value(0).toLongLong();
                ev.timestamp   = QDateTime::fromString(q.value(1).toString(), Qt::ISODate);
                ev.type        = q.value(2).toString();
                ev.description = q.value(3).toString();
                ev.details     = q.value(4).toString();
                ev.severity    = q.value(5).toInt();
                list.append(ev);
            }
            return list;
        }
    }
    return m_memoryCache.mid(0, limit);
}

void AuditLogger::clearLog()
{
    m_memoryCache.clear();
    QSqlDatabase db = QSqlDatabase::database(QStringLiteral("AuditLoggerConnection"));
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.exec(QStringLiteral("DELETE FROM audit_log;"));
        q.exec(QStringLiteral("VACUUM;"));
    }
}

} // namespace verax
