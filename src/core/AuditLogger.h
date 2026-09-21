#pragma once

#include <QString>
#include <QDateTime>
#include <QVector>
#include <QObject>

namespace verax {

struct AuditEvent {
    qint64    id = 0;
    QDateTime timestamp;
    QString   type;        // "Scan", "ThreatBlocked", "RansomwareBlocked", "UsbEvent", "Cleaned"
    QString   description;
    QString   details;
    int       severity = 0;// 0=Info, 1=Success, 2=Warn, 3=Critical
};

class AuditLogger : public QObject {
    Q_OBJECT

public:
    static AuditLogger& instance();

    void logEvent(const QString &type, const QString &description,
                  const QString &details = QString(), int severity = 0);

    QVector<AuditEvent> recentEvents(int limit = 100) const;
    void clearLog();

signals:
    void eventLogged(const AuditEvent &event);

private:
    explicit AuditLogger(QObject *parent = nullptr);
    ~AuditLogger() override = default;

    void initDb();

    mutable QVector<AuditEvent> m_memoryCache;
};

} // namespace verax
