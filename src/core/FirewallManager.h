#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>

namespace verax {

struct FirewallRuleItem {
    QString name;
    QString direction; // "IN" / "OUT"
    QString action;    // "ALLOW" / "BLOCK"
    QString program;
    QString port;
    bool    enabled = true;
};

struct RealConnectionItem {
    QString processName;
    QString localAddress;
    QString remoteAddress;
    QString state;
    int pid = 0;
};

class FirewallManager : public QObject {
    Q_OBJECT
public:
    static FirewallManager& instance();

    bool isFirewallEnabled();
    bool setFirewallEnabled(bool enable);

    QString activeProfile();
    bool blockInboundTraffic(bool blockAll);

    bool blockPort(int port, const QString &protocol = QStringLiteral("TCP"));
    bool blockApplication(const QString &exePath, const QString &ruleName = QString());
    bool deleteRule(const QString &ruleName);

    QVector<FirewallRuleItem> loadActiveRules();
    QVector<RealConnectionItem> loadActiveConnections();
    bool resetToDefaults();

signals:
    void statusChanged(bool enabled, const QString &profile);
    void ruleAdded(const QString &ruleName, bool success);

private:
    explicit FirewallManager(QObject *parent = nullptr);
    int runNetsh(const QStringList &args);
};

} // namespace verax
