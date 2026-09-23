#pragma once

#include <QObject>
#include <QString>
#include <QStringList>

namespace verax {

class WebShield : public QObject {
    Q_OBJECT
public:
    static WebShield& instance();

    bool isEnabled() const;
    bool setEnabled(bool enable);

    bool applyBlocklist();
    bool removeBlocklist();
    bool isProtectionActive() const;
    int  blockedCount() const;

    QStringList defaultMaliciousDomains() const;

signals:
    void statusChanged(bool active);

private:
    explicit WebShield(QObject *parent = nullptr);
    QString hostsFilePath() const;
    bool createBackup(const QString &hostsPath) const;
};

} // namespace verax
