// Repair.h - hosts + VC++ redist + DLL check + Defender excl + Firewall + drivers
// By Ali Sakkaf - https://alisakkaf.com
#pragma once
#include <QObject>
#include <QString>
#include <QStringList>

namespace verax {

enum class RepairStatus {
    Unknown = 0,
    Ok,
    Missing,
    Bad,
    Working
};

class Repair : public QObject {
    Q_OBJECT
public:
    static Repair& instance();

    // Probes (synchronous, fast). Each returns RepairStatus.
    RepairStatus checkVcRedist();
    RepairStatus checkHosts();
    RepairStatus checkCryptoServices();
    RepairStatus checkPhoneDrivers();

    // Actions (async; emit fix*Finished signals).
    void fixVcRedist();
    void fixHosts();
    void fixCryptoServices();
    void fixPhoneDrivers(const QString &infFolder);

    // DLL check against user-supplied known-good map (app -> dll -> sha256)
    QStringList checkAppDlls(const QString &appFolder,
                             const QMap<QString,QString> &knownGood);

    // Master "fix all" runner
    void fixAll();

signals:
    void progress(const QString &card, int pct, const QString &message);
    void cardStatus(const QString &card, RepairStatus s);
    void finished(const QString &card, bool ok, const QString &message);

private:
    explicit Repair(QObject *parent = nullptr);
    int  runProcess(const QString &exe, const QStringList &args,
                    int timeoutMs = 30000);
    bool downloadFile(const QString &url, const QString &dst,
                      int timeoutMs = 60000);
    QString tempDir() const;
};

} // namespace verax
