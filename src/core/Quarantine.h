// Quarantine.h - AES-256-CBC vault + secure delete + restoration ledger
// By Ali Sakkaf - https://alisakkaf.com
#pragma once
#include <QObject>
#include <QMutex>
#include <QString>
#include <QVector>

namespace verax {

struct QuarantineEntry {
    int     id = 0;
    QString originalPath;
    QString vaultPath;
    QString sha256;
    QString detectionName;
    qint64  size = 0;
    qint64  quarantinedAt = 0;
    bool    restoreBlocked = false;
};

class Quarantine : public QObject {
    Q_OBJECT
public:
    static Quarantine& instance();

    // Returns vaultPath on success, empty string on failure.
    QString moveToVault(const QString &originalPath,
                        const QString &sha256,
                        const QString &detectionName);

    bool   restore(int entryId);
    bool   permanentDelete(int entryId);
    bool   secureDelete(const QString &path) const;

    QVector<QuarantineEntry> list() const;
    int     count() const;
    qint64  totalBytes() const;

signals:
    void changed();
    void itemAdded(QuarantineEntry e);

private:
    mutable QMutex m_mutex;
    explicit Quarantine(QObject *parent = nullptr);
    QString vaultDir() const;
    QByteArray deriveKey() const;
    QByteArray hwid() const;
    bool aesCbcEncryptFile(const QString &src, const QString &dst,
                           const QByteArray &key) const;
    bool aesCbcDecryptFile(const QString &src, const QString &dst,
                           const QByteArray &key) const;
};

} // namespace verax
