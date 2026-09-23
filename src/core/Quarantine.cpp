// Quarantine.cpp - AES-256-CBC vault. Uses Windows CryptoAPI (BCrypt) +
// HWID-derived key from MachineGuid registry value.
// By Ali Sakkaf - https://alisakkaf.com
#include "Quarantine.h"
#include "Logger.h"
#include "SignatureDb.h"
#include "../../Version.h"
#include "qthread.h"

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QSqlError>
#include <QStandardPaths>
#include <QCryptographicHash>
#include <QDateTime>
#include <QSettings>
#include <QRandomGenerator>
#include <QSaveFile>
#include <QTemporaryFile>
#include <QUuid>
#include "../utils/HashUtils.h"

#ifdef _WIN32
#  include <windows.h>
#  include <bcrypt.h>
#  ifndef NT_SUCCESS
#    define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#  endif
#  pragma comment(lib, "bcrypt.lib")
#endif

namespace verax {

Quarantine& Quarantine::instance() {
    static Quarantine q;
    return q;
}

Quarantine::Quarantine(QObject *parent) : QObject(parent) {
    QDir().mkpath(vaultDir());
}

QString Quarantine::vaultDir() const {
    return Logger::userDataDir() + QStringLiteral("/") + APP_VAULT_SUBDIR;
}

QByteArray Quarantine::hwid() const
{
#ifdef _WIN32
    QSettings cr("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
                 QSettings::NativeFormat);
    const QString mg = cr.value("MachineGuid").toString();
    if (!mg.isEmpty()) return mg.toUtf8();
#endif
    // Fallback: a stable per-user salt (weaker - documented in README)
    return QStringLiteral("verax-fallback-hwid").toUtf8();
}

QByteArray Quarantine::deriveKey() const
{
    return QCryptographicHash::hash(hwid() + QByteArrayLiteral("Verax-vault-v1"),
                                    QCryptographicHash::Sha256);
}

#ifdef _WIN32
static bool runAesCbc(bool encrypt, const QByteArray &key,
                      const QByteArray &iv, const QByteArray &in,
                      QByteArray &out)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE kh  = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(st)) return false;

    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                           sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return false; }

    st = BCryptGenerateSymmetricKey(alg, &kh, nullptr, 0,
                                    (PUCHAR)key.constData(), key.size(), 0);
    if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return false; }

    QByteArray ivCopy = iv;
    DWORD got = 0;
    auto crypt = encrypt ? &BCryptEncrypt : &BCryptDecrypt;
    st = crypt(kh, (PUCHAR)in.constData(), in.size(), nullptr,
               (PUCHAR)ivCopy.data(), ivCopy.size(),
               nullptr, 0, &got, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(st)) {
        BCryptDestroyKey(kh);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    out.resize(int(got));
    ivCopy = iv;
    st = crypt(kh, (PUCHAR)in.constData(), in.size(), nullptr,
               (PUCHAR)ivCopy.data(), ivCopy.size(),
               (PUCHAR)out.data(), got, &got, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(kh);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (NT_SUCCESS(st)) out.resize(int(got));
    return NT_SUCCESS(st);
}
#endif

bool Quarantine::aesCbcEncryptFile(const QString &src, const QString &dst,
                                   const QByteArray &key) const
{
    QFile in(src);
    if (!in.open(QIODevice::ReadOnly)) return false;
    const QByteArray plain = in.readAll();
    if (in.error() != QFile::NoError || plain.size() != in.size()) return false;
    in.close();

    QByteArray iv(16, 0);
    for (int i = 0; i < 16; ++i) iv[i] = char(QRandomGenerator::global()->bounded(256));

    QByteArray cipher;
#ifdef _WIN32
    if (!runAesCbc(true, key, iv, plain, cipher)) return false;
#else
    cipher = plain; // fallback (no encryption on non-Windows)
#endif

    QSaveFile out(dst);
    out.setDirectWriteFallback(false);
    if (!out.open(QIODevice::WriteOnly)) return false;
    if (out.write(iv) != iv.size() || out.write(cipher) != cipher.size()) return false;
    return out.commit();
}

bool Quarantine::aesCbcDecryptFile(const QString &src, const QString &dst,
                                   const QByteArray &key) const
{
    QFile in(src);
    if (!in.open(QIODevice::ReadOnly)) return false;
    const QByteArray iv     = in.read(16);
    const QByteArray cipher = in.readAll();
    if (in.error() != QFile::NoError) return false;
    in.close();
    if (iv.size() != 16) return false;

    QByteArray plain;
#ifdef _WIN32
    if (!runAesCbc(false, key, iv, cipher, plain)) return false;
#else
    plain = cipher;
#endif

    QSaveFile out(dst);
    out.setDirectWriteFallback(false);
    if (!out.open(QIODevice::WriteOnly)) return false;
    if (out.write(plain) != plain.size()) return false;
    return out.commit();
}

// Deletion is intentionally not advertised as secure erasure (SSD/COW storage).
bool Quarantine::secureDelete(const QString &path) const
{
    return !QFileInfo::exists(path) || QFile::remove(path);
}

namespace {
// Keep every connection within the calling thread, including background protection.
QSqlDatabase vaultDatabase()
{
    struct Connection {
        QString name = QStringLiteral("vault-") + QUuid::createUuid().toString();
        ~Connection() { QSqlDatabase::removeDatabase(name); }
    };
    static thread_local Connection connection;
    auto db = QSqlDatabase::contains(connection.name)
        ? QSqlDatabase::database(connection.name)
        : QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connection.name);
    if (!db.isOpen()) {
        db.setDatabaseName(Logger::userDataDir() + QStringLiteral("/db/verax.sqlite"));
        db.setConnectOptions(QStringLiteral("QSQLITE_BUSY_TIMEOUT=5000"));
        db.open();
    }
    return db;
}

bool removeLedgerEntry(QSqlDatabase &db, int id)
{
    QSqlQuery q(db);
    q.prepare("DELETE FROM quarantine WHERE id = ?");
    q.addBindValue(id);
    return q.exec() && q.numRowsAffected() == 1;
}

bool vaultReferenced(QSqlDatabase &db, const QString &path)
{
    QSqlQuery q(db);
    q.prepare("SELECT COUNT(*) FROM quarantine WHERE vault_path = ?");
    q.addBindValue(path);
    return !q.exec() || !q.next() || q.value(0).toInt() != 0;
}
}

QString Quarantine::moveToVault(const QString &originalPath,
                                const QString &expectedHash,
                                const QString &detectionName)
{
    QMutexLocker guard(&m_mutex);
    QFileInfo fi(originalPath);
    if (!fi.isFile() || fi.isSymLink()) return {};
    const QString hash = HashUtils::sha256Hex(originalPath);
    if (hash.isEmpty() || (!expectedHash.isEmpty() && hash.compare(expectedHash, Qt::CaseInsensitive) != 0)) return {};
    auto db = vaultDatabase();
    if (!db.isOpen()) return {};

    const QString vault = vaultDir() + "/" + QUuid::createUuid().toString(QUuid::WithoutBraces) + ".qvault";
    if (!aesCbcEncryptFile(originalPath, vault, deriveKey())) return {};

    // Read the committed encrypted copy back and verify plaintext before touching source.
    QTemporaryFile verification(vaultDir() + "/verify-XXXXXX");
    if (!verification.open()) { QFile::remove(vault); return {}; }
    const QString verifyPath = verification.fileName();
    verification.close();
    if (!aesCbcDecryptFile(vault, verifyPath, deriveKey()) || HashUtils::sha256Hex(verifyPath) != hash) {
        QFile::remove(vault);
        return {};
    }
    if (!db.transaction()) { QFile::remove(vault); return {}; }
    QSqlQuery q(db);
    q.prepare("INSERT INTO quarantine (original_path, vault_path, sha256, detection_name, size, quarantined_at, restore_blocked) VALUES (?, ?, ?, ?, ?, ?, 0)");
    q.addBindValue(fi.absoluteFilePath()); q.addBindValue(vault); q.addBindValue(hash);
    q.addBindValue(detectionName); q.addBindValue(fi.size());
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    q.addBindValue(now);
    if (!q.exec() || !db.commit()) {
        db.rollback(); QFile::remove(vault); return {};
    }
    const int id = q.lastInsertId().toInt();

    // Stage the source on the same filesystem, then verify the exact staged file.
    // A crash after ledger commit leaves a recoverable vault and may leave the source.
    const QString staged = fi.absolutePath() + "/.multiguard-" + QUuid::createUuid().toString(QUuid::WithoutBraces);
    if (!QFile::rename(originalPath, staged)) {
        Logger::warn(QStringLiteral("Vault saved, but source remains: %1").arg(originalPath));
        guard.unlock(); emit changed(); return {};
    }
    if (HashUtils::sha256Hex(staged) != hash || !QFile::remove(staged)) {
        if (!QFile::rename(staged, originalPath))
            Logger::error(QStringLiteral("Source preserved for manual recovery at %1").arg(staged));
        guard.unlock(); emit changed(); return {};
    }
    QuarantineEntry entry;
    entry.id = id; entry.originalPath = fi.absoluteFilePath(); entry.vaultPath = vault;
    entry.sha256 = hash; entry.detectionName = detectionName; entry.size = fi.size(); entry.quarantinedAt = now;
    guard.unlock();
    emit itemAdded(entry); emit changed();
    return vault;
}

bool Quarantine::restore(int entryId)
{
    QMutexLocker guard(&m_mutex);
    auto db = vaultDatabase();
    if (!db.isOpen()) return false;
    QSqlQuery q(db);
    q.prepare("SELECT original_path, vault_path, restore_blocked, sha256 FROM quarantine WHERE id = ?");
    q.addBindValue(entryId);
    if (!q.exec() || !q.next() || q.value(2).toBool()) return false;
    const QString original = q.value(0).toString(), vault = q.value(1).toString(), hash = q.value(3).toString();
    // Legacy entries lacking integrity metadata require manual recovery.
    if (hash.size() != 64 || QFileInfo::exists(original) || QFileInfo(original).isSymLink()) return false;
    if (!QDir().mkpath(QFileInfo(original).absolutePath())) return false;
    QTemporaryFile restored(QFileInfo(original).absolutePath() + "/.restore-XXXXXX");
    if (!restored.open()) return false;
    const QString temporary = restored.fileName();
    restored.close();
    if (!aesCbcDecryptFile(vault, temporary, deriveKey()) || HashUtils::sha256Hex(temporary) != hash) return false;
    if (!QFile::rename(temporary, original)) return false; // Never overwrite a destination.
    if (!db.transaction()) return false; // Both copies remain safe.
    if (!removeLedgerEntry(db, entryId) || !db.commit()) { db.rollback(); return false; }
    if (!vaultReferenced(db, vault)) QFile::remove(vault);
    guard.unlock(); emit changed();
    return true;
}

bool Quarantine::permanentDelete(int entryId)
{
    QMutexLocker guard(&m_mutex);
    auto db = vaultDatabase();
    if (!db.isOpen() || !db.transaction()) return false;
    QSqlQuery q(db);
    q.prepare("SELECT vault_path FROM quarantine WHERE id = ?");
    q.addBindValue(entryId);
    if (!q.exec() || !q.next()) { db.rollback(); return false; }
    const QString vault = q.value(0).toString();
    if (!removeLedgerEntry(db, entryId)) { db.rollback(); return false; }
    // Legacy duplicate rows must not delete another entry's payload.
    if (!vaultReferenced(db, vault) && !secureDelete(vault)) { db.rollback(); return false; }
    if (!db.commit()) { db.rollback(); return false; }
    guard.unlock(); emit changed();
    return true;
}

QVector<QuarantineEntry> Quarantine::list() const
{
    QVector<QuarantineEntry> out;
    QMutexLocker guard(&m_mutex);
    QSqlDatabase db = vaultDatabase();
    if (!db.isOpen()) return out;

    QSqlQuery q(db);
    if (!q.exec("SELECT id, original_path, vault_path, sha256, "
                "       detection_name, size, quarantined_at, restore_blocked "
                "FROM quarantine ORDER BY quarantined_at DESC"))
        return out;

    while (q.next()) {
        QuarantineEntry e;
        e.id             = q.value(0).toInt();
        e.originalPath   = q.value(1).toString();
        e.vaultPath      = q.value(2).toString();
        e.sha256         = q.value(3).toString();
        e.detectionName  = q.value(4).toString();
        e.size           = q.value(5).toLongLong();
        e.quarantinedAt  = q.value(6).toLongLong();
        e.restoreBlocked = q.value(7).toInt() != 0;
        out.append(e);
    }
    return out;
}

int Quarantine::count() const
{
    QMutexLocker guard(&m_mutex);
    QSqlDatabase db = vaultDatabase();
    if (!db.isOpen()) return 0;
    QSqlQuery q(db);
    if (q.exec("SELECT COUNT(*) FROM quarantine") && q.next())
        return q.value(0).toInt();
    return 0;
}

qint64 Quarantine::totalBytes() const
{
    QMutexLocker guard(&m_mutex);
    QSqlDatabase db = vaultDatabase();
    if (!db.isOpen()) return 0;
    QSqlQuery q(db);
    if (q.exec("SELECT COALESCE(SUM(size),0) FROM quarantine") && q.next())
        return q.value(0).toLongLong();
    return 0;
}

} // namespace verax
