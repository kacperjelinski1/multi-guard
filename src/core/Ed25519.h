#pragma once

#include <QByteArray>
#include <QString>

namespace verax {

class Ed25519 {
public:
    static constexpr int PublicKeySize = 32;
    static constexpr int SignatureSize = 64;

    // Verifies an Ed25519 signature over message bytes.
    // message: ASCII/binary bytes that were signed
    // signature: 64 bytes raw binary signature
    // publicKey: 32 bytes raw binary public key
    static bool verify(const QByteArray &message,
                       const QByteArray &signature,
                       const QByteArray &publicKey);

    // Helper: decode base64url string to QByteArray
    static QByteArray base64UrlDecode(const QString &str);

    // Helper: encode QByteArray to base64url string (without padding)
    static QString base64UrlEncode(const QByteArray &data);

    // Helper: hex string to 32-byte public key QByteArray
    static QByteArray publicKeyFromHex(const QString &hexStr);
};

} // namespace verax
