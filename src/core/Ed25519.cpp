#include "Ed25519.h"
#include <vector>

extern "C" {
#include "tweetnacl.h"
void randombytes(unsigned char *, unsigned long long) {}
}

namespace verax {

bool Ed25519::verify(const QByteArray &message,
                     const QByteArray &signature,
                     const QByteArray &publicKey)
{
    if (signature.size() != SignatureSize || publicKey.size() != PublicKeySize) {
        return false;
    }

    size_t mlen = static_cast<size_t>(message.size());
    size_t smlen = static_cast<size_t>(SignatureSize) + mlen;

    std::vector<unsigned char> sm(smlen);
    memcpy(sm.data(), signature.constData(), SignatureSize);
    if (mlen > 0) {
        memcpy(sm.data() + SignatureSize, message.constData(), mlen);
    }

    std::vector<unsigned char> mOut(smlen);
    unsigned long long mlenOut = 0;

    int ret = crypto_sign_open(mOut.data(),
                               &mlenOut,
                               sm.data(),
                               static_cast<unsigned long long>(smlen),
                               reinterpret_cast<const unsigned char*>(publicKey.constData()));

    return (ret == 0 && mlenOut == mlen);
}

QByteArray Ed25519::base64UrlDecode(const QString &str)
{
    QString s = str.trimmed();
    s.replace('-', '+');
    s.replace('_', '/');
    while (s.size() % 4 != 0) {
        s.append('=');
    }
    return QByteArray::fromBase64(s.toLatin1());
}

QString Ed25519::base64UrlEncode(const QByteArray &data)
{
    QByteArray b64 = data.toBase64();
    QString s = QString::fromLatin1(b64);
    s.replace('+', '-');
    s.replace('/', '_');
    while (s.endsWith('=')) {
        s.chop(1);
    }
    return s;
}

QByteArray Ed25519::publicKeyFromHex(const QString &hexStr)
{
    return QByteArray::fromHex(hexStr.trimmed().toLatin1());
}

} // namespace verax
