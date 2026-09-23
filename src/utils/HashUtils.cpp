// HashUtils.cpp - SHA256 streaming, CRC32 (IEEE 802.3)
// By Ali Sakkaf - https://alisakkaf.com
#include "HashUtils.h"
#include <QFile>
#include <QCryptographicHash>

namespace verax {

QString HashUtils::sha256Hex(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    QCryptographicHash h(QCryptographicHash::Sha256);
    char buf[65536];
    while (!f.atEnd()) {
        const qint64 n = f.read(buf, sizeof(buf));
        if (n < 0) return {};
        if (n == 0) break;
        h.addData(buf, int(n));
    }
    f.close();
    return QString::fromLatin1(h.result().toHex());
}

QString HashUtils::sha256Hex(const QByteArray &data)
{
    return QString::fromLatin1(
        QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
}

quint32 HashUtils::crc32(const QByteArray &data)
{
    static quint32 table[256];
    static bool inited = false;
    if (!inited) {
        for (quint32 i = 0; i < 256; ++i) {
            quint32 c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? 0xEDB88320 ^ (c >> 1) : (c >> 1);
            table[i] = c;
        }
        inited = true;
    }
    quint32 crc = 0xFFFFFFFFu;
    const uchar *p = reinterpret_cast<const uchar*>(data.constData());
    for (int i = 0; i < data.size(); ++i)
        crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

} // namespace verax
