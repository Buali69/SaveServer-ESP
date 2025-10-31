#pragma once
#include <QByteArray>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>

namespace crypto {

// Base64URL ohne '='
inline QByteArray b64url(const QByteArray& bin) {
    return bin.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

// SHA-256 Digest
inline QByteArray sha256(const QByteArray& d) {
    return QCryptographicHash::hash(d, QCryptographicHash::Sha256);
}


// Timing-sicherer Vergleich zweier Bytearrays
inline bool bytesEqualCT(const QByteArray& a, const QByteArray& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    const int n = a.size();
    const unsigned char* pa = reinterpret_cast<const unsigned char*>(a.constData());
    const unsigned char* pb = reinterpret_cast<const unsigned char*>(b.constData());
    for (int i = 0; i < n; ++i) diff |= (pa[i] ^ pb[i]);
    return diff == 0;
}

// HMAC-SHA256
inline QByteArray hmacSha256(const QByteArray& key, const QByteArray& msg) {
    return QMessageAuthenticationCode::hash(msg, key, QCryptographicHash::Sha256);
}

inline QByteArray b64url_decode(const QByteArray& sIn) {
    QByteArray s = sIn;
    // URL Alphabet zurückwandeln
    s.replace('-', '+');
    s.replace('_', '/');
    // Padding auffüllen
    while (s.size() % 4) s.append('=');
    return QByteArray::fromBase64(s);
}

// PBKDF2-HMAC-SHA256 (RFC 8018), Standard dkLen=32
inline QByteArray pbkdf2HmacSha256(const QByteArray& password,
                                   const QByteArray& salt,
                                   int iterations,
                                   int dkLen = 32)
{
    const int hLen = 32;
    const int blocks = (dkLen + hLen - 1) / hLen;

    QByteArray out; out.reserve(blocks * hLen);

    for (int i = 1; i <= blocks; ++i) {
        QByteArray saltBlock = salt;
        saltBlock.append(char((i >> 24) & 0xFF));
        saltBlock.append(char((i >> 16) & 0xFF));
        saltBlock.append(char((i >>  8) & 0xFF));
        saltBlock.append(char((i >>  0) & 0xFF));

        QByteArray u = hmacSha256(password, saltBlock); // U1
        QByteArray t = u;                                // T = U1

        for (int j = 2; j <= iterations; ++j) {
            u = hmacSha256(password, u);                // Uj = PRF(P, Uj-1)
            for (int k = 0; k < hLen; ++k)
                t[k] = t[k] ^ u[k];                     // T ^= Uj
        }

        out.append(t);
    }

    out.truncate(dkLen);
    return out;
}

// Einfaches 16-Byte-Salt
inline QByteArray genSalt16() {
    QByteArray s(16, Qt::Uninitialized);
    // fülle 16 Bytes zufällig
    QRandomGenerator::global()->generate(
        reinterpret_cast<quint32*>(s.data()),
        reinterpret_cast<quint32*>(s.data()) + (s.size()/4)
        );
    return s;
}

} // namespace crypto
