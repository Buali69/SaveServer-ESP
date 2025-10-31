#include "hmacauth.h"

// unsere zentralen Helper (header-only)
#include "../common/crypto_helpers.h"

#include <QDateTime>

HmacAuth::HmacAuth(QByteArray sharedSecret)
    : secret(std::move(sharedSecret)) {}

// Canonical String exakt wie in deinem Header beschrieben:
//
// deviceId=<id>\n
// ts=<timestamp>\n
// nonce=<nonce>\n
// body=<raw json>
QByteArray HmacAuth::canonical(const QString& deviceId,
                               qint64 ts,
                               const QString& nonce,
                               const QByteArray& body)
{
    QByteArray c;
    c += "deviceId="; c += deviceId.toUtf8();   c += '\n';
    c += "ts=";       c += QByteArray::number(ts); c += '\n';
    c += "nonce=";    c += nonce.toUtf8();      c += '\n';
    c += "body=";     c += body;                // unverändert (genau die empfangenen Bytes!)
    return c;
}

// HMAC-SHA256 – Wrapper auf unsere Qt-Helper
QByteArray HmacAuth::hmacSha256(const QByteArray& key, const QByteArray& data)
{
    return crypto::hmacSha256(key, data);
}

bool HmacAuth::verify(const QString& deviceId,
                      qint64 xTimestamp,
                      const QString& nonce,
                      const QByteArray& rawBody,
                      const QByteArray& providedSignatureB64Url,
                      QString* err) const
{
    // 1) Zeitfenster prüfen (±120 s)
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    if (qAbs(now - xTimestamp) > 120) {
        if (err) *err = QStringLiteral("timestamp_skew");
        return false;
    }

    // 2) Canonical-String bilden (muss bytegenau mit Sender übereinstimmen)
    const QByteArray canon = canonical(deviceId, xTimestamp, nonce, rawBody);

    // 3) Erwarteten MAC berechnen und Base64URL-kodieren (ohne '=')
    const QByteArray mac    = crypto::hmacSha256(secret, canon);
    const QByteArray macB64 = crypto::b64url(mac);

    // 4) Timing-sicher vergleichen
    if (!crypto::bytesEqualCT(macB64, providedSignatureB64Url)) {
        if (err) *err = QStringLiteral("bad_signature");
        return false;
    }

    // Hinweis: Replay-Schutz (Nonce in DB speichern/prüfen) gehört in den Aufrufer,
    // z. B. via Storage::insertNonce(deviceId, nonce, xTimestamp).

    return true;
}
