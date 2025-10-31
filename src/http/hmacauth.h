#pragma once
#include <QString>
#include <QByteArray>

/**
 * @brief Prüft HMAC-SHA256-Signaturen für REST-Sensor-Requests.
 *
 * Verwendet wird:
 *  canonical string:
 *    deviceId=<id>\n
 *    ts=<timestamp>\n
 *    nonce=<nonce>\n
 *    body=<json>
 */
class HmacAuth {
public:
    explicit HmacAuth(QByteArray sharedSecret);

    // Prüft Zeitfenster ±120 s, Nonce (optional) und HMAC-Signatur
    bool verify(const QString& deviceId,
                qint64 xTimestamp,
                const QString& nonce,
                const QByteArray& rawBody,
                const QByteArray& providedSignatureB64Url,
                QString* err = nullptr) const;

    static QByteArray canonical(const QString& deviceId,
                                qint64 ts,
                                const QString& nonce,
                                const QByteArray& body);

    static QByteArray hmacSha256(const QByteArray& key, const QByteArray& data);

private:
    QByteArray secret;
};
