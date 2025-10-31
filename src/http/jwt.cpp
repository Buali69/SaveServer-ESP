#include "Jwt.h"
#include <QDateTime>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>

Jwt::Jwt(const QByteArray& secret) : secretKey(secret) {}

QString Jwt::sign(const QJsonObject& claims, int expiresSec) const {
    QJsonObject header;
    header["alg"] = "HS256";
    header["typ"] = "JWT";

    QJsonObject payload = claims;
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    payload["iat"] = now;
    payload["exp"] = now + expiresSec;

    const QByteArray headerB64  = base64UrlEncode(QJsonDocument(header).toJson(QJsonDocument::Compact));
    const QByteArray payloadB64 = base64UrlEncode(QJsonDocument(payload).toJson(QJsonDocument::Compact));
    const QByteArray signingInput = headerB64 + "." + payloadB64;

    // HS256 = HMAC-SHA256(signingInput, secretKey)
    const QByteArray mac   = QMessageAuthenticationCode::hash(signingInput, secretKey, QCryptographicHash::Sha256);
    const QByteArray sigB64 = base64UrlEncode(mac);

    return signingInput + "." + sigB64;
}

QJsonObject Jwt::verify(const QString& token) const {
    const QStringList parts = token.split('.');
    if (parts.size() != 3) return {};

    const QByteArray headerB64  = parts[0].toUtf8();
    const QByteArray payloadB64 = parts[1].toUtf8();
    const QByteArray sigB64     = parts[2].toUtf8();

    const QByteArray signingInput = headerB64 + "." + payloadB64;

    // Erwartete Signatur neu berechnen (HMAC-SHA256)
    const QByteArray mac   = QMessageAuthenticationCode::hash(signingInput, secretKey, QCryptographicHash::Sha256);
    const QByteArray calcSigB64 = base64UrlEncode(mac);

    if (calcSigB64 != sigB64) {
        qWarning() << "JWT signature mismatch";
        return {};
    }

    const QJsonDocument payloadDoc = QJsonDocument::fromJson(base64UrlDecode(payloadB64));
    if (!payloadDoc.isObject()) return {};

    const QJsonObject claims = payloadDoc.object();

    // exp prüfen
    if (claims.contains("exp")) {
        const qint64 exp = claims.value("exp").toVariant().toLongLong();
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        if (exp < now) {
            qWarning() << "JWT expired:" << exp << "now" << now;
            return {};
        }
    }
    return claims;
}
/*
QString Jwt::sign(const QJsonObject& claims, int expiresSec) const {
    QJsonObject header;
    header["alg"] = "HS256";
    header["typ"] = "JWT";

    QJsonObject payload = claims;
    qint64 now = QDateTime::currentSecsSinceEpoch();
    payload["iat"] = now;
    payload["exp"] = now + expiresSec;

    QByteArray headerB64 = base64UrlEncode(QJsonDocument(header).toJson(QJsonDocument::Compact));
    QByteArray payloadB64 = base64UrlEncode(QJsonDocument(payload).toJson(QJsonDocument::Compact));
    QByteArray signingInput = headerB64 + "." + payloadB64;

    QByteArray sig = QCryptographicHash::hash(signingInput + secretKey, QCryptographicHash::Sha256);
    QByteArray sigB64 = base64UrlEncode(sig);

    return signingInput + "." + sigB64;
}

QJsonObject Jwt::verify(const QString& token) const {
    const QStringList parts = token.split('.');
    if (parts.size() != 3)
        return {};

    QByteArray headerB64 = parts[0].toUtf8();
    QByteArray payloadB64 = parts[1].toUtf8();
    QByteArray sigB64 = parts[2].toUtf8();

    QByteArray signingInput = headerB64 + "." + payloadB64;
    QByteArray calcSig = base64UrlEncode(
        QCryptographicHash::hash(signingInput + secretKey, QCryptographicHash::Sha256)
        );

    if (calcSig != sigB64) {
        qWarning() << "JWT signature mismatch";
        return {};
    }

    QJsonDocument payloadDoc = QJsonDocument::fromJson(base64UrlDecode(payloadB64));
    if (!payloadDoc.isObject())
        return {};

    QJsonObject claims = payloadDoc.object();

    // Ablauf prüfen
    if (claims.contains("exp")) {
        qint64 exp = claims.value("exp").toVariant().toLongLong();
        qint64 now = QDateTime::currentSecsSinceEpoch();
        if (exp < now) {
            qWarning() << "JWT expired:" << exp << "now" << now;
            return {};
        }
    }

    return claims;
}
*/
QByteArray Jwt::base64UrlEncode(const QByteArray& data) const {
    QByteArray out = data.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    return out;
}

QByteArray Jwt::base64UrlDecode(const QByteArray& data) const {
    return QByteArray::fromBase64(data, QByteArray::Base64UrlEncoding);
}
