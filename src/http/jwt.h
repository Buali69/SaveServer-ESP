#pragma once
#include <QString>
#include <QJsonObject>

class Jwt {
public:
    Jwt(const QByteArray& secret);

    QString sign(const QJsonObject& claims, int expiresSec = 3600) const;
    QJsonObject verify(const QString& token) const;

private:
    QByteArray secretKey;

    QByteArray base64UrlEncode(const QByteArray& data) const;    //ToDo, aus crypto_helpers.h einbinden
    QByteArray base64UrlDecode(const QByteArray& data) const;
};
