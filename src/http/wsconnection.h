#pragma once
#include <QObject>
#include <QJsonObject>
#include "wsserver.h"  // bringt die VOLLDEFINITION von WsConfig mit

class QWebSocket;

class WsConnection : public QObject {
    Q_OBJECT
public:
    WsConnection(QWebSocket* socket, const WsConfig& cfg, QObject* parent=nullptr);
    bool isAuthenticated() const { return authed; }
    void send(const QString& text);
    void sendText(const QString& msg);      // <<< NEU (Wrapper)

signals:
    void log(const QString& msg);
    void audit(const QString& cat, const QString& user, const QString& msg);
    void closed(WsConnection* self);

private slots:
    void onTextMessage(const QString& msg);
    void onDisconnected();

private:
    QWebSocket* sock = nullptr;
    WsConfig    config;   // ✅ by value – geht jetzt, weil WsConfig voll definiert ist
    bool        authed = false;
    QJsonObject claims;

    QString userFromClaims() const;
    QString peerIp() const;
    QString peerCommonName() const;
};

