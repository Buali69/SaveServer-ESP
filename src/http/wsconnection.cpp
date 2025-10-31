
#include "wsconnection.h"
//#include "wsserver.h"
#include <QtWebSockets/QWebSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QDateTime>
#include <QtNetwork/QSslCertificate>
#include "jwt.h"

WsConnection::WsConnection(QWebSocket* s, const WsConfig& cfg, QObject* parent)
    : QObject(parent), sock(s), config(cfg)
{
    connect(sock, &QWebSocket::textMessageReceived, this, &WsConnection::onTextMessage);
    connect(sock, &QWebSocket::disconnected,       this, &WsConnection::onDisconnected);

    sock->sendTextMessage(QStringLiteral("{\"msg\":\"connected\",\"info\":\"please authenticate with JWT\"}"));
    emit log(QString("WS connected ip=%1").arg(peerIp()));
}

void WsConnection::send(const QString& text) {
    if (sock && sock->isValid()) sock->sendTextMessage(text);
}

void WsConnection::sendText(const QString& msg) {
    if (!sock) return;
    sock->sendTextMessage(msg);
}

QString WsConnection::userFromClaims() const {
    const auto u = claims.value("user").toString();
    if (!u.isEmpty()) return u;
    const auto sub = claims.value("sub").toString();
    return sub.isEmpty() ? QStringLiteral("unknown") : sub;
}

QString WsConnection::peerIp() const {
    return sock ? sock->peerAddress().toString() : QString();
}

QString WsConnection::peerCommonName() const {
    if (!sock) return {};
    const auto cert = sock->sslConfiguration().peerCertificate();
    const auto cns = cert.subjectInfo(QSslCertificate::CommonName);
    return cns.isEmpty() ? QString() : cns.join(',');
}

void WsConnection::onTextMessage(const QString& message) {
    QJsonParseError err;
    const auto doc = QJsonDocument::fromJson(message.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        emit log("WS: invalid JSON");
        return;
    }
    const auto obj = doc.object();
    const auto cmd = obj.value("cmd").toString();

    if (cmd == QLatin1String("auth")) {
        const QString token = obj.value("token").toString();
        Jwt jwt(config.jwtSecret);
        const QJsonObject verified = jwt.verify(token);

        if (verified.isEmpty()) {
            emit audit("ws", "unknown",
                       QString("auth failed ip=%1 reason=invalid-or-expired-token").arg(peerIp()));
            send("{\"status\":\"error\",\"msg\":\"invalid token\"}");
            return;
        }

        claims = verified;
        authed = true;

        const QString user = userFromClaims();
        const qint64  exp  = claims.value("exp").toVariant().toLongLong();
        const QString expIso = exp ? QDateTime::fromSecsSinceEpoch(exp).toString(Qt::ISODate) : "-";
        const QString cn = peerCommonName();

        QString msg = QString("auth ok user=%1 ip=%2").arg(user, peerIp());
        if (!cn.isEmpty()) msg += QString(" cn=%1").arg(cn);
        msg += QString(" exp=%1").arg(expIso);

        emit audit("ws", user, msg);
        send("{\"status\":\"ok\",\"msg\":\"authenticated\"}");
        emit log(QString("WS auth ok user=%1 ip=%2").arg(user, peerIp()));
        return;
    }

    if (cmd == QLatin1String("ping")) {
        send("{\"cmd\":\"pong\"}");
        return;
    }

    // … weitere Kommandos (nur wenn authed) …
}

void WsConnection::onDisconnected() {
    QString user = authed ? userFromClaims() : QStringLiteral("unknown");
    emit audit("ws", user, QString("disconnected ip=%1").arg(peerIp()));
    emit log(QString("WS disconnected user=%1 ip=%2").arg(user, peerIp()));
    emit closed(this);
}


/*
#include "WsConnection.h"
#include "Jwt.h"                // deine JWT-Klasse
#include <QJsonDocument>
#include <QJsonObject>
#include <QEvent>

WsConnection::WsConnection(QWebSocket* socket,
                           const QString& secret,
                           QObject* parent)
    : QObject(parent), sock(socket), jwtSecret(secret)
{
    // -------- StateMachine-Setup --------
    connected     = new QState();
    authenticated = new QState();
    closed        = new QState();

    machine.addState(connected);
    machine.addState(authenticated);
    machine.addState(closed);
    machine.setInitialState(connected);

    // Entry actions
    connect(connected, &QState::entered, this, [this]{
        emit audit("ws", "Connected");
    });
    connect(authenticated, &QState::entered, this, [this]{
        QString user = sock->property("user").toString();
        emit audit("ws", "Authenticated user=" + user);
    });
    connect(closed, &QState::entered, this, [this]{
        emit audit("ws", "Closed");
    });

    // Transitions
    // → Auth success triggert Connected → Authenticated
    connected->addTransition(this, SIGNAL(authenticated()), authenticated);
    // → Disconnect triggert egal wo → Closed
    connected->addTransition(sock, &QWebSocket::disconnected, closed);
    authenticated->addTransition(sock, &QWebSocket::disconnected, closed);

    machine.start();

    // -------- Socket-Events --------
    connect(sock, &QWebSocket::textMessageReceived,
            this, &WsConnection::onTextMessageReceived);
    connect(sock, &QWebSocket::disconnected,
            this, &WsConnection::onDisconnected);
}

/**
 * Eingehende WS-Nachricht (JSON erwartet)
 */

    /*
void WsConnection::onTextMessageReceived(const QString& msg) {
    QJsonDocument doc = QJsonDocument::fromJson(msg.toUtf8());
    if (!doc.isObject()) {
        sock->sendTextMessage("{\"error\":\"invalid json\"}");
        return;
    }

    QJsonObject obj = doc.object();
    QString cmd = obj.value("cmd").toString();

    // ---- Auth-Command ----
    if (cmd == "auth") {
        Jwt jwt(jwtSecret.toUtf8());
        auto claims = jwt.verify(obj.value("token").toString());
        if (claims.isEmpty()) {
            sock->sendTextMessage("{\"error\":\"invalid token\"}");
            emit audit("ws","auth failed");
            return;
        }
        QString user = claims.value("sub").toString();
        sock->setProperty("user", user);
        sock->sendTextMessage("{\"status\":\"ok\"}");
        emit audit("ws","auth success user=" + user);

        // Event für StateMachine → Authenticated
        QMetaObject::invokeMethod(this, "authenticated", Qt::QueuedConnection);
        return;
    }

    // ---- Alle anderen Commands ----
    QString user = sock->property("user").toString();
    if (user.isEmpty()) {
        sock->sendTextMessage("{\"error\":\"not authenticated\"}");
        emit audit("ws", "unauthenticated command");
        return;
    }

    if (cmd == "echo") {
        QString text = obj.value("msg").toString();
        sock->sendTextMessage("{\"echo\":\"" + text + "\"}");
        emit audit("ws", QString("user=%1 echo msg=%2").arg(user, text));
    } else {
        sock->sendTextMessage("{\"error\":\"unknown command\"}");
        emit audit("ws", QString("user=%1 unknown cmd=%2").arg(user, cmd));
    }
}

/**
 * Verbindung beendet
 */

    /*
void WsConnection::onDisconnected() {
    emit log("WS disconnected");
    sock->deleteLater();
    // StateMachine-Transition → Closed läuft automatisch
}


*/
