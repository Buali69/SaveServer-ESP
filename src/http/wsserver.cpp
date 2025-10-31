#include "wsserver.h"
#include "wsconnection.h"
#include <QtWebSockets/QWebSocketServer>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

WsServer::WsServer(QObject* parent) : QObject(parent) {}
WsServer::~WsServer() { stop(); }

void WsServer::setConfig(const WsConfig& cfg) { config = cfg; }

bool WsServer::listen() {
    if (server) return false;

    server = new QWebSocketServer("nBS1 WebSocket", QWebSocketServer::SecureMode, this);

    QSslConfiguration ssl;
    ssl.setProtocol(QSsl::TlsV1_2OrLater);
    ssl.setLocalCertificate(config.serverCert);
    ssl.setPrivateKey(config.serverKey);
    ssl.setCaCertificates(config.caCerts);
    ssl.setPeerVerifyMode(config.requireClientCert ? QSslSocket::VerifyPeer
                                                   : QSslSocket::VerifyNone);
    server->setSslConfiguration(ssl);

    if (!server->listen(QHostAddress::Any, config.port)) {
        emit log(QString("WS Listen failed: %1").arg(server->errorString()));
        return false;
    }

    connect(server, &QWebSocketServer::newConnection, this, &WsServer::onNewConnection);
    emit log(QString("WS läuft auf wss://0.0.0.0:%1").arg(config.port));
    return true;
}

void WsServer::stop() {
    for (auto* c : connections) {
        if (c) c->deleteLater();
    }
    connections.clear();
    server->close();
}

void WsServer::onNewConnection() {
    QWebSocket* sock = server->nextPendingConnection();
    if (!sock) return;

    // 👉 WsConnection bekommt den GESAMTEN WsConfig
    auto* conn = new WsConnection(sock, config, this);

    connections.append(conn);

    connect(conn, &WsConnection::log,   this, &WsServer::log);
    connect(conn, &WsConnection::audit, this, &WsServer::audit);

    connect(conn, &WsConnection::closed, this, [this, conn]() {   // () nicht vergessen
        connections.removeOne(conn);
        conn->deleteLater();
        emit log(QString("WS client closed, %1 remaining").arg(connections.size()));
    });

    emit log("WS client connected (awaiting auth)");
}

void WsServer::onConnectionClosed(WsConnection* c) {
    conns.remove(c);
    c->deleteLater();
}

int WsServer::broadcast(const QString& msg) {
    int sent = 0;
    QJsonParseError pe;
    const auto doc = QJsonDocument::fromJson(msg.toUtf8(), &pe);
    if (pe.error == QJsonParseError::NoError && doc.isObject()) {
        const auto o = doc.object();

        if (o.contains("sensor") && o["sensor"].isObject()) {
            const auto s = o["sensor"].toObject();
            const QString dev = s.value("device").toString();
            const auto    vals= s.value("values").toObject();
            const qint64  ts  = s.value("ts").toVariant().toLongLong();
            emit sensorEvent(dev, vals, ts);
        }
        if (o.contains("ota") && o["ota"].isObject()) {
            const auto ot = o["ota"].toObject();
            const QString dev = ot.value("device").toString();
            const qint64  job = ot.value("job_id").toVariant().toLongLong();
            const QString st  = ot.value("state").toString();
            const int     prg = ot.value("progress").toInt();
            emit otaProgress(dev, job, st, prg);
        }
    }
    for (auto* c : connections) {
        if (!c) continue;
        if (c->isAuthenticated()) {        // WsConnection muss das anbieten
            c->sendText(msg);
            ++sent;
        }
    }
    emit log(QString("broadcasted to %1 clients").arg(sent));
    return sent;
}


/*

#include "wsserver.h"
#include "jwt.h"
#include <QtWebSockets/QWebSocketServer>
#include <QtWebSockets/QWebSocket>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslKey>
#include <QtCore/QFile>
#include <QtCore/QDebug>
#include <QJsonDocument>     // ✅ hinzugefügt
#include <QJsonObject>       // ✅ hinzugefügt
#include <QJsonParseError>   // ✅ hinzugefügt



WsServer::WsServer(QObject* parent)
    : QObject(parent),
    server(new QWebSocketServer("QtSecureServer WS",
                                QWebSocketServer::NonSecureMode,
                                this))
{}

WsServer::~WsServer() {
    stop();
}

bool WsServer::start(quint16 port, const QString& jwtSecret)
{
    secret = jwtSecret;

    // Falls dein QWebSocketServer noch nicht existiert:
    if (!server) {
        // 🔹 Sicheren Modus aktivieren
        server = new QWebSocketServer("nBS1 WebSocket",
                                      QWebSocketServer::SecureMode,
                                      this);

        // 🔹 TLS-Konfiguration vorbereiten
        QSslConfiguration sslConfig;
        sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone); // für Tests
        sslConfig.setProtocol(QSsl::TlsV1_2OrLater);

        // Zertifikat + Key laden (Pfad anpassen!)
        QFile certFile(":/certs/server.crt");
        QFile keyFile(":/certs/server.key");

        if (certFile.open(QIODevice::ReadOnly) && keyFile.open(QIODevice::ReadOnly)) {
            QSslCertificate cert(&certFile, QSsl::Pem);
            QSslKey key(&keyFile, QSsl::Rsa, QSsl::Pem);
            sslConfig.setLocalCertificate(cert);
            sslConfig.setPrivateKey(key);
            server->setSslConfiguration(sslConfig);
        } else {
            emit log("⚠️  Konnte Zertifikat oder Key nicht öffnen — WS läuft unverschlüsselt!");
        }
    }

    // 🔹 Lauschen
    if (!server->listen(QHostAddress::Any, port)) {
        emit log(QString("❌ WS Listen failed on port %1: %2")
                     .arg(port).arg(server->errorString()));
        return false;
    }

    // 🔹 Events verbinden
    connect(server, &QWebSocketServer::newConnection,
            this, &WsServer::onNewConnection);

    emit log(QString("✅ WebSocket läuft auf wss://0.0.0.0:%1").arg(port));
    return true;
}


void WsServer::stop() {
    if (server && server->isListening()) {
        for (QWebSocket* client : clients) {
            client->close();
            client->deleteLater();
        }
        clients.clear();
        server->close();
        emit log("WebSocket server stopped");
    }
}

void WsServer::onNewConnection() {
    QWebSocket* client = server->nextPendingConnection();
    if (!client) return;

    clients.insert(client);

    emit log(QString("Client connected: %1").arg(client->peerAddress().toString()));

    connect(client, &QWebSocket::textMessageReceived,
            this, &WsServer::onTextMessage);
    connect(client, &QWebSocket::disconnected,
            this, &WsServer::onDisconnected);
}

void WsServer::onDisconnected() {
    QWebSocket* client = qobject_cast<QWebSocket*>(sender());
    if (client) {
        clients.remove(client);
        authenticated.remove(client);   // <- auch aus Auth-Liste entfernen
        emit log(QString("Client disconnected: %1").arg(client->peerAddress().toString()));
        client->deleteLater();
    }
}

void WsServer::onTextMessage(const QString& message) {
    QWebSocket* client = qobject_cast<QWebSocket*>(sender());
    if (!client) return;

    emit log(QString("WS Nachricht: %1").arg(message));

    // --- Authentifizierung prüfen ---
    if (!authenticated.contains(client)) {
        // Erster Schritt: Wir erwarten Token (z.B. JSON: {"token":"..."} oder nur String)
        QString token;

        // Versuchen, als JSON zu interpretieren
        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(message.toUtf8(), &err);
        if (err.error == QJsonParseError::NoError && doc.isObject()) {
            QJsonObject obj = doc.object();
            token = obj.value("token").toString();
        } else {
            token = message.trimmed();
        }

        if (token.isEmpty()) {
            emit audit("ws", "Kein Token übermittelt");
            client->sendTextMessage("auth error: missing token");
            client->close();
            return;
        }

        // JWT validieren
        Jwt jwt(secret.toUtf8());               // QString → QByteArray
        QJsonObject payload = jwt.verify(token);

        if (payload.isEmpty()) {
            emit audit("ws", "Ungültiges JWT");
            client->sendTextMessage("auth error: invalid token");
            client->close();
            return;
        }

        // Erfolgreich authentifiziert
        authenticated.insert(client);
        client->sendTextMessage("auth ok");
        emit audit("ws", QString("Client authentifiziert: %1").arg(payload.value("sub").toString()));
        return;
    }

    // --- Ab hier: Authentifizierte Nachrichten ---
    client->sendTextMessage("Echo: " + message);
    emit audit("ws", QString("User Nachricht: %1").arg(message));
}

void WsServer::broadcast(const QString& text) {
    for (QWebSocket* client : clients) {
        if (authenticated.contains(client)) {
            client->sendTextMessage(text);
        }
    }
}
*/
