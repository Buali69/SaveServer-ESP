#pragma once
#include <QObject>
#include <QSet>
#include <QSslCertificate>
#include <QSslKey>
#include <QList>
#include <QByteArray>
#include <QJsonObject>
#include <QJsonDocument>

class QWebSocketServer;
class WsConnection; // nur vorwärts, KEIN include von wsconnection.h

// ✅ Wie bei HTTPS: volle Definition im selben Header
struct WsConfig {
    QSslCertificate        serverCert;
    QSslKey                serverKey;
    QList<QSslCertificate> caCerts;
    bool                   requireClientCert = false;
    quint16                port = 9443;
    QByteArray             jwtSecret;
};

class WsServer : public QObject {
    Q_OBJECT
public:
    explicit WsServer(QObject* parent=nullptr);
    ~WsServer();

    void setConfig(const WsConfig& cfg);
    bool listen();
    void stop();
    int broadcast(const QString& msg);

signals:
    void log(const QString& msg);
    // einheitlich: (Kategorie, User, Nachricht)
    void audit(const QString& cat, const QString& user, const QString& msg);
    void sensorEvent(const QString& device, const QJsonObject& values, qint64 ts);
    void otaProgress(const QString& device, qint64 jobId, const QString& state, int progress);

private slots:
    void onNewConnection();
    void onConnectionClosed(WsConnection* c);

private:
    QWebSocketServer*  server = nullptr;
    QSet<WsConnection*> conns;
    WsConfig           config;   // ✅ by value – wie bei HTTPS
    // <— Hier die Liste deiner aktiven Verbindungen
    QList<WsConnection*> connections;
};


