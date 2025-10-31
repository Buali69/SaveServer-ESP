#pragma once
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslKey>
#include <QtCore/QString>
#include <functional>
//#include "Storage.h"

class HttpConnection;
class Storage;

struct HttpsConfig {
    QSslCertificate                serverCert;
    QSslKey                        serverKey;
    QList<QSslCertificate>         caCerts;         // Trust-CA for client auth (mTLS)
    bool                           requireClientCert = false;
    QString                        documentRoot;    // path to /web
    std::function<void(int)>       onNumber;        // callback to store numbers
    std::function<void(QString)>   log;             // logging sink
    std::function<void(QString, QString)> audit;    // 🔹 NEU: Audit-Logger
    QByteArray                      jwtSecret = "changeme-secret";  // JWT-Schlüssel
    QByteArray                      hmacSecret;  // für Sensor-REST-Auth
    std::function<void(QString, QString)> onOtaUploaded;
    std::function<void(const QString&)> wsBroadcast; // optional: JSON-text an WS schicken
    Storage*                        storage = nullptr;   // NEU: Pointer auf die bereits geöffnete DB
};

class HttpsServer : public QTcpServer {
    Q_OBJECT
public:
    explicit HttpsServer(QObject* parent=nullptr);
    void setConfig(const HttpsConfig& cfg);
   // void setConfig(const HttpsConfig& c) { cfg = c; };
protected:
    void incomingConnection(qintptr handle) override;
private:
    HttpsConfig cfg_;
};
