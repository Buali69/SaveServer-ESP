#include "HttpsServer.h"
#include "HttpConnection.h"
#include <QtNetwork/QSslSocket>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslError>
#include <QtNetwork/QHostAddress>


HttpsServer::HttpsServer(QObject* parent) : QTcpServer(parent) {}

void HttpsServer::setConfig(const HttpsConfig& cfg) { cfg_ = cfg; }

void HttpsServer::incomingConnection(qintptr handle) {
    auto* sock = new QSslSocket(this);
    if (!sock->setSocketDescriptor(handle)) { sock->deleteLater(); return; }

    QSslConfiguration sc = QSslConfiguration::defaultConfiguration();
    sc.setProtocol(QSsl::TlsV1_2OrLater);
    sc.setLocalCertificate(cfg_.serverCert);
    sc.setPrivateKey(cfg_.serverKey);
    if (!cfg_.caCerts.isEmpty()) sc.setCaCertificates(cfg_.caCerts);
    sock->setSslConfiguration(sc);

    sock->setPeerVerifyMode(cfg_.requireClientCert ? QSslSocket::VerifyPeer : QSslSocket::VerifyNone);
    sock->setPeerVerifyDepth(4);

    QObject::connect(sock, &QSslSocket::sslErrors, this, [this, sock](const QList<QSslError>& errs){
        for (const auto& e : errs) {
            if (cfg_.log) cfg_.log(QStringLiteral("SSL error: ") + e.errorString());
        }
        if (!cfg_.requireClientCert) {
            sock->ignoreSslErrors(); // allow self-signed when TLS-only
        } else {
            for (const auto& e : errs) {
                switch (e.error()) {
                case QSslError::NoPeerCertificate:
                case QSslError::CertificateUntrusted:
                case QSslError::SelfSignedCertificate:
                case QSslError::SelfSignedCertificateInChain:
                case QSslError::UnableToGetLocalIssuerCertificate:
                    sock->abort(); return;
                default: break;
                }
            }
        }
    });

    // Create per-connection handler (parses HTTP, serves files, handles /submit)
    new HttpConnection(sock,
                       cfg_.documentRoot,
                       cfg_.onNumber,
                       cfg_.log,
                       cfg_.jwtSecret,
                       cfg_.audit,
                       cfg_.wsBroadcast,
                       this,
                       cfg_.storage);
    sock->startServerEncryption();
}
