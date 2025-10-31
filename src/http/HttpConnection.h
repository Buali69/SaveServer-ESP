#pragma once
#include <QtCore/QObject>
#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <functional>

#include <QtStateMachine/QStateMachine>
#include <QtStateMachine/QState>

class QSslSocket;
class Storage;

class HttpConnection : public QObject {
    Q_OBJECT
public:
    HttpConnection(QSslSocket* sock,
                   QString documentRoot,
                   std::function<void(int)> onNumber,
                   std::function<void(QString)> log,
                   QByteArray jwtSecret,
                   std::function<void(QString, QString)> audit,
                   std::function<void(QString)> wsBroadcast,
                   QObject* parent=nullptr,
                   Storage* storage=nullptr);

signals:
    void tlsOk();
    void authenticated();
    void closed();

private:
    // States
    QStateMachine machine;
    QState* stateConnected;
    QState* stateTlsOk;
    QState* stateAuthenticated;
    QState* stateClosed;
    Storage* storage_ = nullptr;

    void setupStateMachine();
    QString currentStateName;   // 🔹 für Debug/Audit

    void onEncrypted();
    void onReadyRead();
    void onDisconnected();
    void serveIndex();
    void handleSubmit(const QByteArray& body);
    void handleLogin(const QByteArray& body);
    void handleApiRequest(const QByteArray& method,
                          const QByteArray& pathRaw,
                          const QByteArray& body,
                          const QList<QPair<QByteArray,QByteArray>>& headers);
    void send(int code, const QByteArray& ctype, const QByteArray& payload);
    static QByteArray urlDecode(const QByteArray& in);

    bool requireAdminJwt(const QMap<QString,QString>& hdrs, QString* userOut);

 //   QByteArray buffer_;
    bool headersDone_ = false;
 //   qint64 contentLength_ = -1;
 //   int headerEndPos_ = -1;
    int delimLen_ = 0;

    QByteArray rx_;            // Empfangspuffer (Header+Body)
 //   bool headersDone_ = false;
    int  headerEnd_   = -1;    // Position hinter "\r\n\r\n"
    int  contentLen_  = 0;     // erwartete Body-Länge
    QByteArray method_, path_;
    QList<QPair<QByteArray,QByteArray>> hdrs_;
    void resetRequestState(void);
    void parseIncoming();


    std::function<void(QString)> wsBroadcast_;
 //   QByteArray buffer;
    QSslSocket* sock = nullptr;
    QString docRoot;
    std::function<void(int)> onNumber_;
    std::function<void(QString)> log_;
    QByteArray jwtSecret_;
    std::function<void(QString, QString)> audit_;   // 🔹 Audit-Callback
    QString verifyHmac(const QString& method,
                                       const QString& path,
                                       const QMap<QString, QString>& headers,
                                        const QByteArray& body);
};
