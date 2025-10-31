#include "../http/jwt.h"
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDateTime>
#include <QDebug>

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("jwtgen");
    QCoreApplication::setApplicationVersion("1.0");

    QCommandLineParser parser;
    parser.setApplicationDescription("JWT Generator");
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption userOpt(QStringList() << "u" << "user",
                               "User/Subject für das JWT",
                               "user");
    QCommandLineOption secretOpt(QStringList() << "s" << "secret",
                                 "Secret für JWT-Signatur",
                                 "secret");
    parser.addOption(userOpt);
    parser.addOption(secretOpt);
    parser.process(app);

    QString user = parser.value(userOpt);
    QString secret = parser.value(secretOpt);

    if (user.isEmpty() || secret.isEmpty()) {
        qWarning() << "Fehler: bitte --user und --secret angeben!";
        return 1;
    }

    Jwt jwt(secret.toUtf8());

    QJsonObject claims;
    claims["sub"] = user;
    claims["iat"] = QDateTime::currentSecsSinceEpoch();
    claims["exp"] = QDateTime::currentSecsSinceEpoch() + 3600; // 1h gültig

    QString token = jwt.sign(claims);
    qDebug().noquote() << token;

    return 0;
}
