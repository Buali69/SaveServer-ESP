#pragma once
#include <QObject>
#include <QMqttClient>

class MqttClient : public QObject {
    Q_OBJECT
public:
    explicit MqttClient(QObject* parent=nullptr);

    void connectToBroker(const QString& host, quint16 port);
    void publishMessage(const QString& topic, const QString& message);

signals:
    void log(const QString& msg);
    void commandReceived(int addr, quint16 value);

private:
    QMqttClient* client;
};
