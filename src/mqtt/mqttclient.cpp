#include "mqttclient.h"
#include <QMqttTopicFilter>

MqttClient::MqttClient(QObject* parent)
    : QObject(parent), client(new QMqttClient(this))
{
    connect(client, &QMqttClient::connected, this, [this]{
        emit log("MQTT connected to broker");
    });
    connect(client, &QMqttClient::disconnected, this, [this]{
        emit log("MQTT disconnected");
    });
    connect(client, &QMqttClient::messageReceived,
            this, [this](const QByteArray &message, const QMqttTopicName &topic){
                QString t = topic.name();
                if (t.startsWith("modbus/set/")) {
                    bool ok=false;
                    int addr = t.section('/',2,2).toInt(&ok);
                    if (ok) {
                        quint16 val = message.toUShort();
                        emit commandReceived(addr, val);   // NEU
                    }
                }
                emit log(QString("MQTT [%1]: %2").arg(t, QString::fromUtf8(message)));
            });
}

void MqttClient::connectToBroker(const QString& host, quint16 port) {
    client->setHostname(host);
    client->setPort(port);
    client->connectToHost();

    // Wildcard-Subscribe → QMqttTopicFilter nötig
    client->subscribe(QMqttTopicFilter(QStringLiteral("modbus/set/#")));
}

void MqttClient::publishMessage(const QString& topic, const QString& message) {
    if (client->state() == QMqttClient::Connected)
        client->publish(QMqttTopicName(topic), message.toUtf8());
}
