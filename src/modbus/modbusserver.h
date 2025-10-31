#pragma once
#include <QObject>
#include <QModbusTcpServer>
#include <QModbusDataUnit>

class ModbusServer : public QObject {
    Q_OBJECT
public:
    explicit ModbusServer(QObject* parent=nullptr);

    bool start(quint16 port);
    void stop();

    // NEU: Register Zugriff
    bool setRegisterValue(int addr, quint16 value);   // Schreiben
    bool getRegisterValue(int addr, quint16 &value);  // Lesen

signals:
    void log(const QString& msg);
    void registerChanged(int addr, quint16 value);

private:
    QModbusTcpServer* server;
};
