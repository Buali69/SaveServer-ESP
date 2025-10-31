#include "modbusserver.h"
#include <QModbusTcpServer>
#include <QModbusDataUnit>

ModbusServer::ModbusServer(QObject* parent)
    : QObject(parent), server(new QModbusTcpServer(this)) {}

bool ModbusServer::start(quint16 port) {
    if (!server) return false;

    server->setConnectionParameter(QModbusDevice::NetworkAddressParameter,
                                   QStringLiteral("0.0.0.0"));
    server->setConnectionParameter(QModbusDevice::NetworkPortParameter, port);
    server->setServerAddress(1);

    QModbusDataUnitMap reg;
    reg.insert(QModbusDataUnit::HoldingRegisters,
               QModbusDataUnit(QModbusDataUnit::HoldingRegisters, 0, 10));
    server->setMap(reg);

    if (!server->connectDevice()) {
        emit log("Modbus server connectDevice() failed: " + server->errorString());
        return false;
    }

    emit log(QString("Modbus TCP Server started on port %1").arg(port));
    return true;
}

void ModbusServer::stop() {
    if (server) server->disconnectDevice();
    emit log("Modbus TCP Server stopped");
}

bool ModbusServer::setRegisterValue(int addr, quint16 value) {
    if (!server) return false;

    QModbusDataUnit unit(QModbusDataUnit::HoldingRegisters, addr, 1);
    unit.setValue(0, value);

    if (!server->setData(unit)) {
        emit log("Modbus write failed: " + server->errorString());
        return false;
    }

    emit registerChanged(addr, value);
    return true;
}

bool ModbusServer::getRegisterValue(int addr, quint16 &value) {
    if (!server) return false;

    QModbusDataUnit unit(QModbusDataUnit::HoldingRegisters, addr, 1);
    if (!server->data(&unit)) {
        emit log("Modbus read failed: " + server->errorString());
        return false;
    }

    value = unit.value(0);
    return true;
}
