#pragma once

#include <QMainWindow>
#include <QTextEdit>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QGroupBox>
#include <QProgressBar>
#include <QTableWidget>
#include <QStateMachine>
#include <QState>
#include <QTabWidget>
#include <QtWidgets/QLabel>        // +++
#include <QtWidgets/QStatusBar>    // +++
#include <QPropertyAnimation>
#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>
#include <QtCharts/QChart>

#include "../db/Storage.h"
#include "../http/WsServer.h"
#include "../mqtt/mqttclient.h"
#include "../modbus/modbusserver.h"

class HttpsServer;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent=nullptr);
    ~MainWindow();

signals:
    void errorOccurred();        // Übergang Running → Error
    void switchToDrawing();      // Substate: Collecting → Drawing
    void switchToCollecting();   // Substate: Drawing → Collecting

private slots:
    void startServer();
    void stopServer();
    void refreshTable();
    void refreshAudit();

private:
    // ---- GUI Elemente ----
    QTextEdit* logView = nullptr;
    QPushButton* startBtn = nullptr;
    QPushButton* stopBtn = nullptr;

    QLineEdit* portEdit = nullptr;       // HTTPS Port
    QLineEdit* wsPortEdit = nullptr;     // WebSocket Port
    QLineEdit* docRootEdit = nullptr;
    QPushButton* docBtn = nullptr;
    QLineEdit* certEdit = nullptr;
    QPushButton* certBtn = nullptr;
    QLineEdit* keyEdit = nullptr;
    QPushButton* keyBtn = nullptr;
    QLineEdit* caEdit = nullptr;
    QPushButton* caBtn = nullptr;

    QComboBox* modeBox = nullptr;
    QTableWidget* table = nullptr;       // Datenbank-Tabelle
    QTableWidget* auditTable = nullptr;  // Audit-Log Tabelle

    // Tabs
    QTabWidget* tabWidget = nullptr;

    // MQTT/Modbus Tab Widgets
    QLineEdit* mqttTopicEdit = nullptr;
    QLineEdit* mqttMsgEdit   = nullptr;
    QPushButton* mqttSendBtn = nullptr;

    QLineEdit* modbusAddrEdit = nullptr;
    QLineEdit* modbusValEdit  = nullptr;
    QPushButton* modbusSetBtn = nullptr;
    QTableWidget* modbusTable = nullptr;

    // ---- Server / Storage ----
    HttpsServer* server = nullptr;
    WsServer* wsServer = nullptr;
    Storage* storage = nullptr;

    // ---- StateMachine (App) ----
    void setupAppStateMachine();
    QStateMachine* appMachine = nullptr;
    QState* idle = nullptr;
    QState* running = nullptr;
    QState* error = nullptr;
    QState* collecting = nullptr;   // Substates von Running
    QState* drawing = nullptr;

    // ---- MQTT + Modbus ----
    MqttClient* mqtt = nullptr;
    ModbusServer* modbus = nullptr;

    // ---- Helfer ----
    void log(const QString& s);
    void addAudit(const QString& cat, const QString& msg);

    // --- Neu: State-Anzeige
    QLabel* stateLabel = nullptr;   // +++
    QPropertyAnimation* statePulse = nullptr;

    // --- Neu: OTA-Tab Widgets (damit sie im Slot sichtbar sind)
    QLineEdit* otaFileEdit = nullptr;   // optional, wenn du sie außerhalb der Lambdas brauchst
    QComboBox* otaFileCombo = nullptr;  // dito
    QTableWidget* otaFilesTable = nullptr;
    QTableWidget* otaJobsTable  = nullptr;

    void testRangeDownload(qint64 fileId);

    // --- Neu: Hilfsfunktionen (Deklaration)
    void refreshOtaFiles(QTableWidget* filesTable, QComboBox* fileCombo); // +++
    void refreshOtaJobs(QTableWidget* jobsTable);
    void refreshSensorTable(void);

    QChartView* chartView = nullptr;
    QLineSeries* seriesTemp = nullptr;
    QLineSeries* seriesHum  = nullptr;
    QLineSeries* seriesNum  = nullptr;
    QValueAxis* axisX = nullptr;
    QValueAxis* axisY = nullptr;
    qint64 sampleIndex = 0; // einfache X-Achse

    QHash<qint64,int> jobRow;                    // jobId -> Tabellenzeile
    QTimer* jobsRefreshTimer = nullptr;


    void upsertJobRow(qint64 jobId,
                      const QString& device,
                      qint64 fileId,
                      const QString& state,
                      int progress);
    void styleStateCell(QTableWidgetItem* item, const QString& state);

    // --- Neu: gemerkter DocRoot (siehe Punkt 3)
    QString currentDocRoot;

    void loadSettings();
    void saveSettings();

    // --- Device-Admin Widgets als Member (damit Lambdas sie sehen)
    QLineEdit* devKeyEdit = nullptr;
    QLineEdit* devFwEdit  = nullptr;
    QCheckBox* devEnChk   = nullptr;
    QPushButton* devCreateBtn = nullptr;
    QPushButton* devToggleBtn = nullptr;
    QPushButton* devRotateBtn = nullptr;
    QPushButton* devDeleteBtn = nullptr;
    QTableWidget* devTable = nullptr;
    QTableWidget* sensorTable = nullptr;

   // QComboBox* fileCombo = nullptr;
   // QTableWidget* filesTable = nullptr;
    // QTableWidget* jobsTable = nullptr;

    // (optional) Helfer als Methode, wenn du kein Lambda willst
    void refreshDevices();

    // Für das Device-Assign-Feld EINE EIGENE Variable, um Kollision mit devKeyEdit zu vermeiden:
    QLineEdit*    assignDevKeyEdit = nullptr;

};


/*
 * 1. HttpsServer / HttpConnection

Aufgabe:
TLS/mTLS-Server, nimmt HTTPS-Verbindungen entgegen.
Nutzt QSslSocket, überprüft Zertifikate (optional Client-Zertifikate bei mTLS).
Dient als „klassischer Webserver“-Teil.

Wichtige Klassen & Funktionen:

HttpsServer

listen(QHostAddress, quint16) → Startet Server.

setConfig(HttpsConfig cfg) → TLS-Zertifikate, CA, Pfade setzen.

HttpConnection

Repräsentiert eine einzelne Client-Verbindung.

Liest HTTP-Requests, gibt Antworten zurück.

Übergibt Daten (z. B. „number“) an Callback (onNumber).

Besonderheiten:

mTLS (mutual TLS) kann Clients per Zertifikat authentifizieren.

JWT-Auth später hier eingebaut, wenn API-Endpunkte gesichert werden.

2. WsServer

Aufgabe:
WebSocket-Server über TLS (WSS).
Ermöglicht bidirektionale Kommunikation zwischen Server und Clients.
Wichtig für IoT, GUIs oder Echtzeit-Apps.

Wichtige Funktionen:

start(port, secret) → Startet den WebSocket-Server.

stop() → Stoppt ihn wieder.

onNewConnection() → wird gerufen, wenn sich ein neuer Client verbindet.

onTextMessage(const QString&) → verarbeitet Nachrichten der Clients.

Besonderheiten:

Nutzt JWT zur Authentifizierung der Clients.

Hält eine Liste aktiver Clients (QSet<QWebSocket*> clients).

Hat Audit-Events (z. B. Client verbunden/getrennt).

3. Jwt

Aufgabe:
JSON Web Token Signierung & Verifikation.
Für Login und Authentifizierung im HTTP- und WS-Teil.

Wichtige Funktionen:

Jwt(const QByteArray& secret) → Konstruktor mit Secret-Key.

QString sign(const QJsonObject& claims, int expiresSec=3600)

Erstellt ein JWT mit Ablaufzeit.

QJsonObject verify(const QString& token)

Prüft Token-Signatur, Ablaufzeit, Claims.

Besonderheiten:

Base64Url-Encoding/Decoding implementiert.

Keine externe Library notwendig.

Für „echten Betrieb“ sollte Key-Rotation und HMAC-Algorithmen erweitert werden.

4. Storage (DB)

Aufgabe:
SQLite-Backend für Daten und Audit-Logs.
Sorgt dafür, dass „Events“ persistent gespeichert werden.

Wichtige Funktionen/Signale:

insertData(QString name, QString value) → normale Daten speichern.

insertAudit(QString category, QString user, QString msg) → Audit-Event speichern.

selectLatest(int limit) → Abfrage letzter Werte.

selectAudit(int limit) → Audit-Logs abfragen.

signals:

dataInserted(name, value) → für Live-Update im GUI.

auditInserted(cat, user, msg) → Audit-Tabelle im GUI aktualisieren.

Besonderheiten:

Direkt mit QSqlDatabase umgesetzt.

Nutzt Signale für GUI-Anzeige.

5. MqttClient

Aufgabe:
Verbindung zu MQTT-Broker (z. B. Mosquitto).
Dient als Brücke zwischen IoT-Systemen und deinem Server.

Wichtige Funktionen:

connectToBroker(host, port) → Baut Verbindung auf.

publishMessage(topic, payload) → Nachricht senden.

Signal: commandReceived(int addr, quint16 value)

wenn von MQTT eine „set“-Anweisung kommt.

Signal: log(QString) → für Statusausgaben im GUI.

Besonderheiten:

Abonniert per Default modbus/set/#.

Erkennt Kommandos wie „modbus/set/5 = 42“ → schreibt an Modbus weiter.

6. ModbusServer

Aufgabe:
Simpler Modbus/TCP-Server über QModbusTcpServer.
Stellt Register bereit, die per MQTT oder WS beschrieben/gelesen werden können.

Wichtige Funktionen:

start(port) → Startet Server.

stop() → Stoppt Server.

setRegisterValue(addr, value) → Wert in Holding Register schreiben.

Signal: registerChanged(addr, value) → GUI oder MQTT informieren.

Signal: log(QString) → für GUI.

Besonderheiten:

Nutzt QModbusDataUnit zum Zugriff auf Register.

Register werden im Speicher gehalten, Änderungen getriggert.

Dient als Brücke zwischen Hardware/IoT und deinem System.

7. MainWindow (GUI + Orchestrierung)

Aufgabe:
Zentrale Steuerung & Visualisierung.
Alle Module (HTTPS, WS, MQTT, Modbus, Storage) laufen hier zusammen.
User-Interface für Start/Stop, Logs, Audit, Daten, Tabs.

Wichtige Teile:

Tabs:

Server-Konfiguration (Ports, Zertifikate).

Audit/DB-Anzeige.

MQTT/Modbus-Steuerung.

StateMachine:

Idle → Running → Error mit Substates (Collecting, Drawing).

Visuell mit Logmeldungen sichtbar.

Brücken:

Modbus-Änderung → MQTT Publish.

MQTT-Command → Modbus Write.

Besonderheiten:

Nutzt QTableWidget für DB/Audit-Anzeige.

Logs kommen über log() ins Textfeld.

Buttons zum Starten/Stoppen des Servers.

🎯 Lern-Aspekte (was du dir merken kannst)

Lose Kopplung: fast alles läuft über Signale & Slots, nicht über harte Funktionsaufrufe → flexibel erweiterbar.

StateMachine: Qt QStateMachine eignet sich hervorragend, um Systemzustände professionell zu modellieren.

Integration: GUI-Tab, MQTT, Modbus und TLS-Webserver greifen ineinander, ohne Spaghetti-Code.

Best Practices: JWT für Auth, TLS/mTLS für Transport, Audit für Nachvollziehbarkeit.

*/
