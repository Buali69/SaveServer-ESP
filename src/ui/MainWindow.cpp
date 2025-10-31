#include "MainWindow.h"
#include "../http/HttpsServer.h"
#include "../http/WsServer.h"
#include "../db/Storage.h"
#include "../mqtt/mqttclient.h"
#include "../modbus/modbusserver.h"

#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QProgressBar>
#include <QTimer>
#include <QFile>
#include <QSslCertificate>
#include <QSslKey>
#include <QDateTime>
#include <QSettings>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QRandomGenerator>
#include <QMessageBox>
#include "../common/crypto_helpers.h"  // b64url, b64url_decode, sha256, hmacSha256

// ============================================================================
// Hilfsfunktionen (anonyme Namespace → nur in dieser Übersetzungseinheit sichtbar)
// ============================================================================

namespace {

static void setHmacHeaders(QNetworkRequest& req,
                           const QString& method,
                           const QString& path,        // exakt, ohne Query
                           const QByteArray& body,     // bei GET: leer
                           const QString& keyId,
                           const QString& secretBase64Url)
{
    using namespace crypto;

    const QByteArray bodyB64 = b64url( sha256(body) );

    const QByteArray ts    = QByteArray::number(QDateTime::currentSecsSinceEpoch());
    const QByteArray nonce = QUuid::createUuid().toString(QUuid::WithoutBraces).toUtf8();

    QByteArray canon;
    canon += method.toUpper().toUtf8(); canon += '\n';
    canon += path.toUtf8();             canon += '\n';
    canon += bodyB64;                   canon += '\n';
    canon += ts;                        canon += '\n';
    canon += nonce;

    const QByteArray keyBytes = b64url_decode(secretBase64Url.trimmed().toUtf8());
    const QByteArray sigB64   = b64url( hmacSha256(keyBytes, canon) );

    req.setRawHeader("x-auth-keyid", keyId.toUtf8());
    req.setRawHeader("x-auth-ts",    ts);
    req.setRawHeader("x-auth-nonce", nonce);
    req.setRawHeader("x-auth-sign",  sigB64);
}

}

/**
 * Konstruktor
 */
MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("QtSecureServer Demo");
    stateLabel = new QLabel("State: Idle");
    stateLabel->setStyleSheet("QLabel { padding: 4px 8px; border-radius: 8px; color: white; background:#777; }");
    statePulse = new QPropertyAnimation(stateLabel, "windowOpacity", this);
    statePulse->setDuration(300);
    statePulse->setStartValue(0.5);
    statePulse->setEndValue(1.0);
    statusBar()->addPermanentWidget(stateLabel);
    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);

    // ------------------- Server-Einstellungen -------------------
    auto* h1 = new QHBoxLayout;
    portEdit = new QLineEdit; portEdit->setPlaceholderText("HTTPS Port"); portEdit->setText("8443");
    wsPortEdit = new QLineEdit; wsPortEdit->setPlaceholderText("WebSocket Port"); wsPortEdit->setText("9443");
    modeBox = new QComboBox; modeBox->addItems({"TLS","mTLS"});
    h1->addWidget(new QLabel("HTTPS-Port:")); h1->addWidget(portEdit);
    h1->addWidget(new QLabel("WebSocket-Port:")); h1->addWidget(wsPortEdit);
    h1->addWidget(new QLabel("Mode:")); h1->addWidget(modeBox);
    layout->addLayout(h1);

    // DocRoot
    auto* hDoc = new QHBoxLayout;
    docRootEdit = new QLineEdit; docRootEdit->setPlaceholderText("Document Root");
    docBtn = new QPushButton("…");
    hDoc->addWidget(new QLabel("DocRoot:")); hDoc->addWidget(docRootEdit); hDoc->addWidget(docBtn);
    layout->addLayout(hDoc);

    // Zertifikate
    auto* hCert = new QHBoxLayout;
    certEdit = new QLineEdit; certEdit->setPlaceholderText("Server Cert");
    certBtn = new QPushButton("…");
    hCert->addWidget(new QLabel("Cert:")); hCert->addWidget(certEdit); hCert->addWidget(certBtn);
    layout->addLayout(hCert);

    auto* hKey = new QHBoxLayout;
    keyEdit = new QLineEdit; keyEdit->setPlaceholderText("Private Key");
    keyBtn = new QPushButton("…");
    hKey->addWidget(new QLabel("Key:")); hKey->addWidget(keyEdit); hKey->addWidget(keyBtn);
    layout->addLayout(hKey);

    auto* hCA = new QHBoxLayout;
    caEdit = new QLineEdit; caEdit->setPlaceholderText("CA Cert");
    caBtn = new QPushButton("…");
    hCA->addWidget(new QLabel("CA:")); hCA->addWidget(caEdit); hCA->addWidget(caBtn);
    layout->addLayout(hCA);

    // Start/Stop Buttons
    auto* hBtns = new QHBoxLayout;
    startBtn = new QPushButton("Start Server");
    stopBtn = new QPushButton("Stop Server"); stopBtn->setEnabled(false);
    hBtns->addWidget(startBtn); hBtns->addWidget(stopBtn);
    layout->addLayout(hBtns);

    // ------------------- Tabs -------------------
    QTabWidget* tabs = new QTabWidget;
    layout->addWidget(tabs);

    // Log + Tabellen (Overview)
    logView = new QTextEdit; logView->setReadOnly(true);
    table = new QTableWidget(0, 3);
    table->setHorizontalHeaderLabels({"ID","Name","Value"});
    table->horizontalHeader()->setStretchLastSection(true);
    auditTable = new QTableWidget(0, 4);
    auditTable->setHorizontalHeaderLabels({"Zeit","Kategorie","User","Nachricht"});
    auditTable->horizontalHeader()->setStretchLastSection(true);

    QWidget* overview = new QWidget;
    QVBoxLayout* ovLayout = new QVBoxLayout(overview);
    ovLayout->addWidget(new QLabel("Log-Ausgabe:"));
    ovLayout->addWidget(logView);
    ovLayout->addWidget(new QLabel("DB:"));
    ovLayout->addWidget(table);
    ovLayout->addWidget(new QLabel("Audit:"));
    ovLayout->addWidget(auditTable);
    tabs->addTab(overview, "Overview");

    // Im Konstruktor, im Overview-Tab unter die Tabellen noch ein Chart packen:
    seriesTemp = new QLineSeries(); seriesTemp->setName("temp");
    seriesHum  = new QLineSeries(); seriesHum->setName("hum");
    seriesNum  = new QLineSeries(); seriesNum->setName("number");

    auto* chart = new QChart();
    chart->addSeries(seriesTemp);
    chart->addSeries(seriesHum);
    chart->addSeries(seriesNum);
    chart->legend()->setAlignment(Qt::AlignBottom);

    axisX = new QValueAxis(); axisX->setTitleText("t");
    axisY = new QValueAxis(); axisY->setTitleText("value");
    axisX->setLabelFormat("%d");
    axisY->setRange(0, 100);   // grob; wird gleich dynamisch
    chart->addAxis(axisX, Qt::AlignBottom);
    chart->addAxis(axisY, Qt::AlignLeft);
    for (auto* s : {seriesTemp, seriesHum, seriesNum}) {
        s->attachAxis(axisX);
        s->attachAxis(axisY);
    }

    chartView = new QChartView(chart);
    chartView->setRenderHint(QPainter::Antialiasing);
    ovLayout->addWidget(new QLabel("Live-Sensoren:"));
    ovLayout->addWidget(chartView);

    sensorTable = new QTableWidget(0, 4);
    sensorTable->setHorizontalHeaderLabels({"ts","device","name","value"});
    sensorTable->horizontalHeader()->setStretchLastSection(true);
    ovLayout->addWidget(new QLabel("Sensor Data:"));
    ovLayout->addWidget(sensorTable);


    // MQTT/Modbus Tab
    QWidget* mmTab = new QWidget;
    QVBoxLayout* mmLayout = new QVBoxLayout(mmTab);

    QHBoxLayout* mqttLayout = new QHBoxLayout;
    mqttTopicEdit = new QLineEdit; mqttTopicEdit->setPlaceholderText("Topic");
    mqttMsgEdit   = new QLineEdit; mqttMsgEdit->setPlaceholderText("Message");
    mqttSendBtn   = new QPushButton("Publish");
    mqttLayout->addWidget(new QLabel("MQTT:"));
    mqttLayout->addWidget(mqttTopicEdit);
    mqttLayout->addWidget(mqttMsgEdit);
    mqttLayout->addWidget(mqttSendBtn);
    mmLayout->addLayout(mqttLayout);

    QHBoxLayout* mbLayout = new QHBoxLayout;
    modbusAddrEdit = new QLineEdit; modbusAddrEdit->setPlaceholderText("Addr");
    modbusValEdit  = new QLineEdit; modbusValEdit->setPlaceholderText("Value");
    modbusSetBtn   = new QPushButton("Write");
    mbLayout->addWidget(new QLabel("Modbus:"));
    mbLayout->addWidget(modbusAddrEdit);
    mbLayout->addWidget(modbusValEdit);
    mbLayout->addWidget(modbusSetBtn);
    mmLayout->addLayout(mbLayout);

    modbusTable = new QTableWidget(0, 2);
    modbusTable->setHorizontalHeaderLabels({"Addr","Value"});
    modbusTable->horizontalHeader()->setStretchLastSection(true);
    mmLayout->addWidget(modbusTable);

    tabs->addTab(mmTab, "MQTT/Modbus");

    // --- Admin/OTA Tab ---
    QWidget* adminTab = new QWidget;
    QVBoxLayout* adminLayout = new QVBoxLayout(adminTab);
    // --- Devices Panel ---
    // --- Devices Panel ---
    auto* devBox = new QGroupBox("Devices");
    auto* devLay = new QVBoxLayout(devBox);

    // obere Zeile
    auto* devTop = new QHBoxLayout;
    devKeyEdit = new QLineEdit;
    devKeyEdit->setPlaceholderText("key_id (leer = auto)");
    devFwEdit  = new QLineEdit;
    devFwEdit->setPlaceholderText("firmware (optional)");
    devEnChk   = new QCheckBox("enabled");
    devEnChk->setChecked(true);

    devCreateBtn = new QPushButton("Create");
    devToggleBtn = new QPushButton("Enable/Disable");
    devRotateBtn = new QPushButton("Rotate Secret");
    devDeleteBtn = new QPushButton("Delete");

    devTop->addWidget(new QLabel("Device:"));
    devTop->addWidget(devKeyEdit);
    devTop->addWidget(devFwEdit);
    devTop->addWidget(devEnChk);
    devTop->addWidget(devCreateBtn);
    devTop->addWidget(devToggleBtn);
    devTop->addWidget(devRotateBtn);
    devTop->addWidget(devDeleteBtn);

    devLay->addLayout(devTop);

    // Tabelle
    // wird als Membervariable gesetzt //QTableWidget* devTable = new QTableWidget(0, 5);
    devTable = new QTableWidget(0, 5);
    devTable->setHorizontalHeaderLabels({"ID","key_id","enabled","firmware","last_seen"});
    devTable->horizontalHeader()->setStretchLastSection(true);
    devLay->addWidget(devTable);

    adminLayout->addWidget(devBox); // an dein Admin/OTA-Tab anhängen

    // Firmware-Upload
    QHBoxLayout* upLayout = new QHBoxLayout;
    otaFileEdit = new QLineEdit; otaFileEdit->setPlaceholderText("Firmware-Datei (.bin)...");
    QPushButton* otaBrowseBtn = new QPushButton("Datei wählen");
    QPushButton* otaUploadBtn = new QPushButton("Upload");
    upLayout->addWidget(new QLabel("Firmware:"));
    upLayout->addWidget(otaFileEdit);
    upLayout->addWidget(otaBrowseBtn);
    upLayout->addWidget(otaUploadBtn);
    adminLayout->addLayout(upLayout);

    // Zuweisung: Device + File
    QHBoxLayout* assignLayout = new QHBoxLayout;
    assignDevKeyEdit = new QLineEdit; assignDevKeyEdit->setPlaceholderText("device_key (key_id)");
    otaFileCombo = new QComboBox; // wird unten befüllt
    QPushButton* assignBtn = new QPushButton("Job zuweisen");
    assignLayout->addWidget(new QLabel("Device:"));
    assignLayout->addWidget(assignDevKeyEdit);
    assignLayout->addWidget(new QLabel("File:"));
    assignLayout->addWidget(otaFileCombo);
    assignLayout->addWidget(assignBtn);
    adminLayout->addLayout(assignLayout);

    // Tabellen: OTA Files + Jobs
    otaFilesTable = new QTableWidget(0, 4);
    otaFilesTable->setHorizontalHeaderLabels({"ID","Name","Size","SHA256"});
    otaFilesTable->horizontalHeader()->setStretchLastSection(true);

    otaJobsTable = new QTableWidget(0, 5);
    otaJobsTable->setHorizontalHeaderLabels({"JobID","Device","FileID","State","Progress"});
    otaJobsTable->horizontalHeader()->setStretchLastSection(true);

    adminLayout->addWidget(new QLabel("Firmware-Dateien:"));
    adminLayout->addWidget(otaFilesTable);
    adminLayout->addWidget(new QLabel("OTA-Jobs:"));
    adminLayout->addWidget(otaJobsTable);

    tabs->addTab(adminTab, "Admin/OTA");

    setCentralWidget(central);
    loadSettings();

    otaJobsTable = otaJobsTable;

    // ------------------- Storage -------------------
    storage = new Storage(this);
    bool adminCreated = storage->seedAdminIfEmpty();
    if (adminCreated)  {log("[DB] Default-Admin angelegt: admin / secret_admin");
                        qDebug() << "[seedAdminIfEmpty] angelegt";}
    else               {log("[DB] Admin existiert bereits");
                        qDebug() << "[seedAdminIfEmpty] Admin existiert bereits";
                        }

    connect(storage, &Storage::auditInserted, this,
            [this](const QString& cat, const QString& user, const QString& msg){
                int row = auditTable->rowCount();
                auditTable->insertRow(row);
                auditTable->setItem(row,0,new QTableWidgetItem(QDateTime::currentDateTime().toString()));
                auditTable->setItem(row,1,new QTableWidgetItem(cat));
                auditTable->setItem(row,2,new QTableWidgetItem(user));
                auditTable->setItem(row,3,new QTableWidgetItem(msg));
            });

    connect(storage, &Storage::dataInserted, this,
            [this](const QString& name, const QString& value){
                int row = table->rowCount();
                table->insertRow(row);
                table->setItem(row,0,new QTableWidgetItem(QString::number(row+1)));
                table->setItem(row,1,new QTableWidgetItem(name));
                table->setItem(row,2,new QTableWidgetItem(value));
            });

    refreshDevices();

    //storage->createAdmin();    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // 3a) Refresh-Funktion als Lambda (lokal im Konstruktor)
  /*  auto refreshDevices = [this]{
        devTable->setRowCount(0);
        auto q = storage->listDevices(500, 0); // erwartet: id,key_id,enabled,firmware,last_seen
        while (q.next()) {
            const int row = devTable->rowCount(); devTable->insertRow(row);
            devTable->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));                // id
            devTable->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));                // key_id
            devTable->setItem(row,2,new QTableWidgetItem(q.value(2).toInt()!=0 ? "1":"0"));      // enabled
            devTable->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));                // firmware
            devTable->setItem(row,4,new QTableWidgetItem(q.value(4).toString()));                // last_seen
        }
    };
    refreshDevices();
    */
    // 3b) Buttons verbinden
  /*  connect(devCreateBtn, &QPushButton::clicked, this, [this]{
        QString key = devKeyEdit->text().trimmed();
        const QString fw = devFwEdit->text().trimmed();
        const bool en = devEnChk->isChecked();

        if (key.isEmpty())
            key = QUuid::createUuid().toString(QUuid::WithoutBraces).replace("-", "");

        QString secret; // leer => Storage generiert eins
        if (!storage->createDevice(key, secret, en, fw)) {
            log("[DEV] create failed");
            return;
        }
        // Secret ANZEIGEN, damit du es in Postman/Device nutzen kannst:

        QMessageBox::information(this, "Device created",
                                 QString("key_id: %1\nsecret (Base64url): %2").arg(key, secret));

        log(QString("[DEV] created key=%1 enabled=%2 fw=%3").arg(key).arg(en?"1":"0").arg(fw));
        refreshDevices(); // Tabelle neu laden
    }); */

    connect(devCreateBtn, &QPushButton::clicked, this, [this]{
        QString key = devKeyEdit->text().trimmed();
        const QString fw = devFwEdit->text().trimmed();
        const bool en = devEnChk->isChecked();

        if (key.isEmpty())
            key = QUuid::createUuid().toString(QUuid::WithoutBraces).replace("-", "");

        // ← leer rein, gefüllt raus (kommt aus Storage::createDevice)
        QString secret;
        if (!storage->createDevice(key, secret, en, fw)) {
            log("[DEV] create failed");
            return;
        }

        QMessageBox::information(this, "Device created",
                                 QString("key_id: %1\nsecret (Base64url): %2")
                                     .arg(key, secret));

        log(QString("[DEV] created key=%1 enabled=%2 fw=%3")
                .arg(key).arg(en ? "1" : "0").arg(fw));
        refreshDevices();
    });

    connect(devToggleBtn, &QPushButton::clicked, this, [=]{
        auto* it = devTable->currentItem(); if (!it) return;
        const int row = it->row();
        const QString key = devTable->item(row,1)->text();
        const bool en = (devTable->item(row,2)->text()!="0");
        if (!storage->updateDeviceEnabled(key, !en)) {
            log("[DEV] toggle failed");
            return;
        }
        refreshDevices();
    });

    connect(devRotateBtn, &QPushButton::clicked, this, [this]{
        auto* it = devTable->currentItem(); if (!it) { log("[DEV] bitte Zeile wählen"); return; }
        const int row = it->row();
        const QString key = devTable->item(row,1)->text();

        QByteArray rnd(32, Qt::Uninitialized);
        for (int i = 0; i < rnd.size(); ++i)
            rnd[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));
        const QString newSec = rnd.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

        if (!storage->updateDeviceSecret(key, newSec)) {
            log("[DEV] rotate failed");
            return;
        }
        QMessageBox::information(this, "Secret rotated",
                                 QString("key_id: %1\nNEW secret (Base64url): %2").arg(key, newSec));
        log(QString("[DEV] rotated secret key=%1").arg(key));
    });

    connect(devDeleteBtn, &QPushButton::clicked, this, [=]{
        auto* it = devTable->currentItem(); if (!it) return;
        const int row = it->row();
        const QString key = devTable->item(row,1)->text();
        if (!storage->deleteDevice(key)) {
            log("[DEV] delete failed");
            return;
        }
        refreshDevices();
    });

    // ------------------- Buttons -------------------
    connect(startBtn, &QPushButton::clicked, this, &MainWindow::startServer);
    connect(stopBtn,  &QPushButton::clicked, this, &MainWindow::stopServer);

    connect(docBtn, &QPushButton::clicked, this, [this]{
        QString dir = QFileDialog::getExistingDirectory(this,"Document Root");
        if(!dir.isEmpty()) docRootEdit->setText(dir);
    });
    connect(certBtn, &QPushButton::clicked, this, [this]{
        QString file = QFileDialog::getOpenFileName(this,"Zertifikat");
        if(!file.isEmpty()) certEdit->setText(file);
    });
    connect(keyBtn, &QPushButton::clicked, this, [this]{
        QString file = QFileDialog::getOpenFileName(this,"Key");
        if(!file.isEmpty()) keyEdit->setText(file);
    });
    connect(caBtn, &QPushButton::clicked, this, [this]{
        QString file = QFileDialog::getOpenFileName(this,"CA Cert");
        if(!file.isEmpty()) caEdit->setText(file);
    });

    jobsRefreshTimer = new QTimer(this);
    connect(jobsRefreshTimer, &QTimer::timeout, this, [this]{
        refreshOtaJobs(otaJobsTable);
    });
    jobsRefreshTimer->start(1500); // alle 1.5s

    connect(otaJobsTable, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* it){
        const int row = it->row();
        const qint64 jobId = otaJobsTable->item(row,0)->text().toLongLong();
        const QString dev  = otaJobsTable->item(row,1)->text();
        const qint64 fid   = otaJobsTable->item(row,2)->text().toLongLong();
        const QString st   = otaJobsTable->item(row,3)->text();
        log(QString("[OTA] Job %1 (%2) file=%3 state=%4").arg(jobId).arg(dev).arg(fid).arg(st));
    });

    connect(storage, &Storage::sensorInserted, this,
            [this](const QString& dev, const QString& name, const QString& value, qint64 ts){
                log(QString("[UI] sensorInserted dev=%1 %2=%3 ts=%4").arg(dev, name, value).arg(ts));
                refreshSensorTable();

                // -> Diagramm live updaten (statt über dataInserted)
                bool ok=false; const double v = value.toDouble(&ok);
                if (!ok) return;
                ++sampleIndex;
                if (name == "temp")      seriesTemp->append(sampleIndex, v);
                else if (name == "hum")  seriesHum->append(sampleIndex, v);

                // Autoscale
                double minY = 0, maxY = 100;
                for (auto* s : {seriesTemp, seriesHum, seriesNum}) {
                    for (const auto &p : s->pointsVector()) {
                        if (p.y() < minY) minY = p.y();
                        if (p.y() > maxY) maxY = p.y();
                    }
                }
                if (minY < maxY) axisY->setRange(std::floor(minY)-1, std::ceil(maxY)+1);
                axisX->setRange(std::max<qint64>(0, sampleIndex-200), sampleIndex+5);
            });
/*
    // Datenquelle: dein Storage-Signal
    connect(storage, &Storage::dataInserted, this,
            [this](const QString& name, const QString& value){
                bool ok=false; const double v = value.toDouble(&ok);
                if (!ok) return;
                ++sampleIndex;
                if (name == "temp")   seriesTemp->append(sampleIndex, v);
                else if (name == "hum")    seriesHum->append(sampleIndex, v);
                else if (name == "number") seriesNum->append(sampleIndex, v);

                // Autoscale Y (einfach)
                double minY = 0, maxY = 100;
                for (auto* s : {seriesTemp, seriesHum, seriesNum}) {
                    for (const auto &p : s->pointsVector()) {
                        if (p.y() < minY) minY = p.y();
                        if (p.y() > maxY) maxY = p.y();
                    }
                }
                if (minY < maxY) { axisY->setRange(std::floor(minY)-1, std::ceil(maxY)+1); }
                axisX->setRange(std::max<qint64>(0, sampleIndex-200), sampleIndex+5); // „scrollendes“ Fenster
            });

    connect(storage, &Storage::sensorInserted, this,
            [this](const QString& dev, const QString& name, const QString& value, qint64 ts){
                // Debug, damit du siehst, dass Signal kommt:
                log(QString("[UI] sensorInserted dev=%1 %2=%3 ts=%4")
                        .arg(dev, name, value).arg(ts));
                refreshSensorTable(); // oder gezielt nur eine Zeile anhängen
            });
*/
    // Datei wählen
    // Datei wählen
    connect(otaBrowseBtn, &QPushButton::clicked, this, [this]{
        QString p = QFileDialog::getOpenFileName(this, "Firmware wählen", QString(), "Binärdateien (*.bin);;Alle Dateien (*.*)");
        if (!p.isEmpty()) otaFileEdit->setText(p);
    });

    // Upload
    connect(otaUploadBtn, &QPushButton::clicked, this, [this]{
        if (currentDocRoot.isEmpty()) { log("[OTA] DocRoot ist leer – bitte Server starten"); return; }

        const QString src = otaFileEdit->text().trimmed();
        if (src.isEmpty()) { log("[OTA] Bitte Datei wählen"); return; }

        QFile in(src);
        if (!in.open(QIODevice::ReadOnly)) { log("[OTA] Datei kann nicht gelesen werden"); return; }
        const QByteArray data = in.readAll(); in.close();

        QDir out(currentDocRoot + "/ota");
        if (!out.exists()) out.mkpath(".");
        const QString name = QFileInfo(src).fileName();
        const QString dst  = out.filePath(name);

        QFile f(dst);
        if (!f.open(QIODevice::WriteOnly)) { log("[OTA] Ziel kann nicht geschrieben werden"); return; }
        f.write(data);
        f.close();

        const QByteArray shaHex = QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex();

        qint64 fileId = 0;
        if (!storage->insertOtaFile(name, dst, data.size(), QString::fromLatin1(shaHex), &fileId)) {
            log("[OTA] DB-Insert fehlgeschlagen");
            return;
        }
        log(QString("[OTA] Upload ok: id=%1 name=%2").arg(fileId).arg(name));

        refreshOtaFiles(otaFilesTable, otaFileCombo);
    });

    // Job zuweisen
    connect(assignBtn, &QPushButton::clicked, this, [this]{
        //const QString key = devKeyEdit->text().trimmed();
        const QString key = assignDevKeyEdit->text().trimmed();
        if (key.isEmpty()) { log("[OTA] device_key fehlt"); return; }
        const qint64 fileId = otaFileCombo->currentData().toLongLong();
        if (fileId <= 0) { log("[OTA] Datei auswählen"); return; }

        qint64 jobId = 0;
        if (!storage->createOtaJob(key, fileId, &jobId)) {
            log("[OTA] createOtaJob fehlgeschlagen"); return;
        }
        log(QString("[OTA] Job angelegt: job_id=%1 device=%2 file_id=%3").arg(jobId).arg(key).arg(fileId));
        refreshOtaJobs(otaJobsTable);
    });

    // ------------------- StateMachine -------------------
    setupAppStateMachine();

    // ------------------- MQTT + Modbus -------------------
    mqtt = new MqttClient(this);
    connect(mqtt, &MqttClient::log, this, [this](const QString& m){ log("[MQTT] " + m); });

    modbus = new ModbusServer(this);
    connect(modbus, &ModbusServer::log, this, [this](const QString& m){ log("[MODBUS] " + m); });

    // Brücke Modbus -> MQTT
    connect(modbus, &ModbusServer::registerChanged,
            this, [this](int addr, quint16 val){
                if (mqtt)
                    mqtt->publishMessage(QString("modbus/value/%1").arg(addr),
                                         QString::number(val));
            });

    // Brücke MQTT -> Modbus
    connect(mqtt, &MqttClient::commandReceived,
            this, [this](int addr, quint16 val){
                if (modbus)
                    modbus->setRegisterValue(addr, val);
            });

    // GUI Buttons für MQTT/Modbus
    connect(mqttSendBtn, &QPushButton::clicked, this, [this]{
        if (mqtt)
            mqtt->publishMessage(mqttTopicEdit->text(), mqttMsgEdit->text());
    });
    connect(modbusSetBtn, &QPushButton::clicked, this, [this]{
        bool ok1=false, ok2=false;
        int addr = modbusAddrEdit->text().toInt(&ok1);
        quint16 val = modbusValEdit->text().toUShort(&ok2);
        if (ok1 && ok2 && modbus)
            modbus->setRegisterValue(addr, val);
    });
    connect(modbus, &ModbusServer::registerChanged,
            this, [this](int addr, quint16 val){
                int rows = modbusTable->rowCount();
                bool found=false;
                for (int i=0;i<rows;i++) {
                    if (modbusTable->item(i,0)->text().toInt() == addr) {
                        modbusTable->item(i,1)->setText(QString::number(val));
                        found=true;
                        break;
                    }
                }
                if (!found) {
                    int r = modbusTable->rowCount();
                    modbusTable->insertRow(r);
                    modbusTable->setItem(r,0,new QTableWidgetItem(QString::number(addr)));
                    modbusTable->setItem(r,1,new QTableWidgetItem(QString::number(val)));
                }
            });
}

/**
 * Destruktor
 */
MainWindow::~MainWindow() {
    saveSettings();
    stopServer();
}

/**
 * StateMachine Setup
 */
void MainWindow::setupAppStateMachine() {
    appMachine = new QStateMachine(this);

    idle    = new QState();
    running = new QState();
    error   = new QState();

    collecting = new QState(running);
    drawing    = new QState(running);
    running->setInitialState(collecting);

    idle->addTransition(startBtn, &QPushButton::clicked, running);
    running->addTransition(stopBtn, &QPushButton::clicked, idle);
    running->addTransition(this, &MainWindow::errorOccurred, error);
    error->addTransition(startBtn, &QPushButton::clicked, running);

    // helper:
    auto setPill = [this](const QString& txt, const QString& color){
        stateLabel->setText("State: " + txt);
        stateLabel->setStyleSheet(QString("QLabel { padding:4px 8px; border-radius:8px; color:white; background:%1; }").arg(color));
        statePulse->stop();
        statePulse->setDirection(QAbstractAnimation::Forward);
        statePulse->start();
    };

    connect(idle, &QState::entered, this, [=]{ setPill("Idle", "#777"); });
    connect(running, &QState::entered, this, [=]{ setPill("Running", "#2d7"); });
    connect(error, &QState::entered, this, [=]{ setPill("Error", "#d44"); });

    connect(collecting, &QState::entered, this, [=]{ setPill("Collecting", "#0366d6"); });
    connect(drawing,    &QState::entered, this, [=]{ setPill("Drawing",    "#8a2be2"); });
    /*
    connect(idle, &QState::entered, this, [this]{ log("System → Idle"); });
    connect(running, &QState::entered, this, [this]{ log("System → Running"); });
    connect(error, &QState::entered, this, [this]{ log("System → Error"); });

    connect(collecting, &QState::entered, this, [this]{ log("Running → CollectingData"); });
    connect(drawing, &QState::entered, this, [this]{ log("Running → DrawingGraphs"); });
    */
    collecting->addTransition(this, &MainWindow::switchToDrawing, drawing);
    drawing->addTransition(this, &MainWindow::switchToCollecting, collecting);

    QTimer* t = new QTimer(this);
    connect(t, &QTimer::timeout, this, [this]{
        if (appMachine->configuration().contains(collecting))
            emit switchToDrawing();
        else
            emit switchToCollecting();
    });
    t->start(5000);

    appMachine->addState(idle);
    appMachine->addState(running);
    appMachine->addState(error);
    appMachine->setInitialState(idle);
    appMachine->start();
}

/**
 * Server starten
 */
void MainWindow::startServer() {
    if (server || wsServer) return;

    bool ok=false;
    quint16 httpsPort = portEdit->text().toUShort(&ok);
    if (!ok || httpsPort==0) { log("Ungültiger HTTPS-Port"); return; }
    quint16 wsPort = wsPortEdit->text().toUShort(&ok);
    if (!ok || wsPort==0) { log("Ungültiger WS-Port"); return; }

    QFile fcert(certEdit->text()), fkey(keyEdit->text()), fca(caEdit->text());
    if (!fcert.open(QIODevice::ReadOnly)) { log("Cert fehlt"); return; }
    if (!fkey.open(QIODevice::ReadOnly))  { log("Key fehlt"); return; }

    auto certs = QSslCertificate::fromData(fcert.readAll(), QSsl::Pem);
    if (certs.isEmpty()) { log("Ungültiges Zertifikat"); return; }
    QSslCertificate serverCert = certs.first();
    QSslKey serverKey(fkey.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);

    QList<QSslCertificate> caCerts;
    if (fca.open(QIODevice::ReadOnly))
        caCerts = QSslCertificate::fromData(fca.readAll(), QSsl::Pem);

    server = new HttpsServer(this);
    // ❶ Gemeinsames Secret definieren (einmalig):
    const QByteArray jwtSecret = QByteArray("supersecret-change-me-32b"); // TODO: aus Settings laden
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /*
    // Secret entweder aus dir laden, wenn keins da, dann erzeugen
QSettings s("MyCompany","QtSecureServer");

QByteArray jwtSecret;
{
    const QString key = "security/jwtSecretB64Url";
    QString enc = s.value(key).toString();

    if (enc.isEmpty()) {
        // einmalig erzeugen (32 Byte), als Base64url speichern
        const QByteArray raw = randomBytes(32);
        enc = QString::fromLatin1(b64url(raw));
        s.setValue(key, enc);
        s.sync();
    }

    // in Bytes dekodieren, das ist dein echter HMAC-Key
    jwtSecret = b64urlDecode(enc.toLatin1());
}

// (optional) Debug: nur Hash loggen, nie das Secret
#ifdef QT_DEBUG
qDebug() << "[JWT] secret.sha256 ="
         << QCryptographicHash::hash(jwtSecret, QCryptographicHash::Sha256).toHex();
#endif

//Hilfsfunktionen
static QByteArray randomBytes(int n) {
    QByteArray r(n, Qt::Uninitialized);
    QRandomGenerator::global()->generate(
        reinterpret_cast<quint32*>(r.data()),
        reinterpret_cast<quint32*>(r.data()) + (n/sizeof(quint32)));
    return r;

//////// Funktion zum Secret rotieren
void MainWindow::rotateJwtSecret() {
    QSettings s("MyCompany","QtSecureServer");
    const QByteArray raw = randomBytes(32);
    s.setValue("security/jwtSecretB64Url", QString::fromLatin1(b64url(raw)));
    s.sync();
    QMessageBox::information(this, "JWT Secret rotiert",
        "Das neue Secret ist gespeichert. Bitte Server neu starten.\n"
        "Hinweis: Alle existierenden Tokens werden ungültig.");
}
    */



    HttpsConfig cfg;
    cfg.serverCert = serverCert;
    cfg.serverKey  = serverKey;
    cfg.caCerts    = caCerts;
    cfg.requireClientCert = (modeBox->currentIndex()==1);
    //cfg.documentRoot = docRootEdit->text();
    cfg.documentRoot = "C:/Users/tnims/Documents/nBS1_00/Server2mTLSTest2/Server2mTLSTest/Server2mTLSTest/web";
    currentDocRoot = cfg.documentRoot;
    QDir(currentDocRoot).mkpath("ota");
    cfg.jwtSecret = jwtSecret;               // ❷ Auch fürs HTTP/Login setzen!
    cfg.storage   = storage;                 // gemeinsame Storage-Instanz

    // Broadcast-Lambda „laut“ machen:
    cfg.wsBroadcast = [this](const QString& msg) {
        int sent = 0;
        if (wsServer) sent = wsServer->broadcast(msg); // gibt Anzahl gesendeter zurück
        log(QString("[WS] broadcast '%1' -> %2 clients").arg(msg).arg(sent));
    };
    cfg.onNumber = [this](int n){
        storage->insertData("number", QString::number(n));
        log(QString("Gespeichert: %1").arg(n));
        refreshTable();
        // 🔹 Live-Update via WebSocket-Broadcast
        if (wsServer)
            wsServer->broadcast(QString("{\"value\":%1}").arg(n));
    };
    cfg.log = [this](const QString& s){ log(s); };     ///////////////////////////// Log enabled -> landet im GUI-Logfenster
    cfg.audit = [this](const QString& cat,const QString& msg){
        storage->insertAudit(cat,"system",msg);
        refreshAudit();
    };
    cfg.storage = storage;  // << die eine Storage-Instanz durchreichen
    server->setConfig(cfg);
    if (!server->listen(QHostAddress::Any, httpsPort)) {
        log("HTTPS Listen fehlgeschlagen: " + server->errorString());
        emit errorOccurred();
        return;
    }

    // WebSocket-Server starten (neuer Stil)
    WsConfig wsCfg;
    wsCfg.port = wsPort;
    wsCfg.jwtSecret = jwtSecret;             // ❸ Gleiches Secret wie HTTP!
    wsCfg.serverCert = serverCert;
    wsCfg.serverKey  = serverKey;
    wsCfg.caCerts    = caCerts;
    wsCfg.requireClientCert = (modeBox->currentIndex() == 1);

    wsServer = new WsServer(this);
    connect(wsServer, &WsServer::log, this, [this](const QString& s){ log("[WS] " + s); });
    connect(wsServer, &WsServer::audit, this,
            [this](const QString& cat, const QString& user, const QString& msg){
                storage->insertAudit(cat, user, msg);
                refreshAudit();
            });

    wsServer->setConfig(wsCfg);
    if (!wsServer->listen()) {
        log("WS Listen fehlgeschlagen");
        emit errorOccurred();
        return;
    }

    connect(wsServer, &WsServer::sensorEvent, this,
            [this](const QString& dev, const QJsonObject& vals, qint64 ts){
                if (vals.contains("temp")) {
                    bool ok = false;
                    double v = vals.value("temp").toVariant().toDouble(&ok);
                    if (ok) { ++sampleIndex; seriesTemp->append(sampleIndex, v); }
                }
                if (vals.contains("hum")) {
                    bool ok = false;
                    double v = vals.value("hum").toVariant().toDouble(&ok);
                    if (ok) { ++sampleIndex; seriesHum->append(sampleIndex, v); }
                }

                // (optional) Autoscale:
                if (axisX && sampleIndex > axisX->max())
                    axisX->setMax(sampleIndex);
                // Y-Achse kannst du ähnlich anpassen, z.B. min/max clampen oder dynamisch rechnen.
            });

    connect(wsServer, &WsServer::otaProgress, this,
            [this](const QString& dev, qint64 jobId, const QString& state, int progress){
                upsertJobRow(jobId, dev, /*fileId bleibt*/ 0, state, progress);
            });
/*
    // WebSocket-Server starten
    wsServer = new WsServer(this);
    connect(wsServer, &WsServer::log, this, [this](const QString& s){ log("[WS] "+s); });
    connect(wsServer, &WsServer::audit, this, [this](const QString& c,const QString& m){
        storage->insertAudit(c,"ws",m);
        refreshAudit();
    });

    if (!wsServer->start(wsPort, "changeme-secret")) {
        log("WS Listen fehlgeschlagen");
        emit errorOccurred();
        return;
    }
    */
    log("Server gestartet");
    startBtn->setEnabled(false);
    stopBtn->setEnabled(true);

    refreshTable();
    refreshAudit();
}

/**
 * Server stoppen
 */
void MainWindow::stopServer() {
    if (server) { server->close(); server->deleteLater(); server=nullptr; }
    if (wsServer) { wsServer->stop(); wsServer->deleteLater(); wsServer=nullptr; }
    log("Server gestoppt");
    startBtn->setEnabled(true);
    stopBtn->setEnabled(false);
}

/**
 * Log + Tabellen Refresh
 */
void MainWindow::log(const QString& s) {
    if (logView) logView->append(s);
}

void MainWindow::addAudit(const QString& cat, const QString& msg) {
    int row = auditTable->rowCount();
    auditTable->insertRow(row);
    auditTable->setItem(row,0,new QTableWidgetItem(QDateTime::currentDateTime().toString()));
    auditTable->setItem(row,1,new QTableWidgetItem(cat));
    auditTable->setItem(row,2,new QTableWidgetItem("system"));
    auditTable->setItem(row,3,new QTableWidgetItem(msg));
}

void MainWindow::refreshTable() {
    auto q = storage->selectLatest(100);
    table->setRowCount(0);
    while (q.next()) {
        int row = table->rowCount(); table->insertRow(row);
        table->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
        table->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
        table->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
    }
}

void MainWindow::refreshAudit() {
    auto q = storage->selectAudit(200);
    auditTable->setRowCount(0);
    while (q.next()) {
        int row = auditTable->rowCount(); auditTable->insertRow(row);
        auditTable->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
        auditTable->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
        auditTable->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
        auditTable->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));
    }
}

void MainWindow::refreshOtaFiles(QTableWidget* filesTable, QComboBox* fileCombo) {
    filesTable->setRowCount(0);
    fileCombo->clear();
    auto q = storage->listOtaFiles(); // implementiere: SELECT id,name,size,sha256 FROM ota_files ORDER BY id DESC

    while (q.next()) {
        const int row = filesTable->rowCount(); filesTable->insertRow(row);
        const qint64 id = q.value(0).toLongLong();
        const QString name = q.value(1).toString();
        const qint64 size = q.value(2).toLongLong();
        const QString sha = q.value(3).toString();
        filesTable->setItem(row,0,new QTableWidgetItem(QString::number(id)));
        filesTable->setItem(row,1,new QTableWidgetItem(name));
        filesTable->setItem(row,2,new QTableWidgetItem(QString::number(size)));
        filesTable->setItem(row,3,new QTableWidgetItem(sha));

        fileCombo->addItem(QString("%1 (%2 bytes)").arg(name).arg(size), id);
    }
}

void MainWindow::refreshOtaJobs(QTableWidget* table)
{
    if (!table) return;

    // Variante A: „sanftes Upsert“ (bestehende Zeilen behalten)
    // jobRow bleibt erhalten – neue/aktualisierte Jobs werden upserted

    auto q = storage->listOtaJobs(); // SELECT id,device_key,file_id,state,progress ...
    QSet<qint64> seen;               // welche Jobs in diesem Durchlauf existieren

    while (q.next()) {
        const qint64 jobId  = q.value(0).toLongLong();
        const QString dev    = q.value(1).toString();
        const qint64 fileId  = q.value(2).toLongLong();
        const QString state  = q.value(3).toString();
        const int progress   = q.value(4).toInt();

        seen.insert(jobId);
        upsertJobRow(jobId, dev, fileId, state, progress);
    }

    // (optional) Jobs entfernen, die es nicht mehr gibt:
    // -> wenn du das willst, mach eine Rückwärts-Schleife über table->rowCount()
    //    und entferne Zeilen, deren jobId nicht in 'seen' ist.
}

void MainWindow::upsertJobRow(qint64 jobId,
                              const QString& device,
                              qint64 fileId,
                              const QString& state,
                              int progress)
{
    int row = jobRow.value(jobId, -1);
    if (row < 0) {
        return;
      /*  row = otaJobsTable->rowCount();
        otaJobsTable->insertRow(row);
        jobRow.insert(jobId, row);

        // Spalten 0..3 sind QTableWidgetItem
        otaJobsTable->setItem(row, 0, new QTableWidgetItem(QString::number(jobId)));
        otaJobsTable->setItem(row, 1, new QTableWidgetItem(device));
        otaJobsTable->setItem(row, 2, new QTableWidgetItem(QString::number(fileId)));
        otaJobsTable->setItem(row, 3, new QTableWidgetItem(state));

        // Progressbar als CellWidget in Spalte 4
        auto* bar = new QProgressBar(otaJobsTable);
        bar->setRange(0,100);
        bar->setValue(qBound(0, progress, 100));
        bar->setTextVisible(true);
        otaJobsTable->setCellWidget(row, 4, bar);   */
    } else {
        // Update bestehender Zeile
        otaJobsTable->item(row, 1)->setText(device);
        otaJobsTable->item(row, 2)->setText(QString::number(fileId));
        otaJobsTable->item(row, 3)->setText(state);

        if (auto* w = otaJobsTable->cellWidget(row, 4)) {
            if (auto* bar = qobject_cast<QProgressBar*>(w)) {
                bar->setValue(qBound(0, progress, 100));
            }
        }
    }

    // State farblich
    styleStateCell(otaJobsTable->item(row, 3), state);
}

void MainWindow::loadSettings() {
    QSettings s("MyCompany","QtSecureServer");  // Namen frei wählen
    portEdit->setText( s.value("httpsPort", "8443").toString() );
    wsPortEdit->setText( s.value("wsPort", "9443").toString() );
    modeBox->setCurrentIndex( s.value("modeIndex", 0).toInt() );
    docRootEdit->setText( s.value("docRoot", docRootEdit->text()).toString() );
    certEdit->setText( s.value("certPath").toString() );
    keyEdit->setText(  s.value("keyPath").toString() );
    caEdit->setText(   s.value("caPath").toString() );
}

void MainWindow::saveSettings() {
    QSettings s("MyCompany","QtSecureServer");
    s.setValue("httpsPort", portEdit->text());
    s.setValue("wsPort",    wsPortEdit->text());
    s.setValue("modeIndex", modeBox->currentIndex());
    s.setValue("docRoot",   docRootEdit->text());
    s.setValue("certPath",  certEdit->text());
    s.setValue("keyPath",   keyEdit->text());
    s.setValue("caPath",    caEdit->text());
}

void MainWindow::styleStateCell(QTableWidgetItem* item, const QString& state)
{
    if (!item) return;
    // einfache Farben:
    QString bg = "#999";
    if (state == "queued")      bg = "#607D8B";
    else if (state == "downloading") bg = "#1976D2";
    else if (state == "installing")  bg = "#6A1B9A";
    else if (state == "done")        bg = "#2E7D32";
    else if (state == "failed")      bg = "#C62828";

    item->setText(state);
    item->setForeground(QBrush(Qt::white));
    item->setBackground(QColor(bg));
    // leicht fett:
    QFont f = item->font(); f.setBold(true); item->setFont(f);
}

void MainWindow::testRangeDownload(qint64 fileId) {
    if (fileId <= 0) { log("[OTA] bad fileId"); return; }

    // 1) Device-Key nehmen (aus dem Feld „Device“ im OTA-Panel)
    const QString keyId = assignDevKeyEdit->text().trimmed();
    if (keyId.isEmpty()) { log("[OTA] bitte device_key im Feld 'Device' angeben"); return; }

    // 2) Secret aus DB holen
    QString secret; bool enabled=false;
    if (!storage->findDevice(keyId, &secret, &enabled) || !enabled) {
        log("[OTA] device nicht gefunden oder disabled"); return;
    }

    // 3) Request bauen (Pfad muss exakt so in die Signatur!)
    const QString path = QString("/api/ota/file/%1").arg(fileId);
    const QUrl url(QStringLiteral("https://%1:%2%3")
                       .arg("127.0.0.1")
                       .arg(portEdit->text())
                       .arg(path));

    auto* nam = new QNetworkAccessManager(this);
    QNetworkRequest req(url);

    // (Optional) Selbstsigniertes Zertifikat zu Testzwecken tolerieren:
    // connect(nam, &QNetworkAccessManager::sslErrors, this,
    //         [this](QNetworkReply* r, const QList<QSslError>&){ r->ignoreSslErrors(); });

    req.setRawHeader("Range", "bytes=0-1023");

    // 4) HMAC-Header setzen (GET, leerer Body)
    setHmacHeaders(req, "GET", path, QByteArray(), keyId, secret);

    auto* rep = nam->get(req);
    connect(rep, &QNetworkReply::finished, this, [this,rep]{
        const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray data = rep->readAll();
        log(QString("[OTA] range status=%1 len=%2 err=%3")
                .arg(code).arg(data.size()).arg(rep->errorString()));
        rep->deleteLater();
    });
}

void MainWindow::refreshDevices() {
    if (!storage || !devTable) return;
    devTable->setRowCount(0);
    auto q = storage->listDevices(500, 0); // erwartet: id,key_id,enabled,firmware,last_seen
    while (q.next()) {
        const int row = devTable->rowCount(); devTable->insertRow(row);
        devTable->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));                // id
        devTable->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));                // key_id
        devTable->setItem(row,2,new QTableWidgetItem(q.value(2).toInt()!=0 ? "1":"0"));      // enabled
        devTable->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));                // firmware
        devTable->setItem(row,4,new QTableWidgetItem(q.value(4).toString()));                // last_seen
    }
}

void MainWindow::refreshSensorTable() {
    if (!storage || !sensorTable) return;
    sensorTable->setRowCount(0);

    QSqlQuery q = storage->selectLatestSensors(50);
    while (q.next()) {
        const int row = sensorTable->rowCount();
        sensorTable->insertRow(row);
        sensorTable->setItem(row, 0, new QTableWidgetItem(q.value(0).toString())); // ts
        sensorTable->setItem(row, 1, new QTableWidgetItem(q.value(1).toString())); // device_key
        sensorTable->setItem(row, 2, new QTableWidgetItem(q.value(2).toString())); // name
        sensorTable->setItem(row, 3, new QTableWidgetItem(q.value(3).toString())); // value
    }
}

/*
#include "MainWindow.h"
#include "../http/HttpsServer.h"
#include "../db/Storage.h"
#include "WsServer.h"   // 🔹 WebSocket-Server einbinden

#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QComboBox>

#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslKey>
#include <QtNetwork/QSslSocket>
#include <QtNetwork/QHostAddress>

#include <QtCore/QFile>
#include <QtCore/QDateTime>
#include <QtCore/QTextStream>
#include <QTimer>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("Qt TLS/mTLS HTTPS + WebSocket Server");
    auto* central = new QWidget(this);
    auto* v = new QVBoxLayout(central);

    // ------------------- Server-Konfiguration -------------------
    auto* r1 = new QHBoxLayout();
    modeBox = new QComboBox; modeBox->addItems({"TLS","mTLS"});
    portEdit = new QLineEdit; portEdit->setPlaceholderText("HTTPS Port"); portEdit->setText("8443");
    wsPortEdit = new QLineEdit; wsPortEdit->setPlaceholderText("WebSocket Port"); wsPortEdit->setText("9443");
    docRootEdit = new QLineEdit; docRootEdit->setPlaceholderText("Dokument-Root"); docRootEdit->setText("web");
    docBtn = new QPushButton("Ordner...");
    r1->addWidget(new QLabel("Modus:")); r1->addWidget(modeBox);
    r1->addWidget(new QLabel("HTTPS Port:")); r1->addWidget(portEdit);
    r1->addWidget(new QLabel("WS Port:")); r1->addWidget(wsPortEdit);
    r1->addWidget(new QLabel("DocRoot:")); r1->addWidget(docRootEdit); r1->addWidget(docBtn);
    v->addLayout(r1);

    // ------------------- Zertifikate -------------------
    auto* r2 = new QHBoxLayout();
    certEdit = new QLineEdit; certBtn = new QPushButton("Server-Zertifikat...");
    keyEdit  = new QLineEdit; keyBtn  = new QPushButton("Privater Schlüssel...");
    caEdit   = new QLineEdit; caBtn   = new QPushButton("CA-Zertifikat...");
    r2->addWidget(new QLabel("server.crt:")); r2->addWidget(certEdit); r2->addWidget(certBtn);
    r2->addWidget(new QLabel("server.key:")); r2->addWidget(keyEdit);  r2->addWidget(keyBtn);
    r2->addWidget(new QLabel("ca.crt:"));     r2->addWidget(caEdit);   r2->addWidget(caBtn);
    v->addLayout(r2);

    // ------------------- Start/Stop -------------------
    auto* r3 = new QHBoxLayout();
    startBtn = new QPushButton("Start"); stopBtn = new QPushButton("Stop"); stopBtn->setEnabled(false);
    r3->addWidget(startBtn); r3->addWidget(stopBtn);
    v->addLayout(r3);

    // ------------------- Log -------------------
    logView = new QTextEdit; logView->setReadOnly(true);
    v->addWidget(new QLabel("Log:")); v->addWidget(logView);

    // ------------------- Tabellen -------------------
    table = new QTableWidget(0,3);
    table->setHorizontalHeaderLabels({"ID","Wert","Zeit"});
    table->horizontalHeader()->setStretchLastSection(true);
    v->addWidget(new QLabel("SQLite: gespeicherte Zahlen"));
    v->addWidget(table);

    auditTable = new QTableWidget(0,4);
    auditTable->setHorizontalHeaderLabels({"ID","Kategorie","Nachricht","Zeit"});
    auditTable->horizontalHeader()->setStretchLastSection(true);
    auditTable->setSortingEnabled(true);
    v->addWidget(new QLabel("Audit-Log"));
    v->addWidget(auditTable);

    setCentralWidget(central);

    // ------------------- Storage -------------------
    storage = new Storage();
    if (!storage->open("numbers.db")) log("SQLite open fail: " + storage->error());
    refreshTable();
    refreshAudit();

    // ------------------- UI Events -------------------
    connect(certBtn,&QPushButton::clicked,this,[this]{ certEdit->setText(QFileDialog::getOpenFileName(this,"server.crt auswählen")); });
    connect(keyBtn,&QPushButton::clicked,this,[this]{ keyEdit->setText(QFileDialog::getOpenFileName(this,"server.key auswählen")); });
    connect(caBtn, &QPushButton::clicked,this,[this]{ caEdit->setText(QFileDialog::getOpenFileName(this,"ca.crt auswählen")); });
    connect(docBtn,&QPushButton::clicked,this,[this]{ docRootEdit->setText(QFileDialog::getExistingDirectory(this,"Dokument-Root wählen")); });

    connect(startBtn,&QPushButton::clicked,this,&MainWindow::startServer);
    connect(stopBtn, &QPushButton::clicked,this,&MainWindow::stopServer);
}

MainWindow::~MainWindow() {
    stopServer();
    delete storage;
}

// ------------------- Server-Start -------------------
void MainWindow::startServer() {
    if (server) return;

    bool ok=false; quint16 port = portEdit->text().toUShort(&ok);
    if (!ok || port==0) { log("Ungültiger HTTPS-Port"); return; }
    quint16 wsPort = wsPortEdit->text().toUShort(&ok);
    if (!ok || wsPort==0) { log("Ungültiger WebSocket-Port"); return; }

    // Zertifikate laden
    QFile fcert(certEdit->text()), fkey(keyEdit->text()), fca(caEdit->text());
    if (!fcert.open(QIODevice::ReadOnly)) { log("Kann server.crt nicht lesen"); return; }
    if (!fkey.open(QIODevice::ReadOnly))  { log("Kann server.key nicht lesen"); return; }

    const auto certs = QSslCertificate::fromData(fcert.readAll(), QSsl::Pem);
    if (certs.isEmpty()) { log("Ungültiges server.crt"); return; }
    const QSslCertificate serverCert = certs.first();
    const QSslKey serverKey(fkey.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    if (serverKey.isNull()) { log("Ungültiger server.key"); return; }
    QList<QSslCertificate> caCerts;
    if (fca.open(QIODevice::ReadOnly)) caCerts = QSslCertificate::fromData(fca.readAll(), QSsl::Pem);

    // HTTPS-Server starten
    server = new HttpsServer(this);
    HttpsConfig cfg;
    cfg.serverCert = serverCert;
    cfg.serverKey  = serverKey;
    cfg.caCerts    = caCerts;
    cfg.requireClientCert = (modeBox->currentIndex()==1);
    cfg.documentRoot = docRootEdit->text();
    cfg.onNumber = [this](int n){
        if (!storage->insertNumber(n)) log("Insert fail: " + storage->error());
        else { log(QString("Gespeichert: %1").arg(n)); refreshTable(); }
    };
    cfg.log = [this](const QString& s){ log(s); };
    cfg.audit = [this](const QString& category, const QString& msg){
        storage->insertAudit(category,msg); refreshAudit();
    };

    server->setConfig(cfg);
    if (!server->listen(QHostAddress::Any, port)) {
        log("HTTPS Listen fehlgeschlagen: " + server->errorString());
        server->deleteLater(); server=nullptr; return;
    }

    log(QString("HTTPS Server gestartet auf Port %1 (%2)")
            .arg(port).arg(cfg.requireClientCert? "mTLS":"TLS"));

    // WebSocket-Server starten
    wsServer = new WsServer(this);
    connect(wsServer, &WsServer::log, this, [this](const QString& s){ log("[WS] " + s); });
    connect(wsServer, &WsServer::audit, this, [this](const QString& c,const QString& m){
        storage->insertAudit(c,m); refreshAudit(); });
    connect(wsServer, &WsServer::stateChanged, this,
            [this](const QString& st, const QString& user){
                storage->insertAudit("ws-state",
                                     user.isEmpty() ? st : st + " user=" + user);
                refreshAudit();
            });

    if (!wsServer->start(wsPort, cfg.jwtSecret)) {
        log("WebSocket Listen fehlgeschlagen");
        wsServer->deleteLater(); wsServer=nullptr;
    }

    startBtn->setEnabled(false); stopBtn->setEnabled(true);
}

void MainWindow::stopServer() {
    if (server) { server->close(); server->deleteLater(); server=nullptr; }
    if (wsServer) { wsServer->stop(); wsServer->deleteLater(); wsServer=nullptr; }
    log("Server gestoppt");
    startBtn->setEnabled(true); stopBtn->setEnabled(false);
}

// ------------------- Tabellen-Refresh -------------------
void MainWindow::log(const QString& s) { if (logView) logView->append(s); }

void MainWindow::refreshTable() {
    auto q = storage->selectLatest(100);
    table->setRowCount(0);
    while (q.next()) {
        int row = table->rowCount(); table->insertRow(row);
        table->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
        table->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
        table->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
    }
}

void MainWindow::refreshAudit() {
    auto q = storage->selectAudit(200);
    auditTable->setRowCount(0);
    while (q.next()) {
        int row = auditTable->rowCount(); auditTable->insertRow(row);
        auditTable->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
        auditTable->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
        auditTable->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
        auditTable->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));
    }
}

void MainWindow::setupAppStateMachine() {
    appMachine = new QStateMachine(this);

    idle    = new QState();
    running = new QState();
    error   = new QState();

    // Substates of Running
    collecting = new QState(running);
    drawing    = new QState(running);
    running->setInitialState(collecting);

    // Übergänge
    idle->addTransition(startBtn, &QPushButton::clicked, running);
    running->addTransition(this, &MainWindow::errorOccurred, error);
    error->addTransition(stopBtn, &QPushButton::clicked, idle);

    // Entry-Actions
    connect(idle, &QState::entered, this, [this]{
        log("System → Idle");
        storage->insertAudit("system", "Idle");
    });
    connect(running, &QState::entered, this, [this]{
        log("System → Running");
        storage->insertAudit("system", "Running");
    });
    connect(error, &QState::entered, this, [this]{
        log("System → Error");
        storage->insertAudit("system", "Error");
    });

    // Substates
    connect(collecting, &QState::entered, this, [this]{
        log("Running → CollectingData");
        storage->insertAudit("system", "CollectingData");
    });
    connect(drawing, &QState::entered, this, [this]{
        log("Running → DrawingGraphs");
        storage->insertAudit("system", "DrawingGraphs");
    });

    // Toggle Collecting <-> Drawing alle 5 Sekunden (Demo)
    QTimer* t = new QTimer(this);
    connect(t, &QTimer::timeout, this, [this]{
        if (appMachine->configuration().contains(collecting))
            appMachine->postEvent(new QEvent(QEvent::Type(QEvent::User+1)));
        else
            appMachine->postEvent(new QEvent(QEvent::Type(QEvent::User+2)));
    });
    t->start(5000);

    collecting->addTransition(this, QEvent::User+1, drawing);
    drawing->addTransition(this, QEvent::User+2, collecting);

    appMachine->addState(idle);
    appMachine->addState(running);
    appMachine->addState(error);
    appMachine->setInitialState(idle);
    appMachine->start();
}
*/
