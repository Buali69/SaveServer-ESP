#pragma once
#include <QObject>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>

/**
 * Storage
 * -------
 * Verantwortlich für Zugriff auf SQLite-DB:
 *   - Messdaten
 *   - Audit-Logs
 *
 * Erbt jetzt von QObject → kann Signals/Slots nutzen.
 */
class Storage : public QObject {
    Q_OBJECT
public:
    explicit Storage(QObject* parent = nullptr);
     ~Storage() override {}                  // KEIN removeDatabase!

    // Datenbank-Zugriff
    QSqlQuery selectLatest(int limit = 100);
    QSqlQuery selectAudit(int limit = 200);
    QSqlQuery selectLatestSensors(int limit);

    QSqlQuery listOtaFiles(int limit=200, int offset=0);
    QSqlQuery listOtaJobs(int limit=200, int offset=0);

    bool findUser(const QString& user,
                  QByteArray* hash=nullptr,
                  QByteArray* salt=nullptr,
                  int* iterations=nullptr,
                  QString* role=nullptr);

    bool upsertUser(const QString& user,
                    const QByteArray& hash,
                    const QByteArray& salt,
                    int iterations,
                    const QString& role);

  //  static QByteArray pbkdf2HmacSha256(const QByteArray& password, const QByteArray& salt, int iterations, int dkLen);

    void createAdmin(void);
    bool seedAdminIfEmpty(const QString& user  = "admin",
                          const QString& pass  = "secret_admin",
                          const QString& role  = "admin",
                          int iters            = 100000);
    bool hasAnyUser() const;

    bool getOtaFile(qint64 fileId, QString* path, QString* name, qint64* size, QString* sha256);


    // Gerät anlegen/finden
    bool insertDevice(const QString& keyId, const QString& secret, const QString& firmware = QString());
    // Geräte-CRUD
    bool createDevice(const QString& keyId, QString& secretInOut, bool enabled, const QString& firmware);
    bool updateDeviceEnabled(const QString& keyId, bool enabled);
    bool updateDeviceSecret(const QString& keyId, const QString& newSecret);
    bool updateDeviceFirmware(const QString& keyId, const QString& firmware);
    bool updateDeviceLastSeen(const QString& keyId, qint64 ts);
    bool deleteDevice(const QString& keyId);

    // Liste/Details
    QSqlQuery listDevices(int limit = 200, int offset = 0);
    bool findDevice(const QString& keyId, QString* secret, bool* enabled,
                    QString* firmware = nullptr, qint64* lastSeen = nullptr);

    void insertData(const QString& name, const QString& value);
    void insertAudit(const QString& category,
                     const QString& user,
                     const QString& message);
    bool insertNonce(const QString& deviceId, const QString& nonce, qint64 ts);
    bool insertSensor(const QString& deviceId, const QString& name,
                      const QString& value, qint64 ts);
    // Dateien
    bool insertOtaFile(const QString& name,
                       const QString& path,
                       qint64 size,
                       const QString& sha256,
                       qint64* outId);

    // Jobs
    bool createOtaJob(const QString& deviceKey, qint64 fileId, qint64* outJobId);
    bool selectQueuedOtaJob(const QString& deviceKey,
                            qint64* jobId, qint64* fileId,
                            QString* fileName, qint64* size, QString* sha256);
    bool updateOtaJobState(qint64 jobId, const QString& state, int progress);
    QString lastErrorString() const { return lastErr_; }
    QString lastSqlString()   const { return lastSql_; }
    bool claimNextQueuedOtaJob(const QString& deviceKey,
                               qint64* jobId, qint64* fileId,
                               QString* fileName, qint64* size, QString* sha256);
    bool getOtaJobDevice(qint64 jobId, QString* deviceKeyOut);


signals:
    void dataInserted(const QString& name, const QString& value);   //alte Version ->nicht mehr verwenden!
    void auditInserted(const QString& category,
                       const QString& user,
                       const QString& message);
    void sensorInserted(const QString& deviceKey, const QString& name, const QString& value, qint64 ts);

private:
    QSqlDatabase db;
    void ensureSchema();
    QString lastErr_;
    QString lastSql_;

    // Helfer:
    bool execOrFail(QSqlQuery& q, const char* ctx);      // führt q.exec() aus + Fehlerlog
    bool fail(const QSqlQuery& q, const char* ctx);      // nur Fehler setzen/loggen

};



/*
#pragma once
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QtCore/QDateTime>
#include <QtCore/QString>

//SQL-Befehle sind standardisiert: CREATE, INSERT, SELECT, UPDATE, DELETE

class Storage {
public:
    Storage() = default;

    bool open(const QString& file = QStringLiteral("numbers.db")) {
        if (!db.isValid()) db = QSqlDatabase::addDatabase("QSQLITE");       //Ist Verbindung schon gültig, wenn nicht, neue anlegen
        db.setDatabaseName(file);                                           //Datei für DB setzen, auch Pfad möglich
        if (!db.open()) { lastErr = db.lastError().text(); return false; }  //DB öffnen
        QSqlQuery q;
        if (!q.exec("CREATE TABLE IF NOT EXISTS numbers("                   //Tabelle anlegen
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"                 //Mit ID, automatisch hochgezählt
                    "value INTEGER NOT NULL,"                               //value als Ganzzahl (welche übergeben wird)
                    "created_at TEXT NOT NULL)")) {                         //created_at als Text, Zeitstempel
            lastErr = q.lastError().text(); return false;
        }
        // Tabelle audit_log
        if (!q.exec("CREATE TABLE IF NOT EXISTS audit_log("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "category TEXT NOT NULL,"
                    "message TEXT NOT NULL,"
                    "created_at TEXT NOT NULL)")) {
            lastErr = q.lastError().text(); return false;
        }
        return true;
    }

    bool insertAudit(const QString& category, const QString& message) {
        QSqlQuery q;
        q.prepare("INSERT INTO audit_log(category, message, created_at) VALUES(?, ?, ?)");
        q.addBindValue(category);
        q.addBindValue(message);
        q.addBindValue(QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
        if (!q.exec()) { lastErr = q.lastError().text(); return false; }
        return true;
    }

    QSqlQuery selectAudit(int limit=200) {
        QSqlQuery q;
        q.exec(QString("SELECT id, category, message, created_at FROM audit_log ORDER BY id DESC LIMIT %1").arg(limit));
        return q;
    }


    bool insertNumber(int v) {
        QSqlQuery q;                                 //Mit Platzhalter sicherer gg SQL Injection
        q.prepare("INSERT INTO numbers(value, created_at) VALUES(?, ?)");   //SQL Statement vorbereiten, in Tabelle numbers, mit 2 Platzhaltern
        q.addBindValue(v);                                                  //Der erste Platzhalter ? wird mit v beschrieben, landet in Spalte value
        q.addBindValue(QDateTime::currentDateTimeUtc().toString(Qt::ISODate));   //2. ? Aktuelle Zeit landet in created_at
        if (!q.exec()) { lastErr = q.lastError().text(); return false; }    //Ausführen
        return true;
    }

    QSqlQuery selectLatest(int limit=100) {
        QSqlQuery q;   //Diese 3 Spalten werden gelesen / aus Tabelle numbers / sortiert nach id absteigend / Nur die ersten Zeilen bis Limit zurückgeben
        q.exec(QString("SELECT id,value,created_at FROM numbers ORDER BY id DESC LIMIT %1").arg(limit));  //SQL Abfrage zusammenbauen
        return q; // copy of handle
    }

    QString error() const { return lastErr; }

private:
    QSqlDatabase db;
    QString lastErr;
};
*/



/*
 * Konkrete Empfehlungen für deine Anwendung

Wenn die Daten nicht sensibel sind (Zahlen, nicht personenbezogen):

Einfach DB im App-Datenverzeichnis anlegen und Dateirechte einschränken.

Wenn die Daten vertraulich sind (z. B. personenbezogene Daten, Passwörter):

Nutze SQLCipher oder verschlüssele die Felder in der App.

Setze Dateirechte so restriktiv wie möglich.

Wenn mehrere Anwender / Netzwerkzugriff erforderlich:

Verwende eine Client-Server-Datenbank (Postgres/MySQL) mit Authentifizierung, statt SQLite-Datei.

6) Kurzer Code-Überblick: Datei erzeugen + Rechte setzen + Pfad verwenden
QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
QDir().mkpath(path);
QString file = path + QDir::separator() + "numbers.db";

QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
db.setDatabaseName(file);
if (!db.open()) {
    qWarning() << "DB open failed:" << db.lastError().text();
    return false;
}

// Rechte auf Eigentümer beschränken (POSIX)
QFile f(file);
if (f.exists()) {
    f.setPermissions(QFile::ReadOwner | QFile::WriteOwner);    //macht in Windows öfter Probleme (POSIX-Rechte z. B. rw------- / 0600).
}
*/
