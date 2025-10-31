#include "Storage.h"
#include <QDateTime>
#include <QDebug>
#include <QSqlQuery>
#include <QSqlError>
#include <QStandardPaths>
#include <QDir>
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>
#include "../common/crypto_helpers.h"
using crypto::pbkdf2HmacSha256;
using crypto::genSalt16;

static const char* kConnName = "appdb";   // eine gemeinsame Verbindung für die ganze App

Storage::Storage(QObject* parent) : QObject(parent)
{
    if (!QSqlDatabase::contains(kConnName)) {
        db = QSqlDatabase::addDatabase("QSQLITE", kConnName);
        const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir().mkpath(dir);
        db.setDatabaseName(dir + "/server.sqlite");
        if (!db.open()) {
            qWarning() << "[DB] open failed:" << db.lastError();
        }
        ensureSchema();
    } else {
        db = QSqlDatabase::database(kConnName);
    }
    qDebug() << "[DB] using" << db.connectionName() << db.databaseName();

/*
Storage::Storage(QObject* parent) : QObject(parent) {
    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("storage.sqlite");

    if (!db.open()) {
        qWarning() << "DB open error:" << db.lastError().text();
        return;
    }
*/
    QSqlQuery q(db);
    // Messdaten-Tabelle
    q.exec("CREATE TABLE IF NOT EXISTS data ("
           "id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "name TEXT,"
           "value TEXT,"
           "ts DATETIME DEFAULT CURRENT_TIMESTAMP)");

    // Audit-Tabelle
    q.exec("CREATE TABLE IF NOT EXISTS audit ("
           "id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "ts DATETIME DEFAULT CURRENT_TIMESTAMP,"
           "category TEXT,"
           "user TEXT,"
           "message TEXT)");
    q.exec("CREATE TABLE IF NOT EXISTS replay_nonce("
           ""
           "device_id TEXT, "
           "nonce TEXT, "
           "ts INTEGER, "
           "PRIMARY KEY(device_id,nonce))");


    q.exec(R"SQL(
            CREATE TABLE IF NOT EXISTS devices(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
              key_id   TEXT UNIQUE NOT NULL,
              secret   TEXT NOT NULL,
              enabled  INTEGER NOT NULL DEFAULT 1,
              firmware TEXT,
              last_seen INTEGER DEFAULT 0
            );
            )SQL");

                // Nonces: Replay-Schutz (einmalig verwendbar)
                q.exec(R"SQL(
            CREATE TABLE IF NOT EXISTS api_nonces(
              nonce  TEXT PRIMARY KEY,
              key_id TEXT NOT NULL,
              ts     INTEGER NOT NULL
            );
            )SQL");

                // Sensordaten (einfaches Schema, flexibel)
                q.exec(R"SQL(
            CREATE TABLE IF NOT EXISTS sensor_data(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              device_key TEXT NOT NULL,
              ts   INTEGER NOT NULL,
              name TEXT NOT NULL,
              value REAL
            );
            )SQL");

                // OTA-Dateien
                q.exec(R"SQL(
            CREATE TABLE IF NOT EXISTS ota_files(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              path TEXT NOT NULL,
              size INTEGER NOT NULL,
              sha256 TEXT NOT NULL,
              uploaded_at INTEGER NOT NULL
            );
            )SQL");

                // OTA-Jobs
                q.exec(R"SQL(
            CREATE TABLE IF NOT EXISTS ota_jobs(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              device_key TEXT NOT NULL,
              file_id INTEGER NOT NULL,
              state TEXT NOT NULL DEFAULT 'queued',  -- queued|downloading|installing|done|failed
              progress INTEGER NOT NULL DEFAULT 0,   -- 0..100
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );
            )SQL");

                //User Pass
                q.exec(R"SQL(
            CREATE TABLE IF NOT EXISTS users(
              username TEXT PRIMARY KEY,
              pass_hash BLOB NOT NULL,   -- PBKDF2 Output (32 Bytes)
              salt      BLOB NOT NULL,   -- 16..32 Bytes
              iters     INTEGER NOT NULL,-- z. B. 100000
              role      TEXT NOT NULL DEFAULT 'admin' -- oder 'user'
            );
            )SQL");

}


void Storage::ensureSchema() {
    // Optional: sinnvolle Pragmas
    {
        QSqlQuery p(db);
        p.exec("PRAGMA journal_mode=WAL");
        p.exec("PRAGMA synchronous=NORMAL");
        p.exec("PRAGMA foreign_keys=ON");
    }

    QSqlQuery q(db);

    auto execOrWarn = [&](const char* sql, const char* ctx){
        if (!q.exec(sql)) {
            qWarning() << "[DB] ensureSchema" << ctx << ":" << q.lastError().text();
        }
        q.finish();
    };

    // --- USERS (Login / Rollen) ---
    execOrWarn(R"SQL(
        CREATE TABLE IF NOT EXISTS users (
            name       TEXT PRIMARY KEY,
            hash       BLOB NOT NULL,
            salt       BLOB NOT NULL,
            iterations INTEGER NOT NULL,
            role       TEXT NOT NULL
        )
    )SQL", "create users");

    // --- DATA (Demo-Tabelle für einfache Werte) ---
    execOrWarn(R"SQL(
        CREATE TABLE IF NOT EXISTS data (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            name  TEXT,
            value TEXT,
            ts    DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    )SQL", "create data");

    // --- AUDIT (Ereignisprotokoll) ---
    execOrWarn(R"SQL(
        CREATE TABLE IF NOT EXISTS audit (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       DATETIME DEFAULT CURRENT_TIMESTAMP,
            category TEXT,
            user     TEXT,
            message  TEXT
        )
    )SQL", "create audit");

    // --- DEVICES (HMAC-Clients) ---
    execOrWarn(R"SQL(
        CREATE TABLE IF NOT EXISTS devices (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id    TEXT UNIQUE NOT NULL,
            secret    TEXT NOT NULL,    -- Base64url des Schlüssels
            enabled   INTEGER NOT NULL DEFAULT 1,
            firmware  TEXT,
            last_seen INTEGER DEFAULT 0
        )
    )SQL", "create devices");

    execOrWarn(R"SQL(
        CREATE INDEX IF NOT EXISTS idx_devices_key_id ON devices(key_id)
    )SQL", "index devices.key_id");

    // --- API NONCES (Replay-Schutz) ---
    execOrWarn(R"SQL(
        CREATE TABLE IF NOT EXISTS api_nonces (
            nonce  TEXT PRIMARY KEY,
            key_id TEXT NOT NULL,
            ts     INTEGER NOT NULL
        )
    )SQL", "create api_nonces");

    // --- SENSOR_DATA (NEUES Schema mit device_key) ---
    execOrWarn(R"SQL(
        CREATE TABLE IF NOT EXISTS sensor_data (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            device_key TEXT NOT NULL,
            ts         INTEGER NOT NULL,
            name       TEXT NOT NULL,
            value      REAL
        )
    )SQL", "create sensor_data");

    execOrWarn(R"SQL(
        CREATE INDEX IF NOT EXISTS idx_sensor_data_dev_ts ON sensor_data(device_key, ts)
    )SQL", "index sensor_data");

    // === MIGRATION: altes sensor_data (device_id) → neues (device_key) ===
    {
        QSqlQuery qi(db);
        if (qi.exec("PRAGMA table_info(sensor_data)")) {
            bool hasDeviceKey = false, hasDeviceId = false;
            while (qi.next()) {
                const QString col = qi.value(1).toString();
                if (col == "device_key") hasDeviceKey = true;
                if (col == "device_id")  hasDeviceId  = true;
            }
            qi.finish();

            if (!hasDeviceKey && hasDeviceId) {
                qWarning() << "[DB] migrating sensor_data (device_id -> device_key)";
                QSqlQuery m(db);

                if (!m.exec("ALTER TABLE sensor_data RENAME TO sensor_data_old")) {
                    qWarning() << "[DB] migrate rename failed:" << m.lastError();
                } else {
                    if (!m.exec(R"SQL(
                        CREATE TABLE sensor_data (
                            id         INTEGER PRIMARY KEY AUTOINCREMENT,
                            device_key TEXT NOT NULL,
                            ts         INTEGER NOT NULL,
                            name       TEXT NOT NULL,
                            value      REAL
                        )
                    )SQL")) {
                        qWarning() << "[DB] migrate create new failed:" << m.lastError();
                    } else {
                        if (!m.exec(R"SQL(
                            INSERT INTO sensor_data(device_key, ts, name, value)
                            SELECT device_id, ts, name,
                                   CASE
                                     WHEN typeof(value)='text' THEN CAST(value AS REAL)
                                     ELSE value
                                   END
                            FROM sensor_data_old
                        )SQL")) {
                            qWarning() << "[DB] migrate copy failed:" << m.lastError();
                        }
                        QSqlQuery d(db);
                        if (!d.exec("DROP TABLE sensor_data_old")) {
                            qWarning() << "[DB] migrate drop old failed:" << d.lastError();
                        }
                    }
                }
            }
        }
    }

    // --- OTA_FILES ---
    execOrWarn(R"SQL(
        CREATE TABLE IF NOT EXISTS ota_files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            path        TEXT NOT NULL,
            size        INTEGER NOT NULL,
            sha256      TEXT NOT NULL,
            uploaded_at INTEGER NOT NULL
        )
    )SQL", "create ota_files");

    // --- OTA_JOBS ---
    execOrWarn(R"SQL(
        CREATE TABLE IF NOT EXISTS ota_jobs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            device_key TEXT NOT NULL,
            file_id    INTEGER NOT NULL,
            state      TEXT NOT NULL DEFAULT 'queued',
            progress   INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
    )SQL", "create ota_jobs");

    execOrWarn(R"SQL(
        CREATE INDEX IF NOT EXISTS idx_ota_jobs_dev_state ON ota_jobs(device_key, state)
    )SQL", "index ota_jobs");
}


QSqlQuery Storage::selectLatest(int limit) {
    QSqlQuery q(db);
    q.prepare("SELECT id, name, value FROM data "
              "ORDER BY ts DESC LIMIT :lim");
    q.bindValue(":lim", limit);
    q.exec();
    return q;
}

QSqlQuery Storage::selectAudit(int limit) {
    QSqlQuery q(db);
    q.prepare("SELECT ts, category, user, message FROM audit "
              "ORDER BY ts DESC LIMIT :lim");
    q.bindValue(":lim", limit);
    q.exec();
    return q;
}

void Storage::insertData(const QString& name, const QString& value) {
    QSqlQuery q(db);
    q.prepare("INSERT INTO data (name, value) VALUES (:n, :v)");
    q.bindValue(":n", name);
    q.bindValue(":v", value);
    if (!q.exec()) {
        qWarning() << "insertData failed:" << q.lastError().text();
        return;
    }
    emit dataInserted(name, value);
}

void Storage::insertAudit(const QString& category,
                          const QString& user,
                          const QString& message) {
    QSqlQuery q(db);
    q.prepare("INSERT INTO audit (category, user, message) "
              "VALUES (:c, :u, :m)");
    q.bindValue(":c", category);
    q.bindValue(":u", user);
    q.bindValue(":m", message);
    if (!q.exec()) {
        qWarning() << "insertAudit failed:" << q.lastError().text();
        return;
    }
    emit auditInserted(category, user, message);
}

bool Storage::insertDevice(const QString& keyId, const QString& secret, const QString& firmware) {
    QSqlQuery q(db);
    q.prepare("INSERT OR IGNORE INTO devices(key_id,secret,firmware) VALUES(:k,:s,:f)");
    q.bindValue(":k", keyId);
    q.bindValue(":s", secret);
    q.bindValue(":f", firmware);
    if (!q.exec()) { qWarning() << "insertDevice:" << q.lastError().text(); return false; }
    return true;
}

/*
bool Storage::createDevice(const QString& keyId, QString secret, bool enabled, const QString& firmware) {
    QSqlQuery q(db);
    if (secret.isEmpty()) {
        QByteArray rnd(32, Qt::Uninitialized);
        for (int i=0;i<rnd.size();++i) rnd[i] = char(QRandomGenerator::global()->bounded(256));
        secret = rnd.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    }
    q.prepare("INSERT INTO devices(key_id, secret, enabled, firmware, last_seen) "
              "VALUES(:k,:s,:e,:f,0)");
    q.bindValue(":k", keyId);
    q.bindValue(":s", secret);
    q.bindValue(":e", enabled ? 1 : 0);
    q.bindValue(":f", firmware);
    if (!execOrFail(q, "createDevice.insert"))
        return false;            // Insert ist fehlgeschlagen (inkl. Duplicate)
    return true;    // Insert war erfolgreich

  //  return q.exec(); // bei Duplicate key_id → false
}  */

bool Storage::createDevice(const QString& keyId,
                           QString& secretInOut,
                           bool enabled,
                           const QString& firmware)
{
    QSqlQuery q(db);

    // Falls kein Secret übergeben: generieren (Base64URL, ohne '=')
    QString secret = secretInOut;
    if (secret.isEmpty()) {
        QByteArray rnd(32, Qt::Uninitialized);
        for (int i = 0; i < rnd.size(); ++i)
            rnd[i] = char(QRandomGenerator::global()->bounded(256));
        secret = rnd.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    }

    q.prepare("INSERT INTO devices(key_id, secret, enabled, firmware, last_seen) "
              "VALUES(:k,:s,:e,:f,0)");
    q.bindValue(":k", keyId);
    q.bindValue(":s", secret);
    q.bindValue(":e", enabled ? 1 : 0);
    q.bindValue(":f", firmware);

    if (!execOrFail(q, "createDevice.insert"))
        return false;

    // → generiertes/benutztes Secret an den Aufrufer zurückgeben
    secretInOut = secret;
    return true;
}

bool Storage::updateDeviceEnabled(const QString& keyId, bool enabled) {
    QSqlQuery q(db);
    q.prepare("UPDATE devices SET enabled=:e WHERE key_id=:k");
    q.bindValue(":e", enabled ? 1 : 0);
    q.bindValue(":k", keyId);
    return q.exec() && q.numRowsAffected() > 0;
}

bool Storage::updateDeviceSecret(const QString& keyId, const QString& newSecret) {
    QSqlQuery q(db);
    q.prepare("UPDATE devices SET secret=:s WHERE key_id=:k");
    q.bindValue(":s", newSecret);
    q.bindValue(":k", keyId);
    return q.exec() && q.numRowsAffected() > 0;
}

bool Storage::updateDeviceFirmware(const QString& keyId, const QString& firmware) {
    QSqlQuery q(db);
    q.prepare("UPDATE devices SET firmware=:f WHERE key_id=:k");
    q.bindValue(":f", firmware);
    q.bindValue(":k", keyId);
    return q.exec() && q.numRowsAffected() > 0;
}

bool Storage::updateDeviceLastSeen(const QString& keyId, qint64 ts) {
    QSqlQuery q(db);
    q.prepare("UPDATE devices SET last_seen=:t WHERE key_id=:k");
    q.bindValue(":t", ts);
    q.bindValue(":k", keyId);
    return q.exec() && q.numRowsAffected() > 0;
}


bool Storage::deleteDevice(const QString& keyId) {
    QSqlQuery q(db);
    q.prepare("DELETE FROM devices WHERE key_id=:k");
    q.bindValue(":k", keyId);
    return q.exec() && q.numRowsAffected() > 0;
}

QSqlQuery Storage::listDevices(int limit, int offset) {
    QSqlQuery q(db);
    q.prepare("SELECT id, key_id, enabled, firmware, last_seen "
              "FROM devices ORDER BY last_seen DESC LIMIT :lim OFFSET :off");
    q.bindValue(":lim", limit);
    q.bindValue(":off", offset);
    q.exec();
    return q;
}

bool Storage::findDevice(const QString& keyId, QString* secret, bool* enabled,
                         QString* firmware, qint64* lastSeen) {
    QSqlQuery q(db);
    q.prepare("SELECT secret, enabled, firmware, last_seen FROM devices WHERE key_id=:k");
    q.bindValue(":k", keyId);
    if (!q.exec() || !q.next()) return false;
    if (secret)   *secret   = q.value(0).toString();
    if (enabled)  *enabled  = (q.value(1).toInt() != 0);
    if (firmware) *firmware = q.value(2).toString();
    if (lastSeen) *lastSeen = q.value(3).toLongLong();
    return true;
}

bool Storage::insertNonce(const QString& keyId, const QString& nonce, qint64 ts) {
    QSqlQuery q(db);
    q.prepare("INSERT INTO api_nonces(nonce,key_id,ts) VALUES(:n,:k,:t)");
    q.bindValue(":n", nonce);
    q.bindValue(":k", keyId);
    q.bindValue(":t", ts);
    if (!q.exec()) {
        // UNIQUE-Fehler = Replay
        // qDebug() << "insertNonce:" << q.lastError().databaseText();
        return false;
    }
    return true;
}

bool Storage::insertSensor(const QString& keyId, const QString& name, const QString& value, qint64 ts) {
    QSqlQuery q(db);
    q.prepare("INSERT INTO sensor_data(device_key,ts,name,value) VALUES(:k,:t,:n,:v)");
    q.bindValue(":k", keyId);
    q.bindValue(":t", ts);
    q.bindValue(":n", name);
    q.bindValue(":v", value);
    if (!q.exec()) {
        qWarning() << "insertSensor:" << q.lastError().text();
        insertAudit("db", "system", QString("insertSensor failed: %1").arg(q.lastError().text())); // → GUI Audit-Tab
        return false;
    }
    insertAudit("sensor","system", QString("insert ok %1 %2=%3").arg(keyId, name, value)); // sichtbar
    emit sensorInserted(keyId, name, value, ts);
    return true;
}

bool Storage::insertOtaFile(const QString& name, const QString& path, qint64 size,
                            const QString& sha256, qint64* outId) {
    QSqlQuery q(db);
    q.prepare("INSERT INTO ota_files(name,path,size,sha256,uploaded_at)"
              " VALUES(:n,:p,:s,:h,:t)");
    q.bindValue(":n", name);
    q.bindValue(":p", path);
    q.bindValue(":s", size);
    q.bindValue(":h", sha256);
    q.bindValue(":t", QDateTime::currentSecsSinceEpoch());
    if (!q.exec()) { qWarning() << "insertOtaFile:" << q.lastError().text(); return false; }
    if (outId) *outId = q.lastInsertId().toLongLong();
    return true;
}

bool Storage::createOtaJob(const QString& deviceKey, qint64 fileId, qint64* outJobId) {
    QSqlQuery q(db);
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    q.prepare("INSERT INTO ota_jobs(device_key,file_id,state,progress,created_at,updated_at)"
              " VALUES(:d,:f,'queued',0,:c,:u)");
    q.bindValue(":d", deviceKey);
    q.bindValue(":f", fileId);
    q.bindValue(":c", now);
    q.bindValue(":u", now);
    if (!q.exec()) { qWarning() << "createOtaJob:" << q.lastError().text(); return false; }
    if (outJobId) *outJobId = q.lastInsertId().toLongLong();
    return true;
}

bool Storage::selectQueuedOtaJob(const QString& deviceKey,
                                 qint64* jobId, qint64* fileId,
                                 QString* fileName, qint64* size, QString* sha256) {
    QSqlQuery q(db);
    q.prepare(
        "SELECT j.id, j.file_id, f.name, f.size, f.sha256 "
        "FROM ota_jobs j JOIN ota_files f ON f.id=j.file_id "
        "WHERE j.device_key=:d AND j.state='queued' "
        "ORDER BY j.created_at ASC LIMIT 1");
    q.bindValue(":d", deviceKey);
    if (!q.exec() || !q.next()) return false;
    if (jobId)    *jobId    = q.value(0).toLongLong();
    if (fileId)   *fileId   = q.value(1).toLongLong();
    if (fileName) *fileName = q.value(2).toString();
    if (size)     *size     = q.value(3).toLongLong();
    if (sha256)   *sha256   = q.value(4).toString();
    return true;
}

bool Storage::updateOtaJobState(qint64 jobId, const QString& state, int progress) {
    QSqlQuery q(db);
    q.prepare("UPDATE ota_jobs SET state=:s, progress=:p, updated_at=:u WHERE id=:id");
    q.bindValue(":s", state);
    q.bindValue(":p", qBound(0, progress, 100));
    q.bindValue(":u", QDateTime::currentSecsSinceEpoch());
    q.bindValue(":id", jobId);
    return q.exec() && q.numRowsAffected() > 0;   // <-- wichtig
}

QSqlQuery Storage::listOtaFiles(int limit, int offset) {
    QSqlQuery q(db);
    q.prepare("SELECT id,name,size,sha256 FROM ota_files ORDER BY id DESC LIMIT :lim OFFSET :off");
    q.bindValue(":lim", limit);
    q.bindValue(":off", offset);
    q.exec();
    return q;
}
QSqlQuery Storage::listOtaJobs(int limit, int offset) {
    QSqlQuery q(db);
    q.prepare(R"SQL(
        SELECT id, device_key, file_id, state, progress
        FROM ota_jobs
        ORDER BY id DESC
        LIMIT :lim OFFSET :off
    )SQL");
    q.bindValue(":lim",  limit);
    q.bindValue(":off",  offset);
    if (!q.exec()) {
        qWarning() << "[DB] listOtaJobs failed:" << q.lastError().text();
        // Optional: leere Query zurück, die trotzdem gültig ist
    }
    return q; // ok: 'db' ist Member, lebt lange genug
}

bool Storage::fail(const QSqlQuery& q, const char* ctx) {
    lastErr_ = q.lastError().text();
    lastSql_ = q.lastQuery();
    qDebug() << "[DB]" << ctx << ":" << lastErr_ << "| SQL =" << lastSql_;
    return false;
}

bool Storage::execOrFail(QSqlQuery& q, const char* ctx) {
    if (!q.exec())
        return fail(q, ctx);
    return true;
}

QSqlQuery Storage::selectLatestSensors(int limit) {
    QSqlQuery q(db);
    // EXPLIZIT die Spalten und Reihenfolge wählen, die dein UI erwartet:
    q.prepare(R"SQL(
        SELECT ts, device_key, name, value
        FROM sensor_data
        ORDER BY id DESC
        LIMIT :lim
    )SQL");
    q.bindValue(":lim", limit);
    if (!q.exec()) {
        qWarning() << "[DB] selectLatestSensors failed:" << q.lastError().text();
    }
    return q;
}

/*
bool Storage::upsertUser(const QString& u, const QByteArray& h, const QByteArray& s, int it, const QString& role) {
    QSqlQuery q(db);
    q.prepare("INSERT INTO users(username,pass_hash,salt,iters,role)"
              " VALUES(:u,:h,:s,:i,:r)"
              " ON CONFLICT(username) DO UPDATE SET pass_hash=:h, salt=:s, iters=:i, role=:r");
    q.bindValue(":u", u);
    q.bindValue(":h", h);
    q.bindValue(":s", s);
    q.bindValue(":i", it);
    q.bindValue(":r", role);
    return q.exec();
}

bool Storage::findUser(const QString& user,
                       QByteArray* pwdHash,
                       QByteArray* salt,
                       int* iterations,
                       QString* role)
{
    QSqlQuery q(db);
    q.prepare("SELECT pwd_hash, salt, iterations, role FROM users WHERE username=:u");
    q.bindValue(":u", user);
    if (!q.exec() || !q.next()) return false;

    if (pwdHash)   *pwdHash   = q.value(0).toByteArray();
    if (salt)      *salt      = q.value(1).toByteArray();
    if (iterations)*iterations= q.value(2).toInt();
    if (role)      *role      = q.value(3).toString();
    return true;
}
*/

/*
static QByteArray genSalt16() {
    QByteArray s(16, Qt::Uninitialized);
    QRandomGenerator::global()->generate(reinterpret_cast<quint32*>(s.data()),
                                         reinterpret_cast<quint32*>(s.data()) + s.size()/4);
    return s;
}
*/
static bool constTimeEq(const QByteArray& a, const QByteArray& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (int i=0;i<a.size();++i) diff |= static_cast<unsigned char>(a[i]^b[i]);
    return diff == 0;
}

bool Storage::hasAnyUser() const {
    QSqlQuery q(db);
    if (!q.exec("SELECT COUNT(*) FROM users")) return false;
    if (!q.next()) return false;
    return q.value(0).toInt() > 0;
}

bool Storage::findUser(const QString& user,
                       QByteArray* hash, QByteArray* salt, int* iterations, QString* role)
{
    QSqlQuery q(db);                                // *** dieselbe Verbindung! ***
    q.prepare("SELECT hash,salt,iterations,role FROM users WHERE name=?");
    q.addBindValue(user);
    if (!q.exec()) {
        qWarning() << "[DB] findUser exec:" << q.lastError();
        return false;
    }
    if (!q.next()) return false;

    if (hash)       *hash = q.value(0).toByteArray();
    if (salt)       *salt = q.value(1).toByteArray();
    if (iterations) *iterations = q.value(2).toInt();
    if (role)       *role = q.value(3).toString();
    return true;
}

bool Storage::upsertUser(const QString& user,
                         const QByteArray& hash,
                         const QByteArray& salt,
                         int iterations,
                         const QString& role)
{
    QSqlQuery q(db);                                // *** dieselbe Verbindung! ***
    q.prepare(
        "INSERT INTO users(name,hash,salt,iterations,role) "
        "VALUES(?,?,?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET "
        " hash=excluded.hash, salt=excluded.salt, iterations=excluded.iterations, role=excluded.role"
        );
    q.addBindValue(user);
    q.addBindValue(hash);
    q.addBindValue(salt);
    q.addBindValue(iterations);
    q.addBindValue(role);
    if (!q.exec()) {
        qWarning() << "[DB] upsertUser exec:" << q.lastError();
        return false;
    }
    return true;
}

bool Storage::seedAdminIfEmpty(const QString& user,
                               const QString& pass,
                               const QString& role,
                               int iterations)
{
    // Nur dann seed’en, wenn GENAU dieser User fehlt
    QByteArray h,s; int it=0; QString r;
    if (findUser(user, &h, &s, &it, &r)) {
        return false; // admin existiert bereits → nichts tun
    }

    // Salt + Hash erzeugen (dkLen MUSS zu deinem Login passen: 32!)
    QByteArray salt(16, Qt::Uninitialized);
    QRandomGenerator::global()->generate(
        reinterpret_cast<quint32*>(salt.data()),
        reinterpret_cast<quint32*>(salt.data()) + (salt.size()/sizeof(quint32))
        );
    const QByteArray hash = pbkdf2HmacSha256(pass.toUtf8(), salt, iterations, 32);

    const bool ok = upsertUser(user, hash, salt, iterations, role);

#ifdef QT_DEBUG
    // Mini-Selbsttest: direkt wieder aus DB lesen
    QByteArray hh, ss; int ii=0; QString rr;
    const bool found = findUser(user, &hh, &ss, &ii, &rr);
    qDebug() << "[seedAdminIfEmpty] upsert=" << ok << " found=" << found << " iters=" << ii << " role=" << rr;
#endif
    return ok; // true = Admin wurde jetzt angelegt
}

 /*
bool Storage::seedAdminIfEmpty(const QString& user,
                               const QString& pass,
                               const QString& role,
                               int iters)
{
    // Tabelle 'users' muss existieren – ggf. vorher in deinem ctor anlegen.
   if (hasAnyUser()) return true; // nichts zu tun

    QByteArray salt = genSalt16();
    QByteArray hash = pbkdf2HmacSha256(pass.toUtf8(), salt, iters);

    return upsertUser(user, hash, salt, iters, role);

}   */

/*
void Storage::createAdmin(void)
{
    Storage st(this);
    QByteArray salt = genSalt16();
    const int iters = 100000;
    QByteArray hash = pbkdf2HmacSha256("secret_admin", salt, iters);
    st.upsertUser("admin", hash, salt, iters, "admin");
}  */

bool Storage::getOtaFile(qint64 fileId, QString* path, QString* name, qint64* size, QString* sha256) {
    QSqlQuery q(db);
    q.prepare("SELECT path, name, size, sha256 FROM ota_files WHERE id=:id");
    q.bindValue(":id", fileId);
    if (!q.exec() || !q.next()) return false;
    if (path)   *path   = q.value(0).toString();
    if (name)   *name   = q.value(1).toString();
    if (size)   *size   = q.value(2).toLongLong();
    if (sha256) *sha256 = q.value(3).toString();
    return true;
}

bool Storage::claimNextQueuedOtaJob(const QString& deviceKey,
                                    qint64* jobId, qint64* fileId,
                                    QString* fileName, qint64* size, QString* sha256)
{
    // Für SQLite genügt BEGIN IMMEDIATE als primitive Sperre
    QSqlQuery q(db);
    if (!q.exec("BEGIN IMMEDIATE")) return false;

    q.prepare(
        "SELECT j.id, j.file_id, f.name, f.size, f.sha256 "
        "FROM ota_jobs j JOIN ota_files f ON f.id=j.file_id "
        "WHERE j.device_key=:d AND j.state='queued' "
        "ORDER BY j.created_at ASC LIMIT 1");
    q.bindValue(":d", deviceKey);
    if (!q.exec() || !q.next()) {
        db.exec("ROLLBACK");
        return false;
    }

    const qint64 jid = q.value(0).toLongLong();
    if (jobId)    *jobId    = jid;
    if (fileId)   *fileId   = q.value(1).toLongLong();
    if (fileName) *fileName = q.value(2).toString();
    if (size)     *size     = q.value(3).toLongLong();
    if (sha256)   *sha256   = q.value(4).toString();

    QSqlQuery u(db);
    u.prepare("UPDATE ota_jobs SET state='downloading', progress=0, updated_at=:t WHERE id=:id");
    u.bindValue(":t", QDateTime::currentSecsSinceEpoch());
    u.bindValue(":id", jid);
    if (!u.exec()) {
        db.exec("ROLLBACK");
        return false;
    }
    db.exec("COMMIT");
    return true;
}

bool Storage::getOtaJobDevice(qint64 jobId, QString* deviceKeyOut) {
    QSqlQuery q(db);
    q.prepare("SELECT device_key FROM ota_jobs WHERE id=:id");
    q.bindValue(":id", jobId);
    if (!q.exec() || !q.next()) return false;
    if (deviceKeyOut) *deviceKeyOut = q.value(0).toString();
    return true;
}

//#include "Storage.h"
// intentionally empty — implementation in header for simplicity
