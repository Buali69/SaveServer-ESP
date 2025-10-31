// ============================================================================
// HttpConnection.cpp
// ----------------------------------------------------------------------------
// Diese Datei implementiert die pro-Connection-Logik deines kleinen HTTPS-Servers.
// Pro TCP/TLS-Verbindung wird genau ein HttpConnection-Objekt erstellt (siehe
// HttpsServer::incomingConnection). Dieses Objekt:
//
//   1) hängt sich an den QSslSocket (encrypted/readyRead/disconnected),
//   2) pflegt eine kleine StateMachine (connected → tls-ok → authenticated? → closed)
//   3) parst eingehende HTTP/1.1 Requests (Startzeile, Header, Body),
//   4) bedient definierte Routen (/, /submit, /login, /api/...),
//   5) sendet Antworten und schließt die Verbindung.
//
// Der Parser ist absichtlich minimalistisch (kein Chunked-Encoding, keine
// Keep-Alive-Mehrfachrequests nach einer Antwort; wir schließen aktiv).
// Das reicht für den Demo-/Lab-Betrieb, ist leicht nachvollziehbar und erweiterbar.
// ============================================================================

#include "HttpConnection.h"

// --- Qt-Network / Qt-Core ---
#include <QtNetwork/QSslSocket>
#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QDateTime>
#include <QtCore/QUrlQuery>
#include <QtCore/QByteArray>
#include <QtCore/QDebug>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QRegularExpression>
#include <QtCore/QMessageAuthenticationCode>
#include <QtCore/QStandardPaths>
#include <QtCore/QUuid>
#include <QtCore/QRandomGenerator>
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>

#include "../common/crypto_helpers.h"
using crypto::b64url;
using crypto::sha256;
using crypto::bytesEqualCT;
using crypto::pbkdf2HmacSha256;

// --- Deine Projekt-Klassen ---
#include "jwt.h"          // Klasse Jwt: sign(Claims), verify(Token)
#include "../db/Storage.h"      // SQLite-Wrapper: selectLatest/insertNonce/insertSensor

// ============================================================================
// Hilfsfunktionen (anonyme Namespace → nur in dieser Übersetzungseinheit sichtbar)
// ============================================================================

namespace {

// ------------------------------------------------------------------
// readLine: Liest die nächste CRLF-terminierte Zeile aus 'buf' heraus.
// - Gibt die Zeile OHNE CRLF zurück.
// - Entfernt die gelesene Zeile (inkl. CRLF) aus 'buf'.
// - Wenn kein CRLF vorhanden → gibt leeres QByteArray zurück.
// ------------------------------------------------------------------
QByteArray readLine(QByteArray& buf) {
    const int idx = buf.indexOf("\r\n");           // Suche nach CRLF
    if (idx < 0) return {};                        // noch unvollständig → später erneut versuchen
    QByteArray line = buf.left(idx);               // Zeile ohne CRLF
    buf.remove(0, idx + 2);                        // Zeile + CRLF aus Buffer entfernen
    return line;
}

// ------------------------------------------------------------------
// HttpReq: Einfache Repräsentation eines HTTP-Requests
// - method: "GET", "POST", ...
// - path: Pfad inkl. Query (" /api/xyz?limit=10 ")
// - version: "HTTP/1.1"
// - headers: Liste aus (Key, Value)
// - body: Bytes des Request-Bodys (falls Content-Length > 0)
// ------------------------------------------------------------------
struct HttpReq {
    QByteArray method;
    QByteArray path;
    QByteArray version;
    QList<QPair<QByteArray,QByteArray>> headers;
    QByteArray body;

    // Header-Zugriff: case-insensitive Suche
    QByteArray header(const QByteArray& key) const {
        for (const auto& h : headers) {
            if (h.first.compare(key, Qt::CaseInsensitive) == 0)
                return h.second;
        }
        return {};
    }
};

// ------------------------------------------------------------------
// parseHttp: Parst genau EINE vollständige HTTP-Nachricht aus 'buf'.
// 1) Start-Line → METHOD SP PATH SP VERSION CRLF
// 2) Header-Zeilen → "Key: Value" bis zur Leerzeile
// 3) Optionaler Body → anhand Content-Length
// Rückgabewert: true  → ein kompletter Request konnte gelesen werden
//                false → (noch) unvollständig → später erneut probieren
//
// WICHTIG: Diese Funktion entfernt die gelesenen Teile aus 'buf'.
// ------------------------------------------------------------------
bool parseHttp(QByteArray& buf, HttpReq& out) {
    // --- 1) Start-Line ---
    const QByteArray startLine = readLine(buf);
    if (startLine.isEmpty()) return false;      // noch nicht vollständig

    const QList<QByteArray> parts = startLine.split(' ');
    if (parts.size() != 3) return false;        // ungültig → hier beenden (oder 400 senden)
    out.method  = parts[0];
    out.path    = parts[1];
    out.version = parts[2];

    // --- 2) Header-Zeilen ---
    while (true) {
        const QByteArray line = readLine(buf);
        if (line.isNull()) return false;        // Header noch unvollständig
        if (line.isEmpty()) break;              // Leerzeile → Header-Ende
        const int col = line.indexOf(':');
        if (col <= 0) continue;                 // ignorieren, wenn kein "Key: Value"
        const QByteArray key = line.left(col).trimmed();
        const QByteArray val = line.mid(col + 1).trimmed();
        out.headers.append({key, val});
    }

    // --- 3) Body (optional über Content-Length) ---
    bool okLen = false;
    const int len = out.header("Content-Length").toInt(&okLen);
    // DEBUG: Content-Length und aktueller Buffer-Stand
    qDebug() << "[parseHttp] okLen=" << okLen
             << "CL=" << len
             << "buf.size=" << buf.size();

    if (okLen && len > 0) {
        if (buf.size() < len) {
            // DEBUG: Es fehlen noch Bytes → später erneut versuchen
            qDebug() << "[parseHttp] waiting for more body bytes:"
                     << (len - buf.size());
            return false;     // Body noch nicht komplett
        }
        out.body = buf.left(len);

        // DEBUG: tatsächlich entnommene Body-Größe
        qDebug() << "[parseHttp] body.size=" << out.body.size();

        buf.remove(0, len);   // Body aus Buffer entfernen
    }
    return true;                                // Ein kompletter Request ist geparst
}

// ------------------------------------------------------------------
// urlDecode: Wandelt x-www-form-urlencoded in Klartext um.
// Beispiel: "value=42&name=Max%20M." → map["value"]="42", map["name"]="Max M."
// ------------------------------------------------------------------
QMap<QByteArray,QByteArray> parseWwwForm(const QByteArray& body) {
    QMap<QByteArray,QByteArray> out;
    const QList<QByteArray> pairs = body.split('&');
    for (const QByteArray& p : pairs) {
        const int eq = p.indexOf('=');
        if (eq < 0) continue;
        const QByteArray kEnc = p.left(eq);
        const QByteArray vEnc = p.mid(eq + 1);
        const QByteArray k = QByteArray::fromPercentEncoding(kEnc);
        const QByteArray v = QByteArray::fromPercentEncoding(vEnc);
        out[k] = v;
    }
    return out;
}

// ------------------------------------------------------------------
// simpleContentType: Ermittelt grob den Content-Type anhand Dateiendung.
// Individuell erweiterbar.
// ------------------------------------------------------------------
QByteArray simpleContentType(const QString& localPath) {
    if (localPath.endsWith(".html", Qt::CaseInsensitive)) return "text/html; charset=utf-8";
    if (localPath.endsWith(".css",  Qt::CaseInsensitive)) return "text/css";
    if (localPath.endsWith(".js",   Qt::CaseInsensitive)) return "application/javascript";
    if (localPath.endsWith(".json", Qt::CaseInsensitive)) return "application/json";
    if (localPath.endsWith(".png",  Qt::CaseInsensitive)) return "image/png";
    if (localPath.endsWith(".jpg",  Qt::CaseInsensitive) ||
        localPath.endsWith(".jpeg", Qt::CaseInsensitive)) return "image/jpeg";
    if (localPath.endsWith(".svg",  Qt::CaseInsensitive)) return "image/svg+xml";
    if (localPath.endsWith(".txt",  Qt::CaseInsensitive)) return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

// ------------------------------------------------------------------
// sanitizePath: Verhindert Path-Traversal (../../) in URL-Pfaden.
// - erlaubt nur Unterpfade unterhalb des documentRoot
// - säubert doppelte Slashes
// - lehnt verdächtige Komponenten ab
// Rückgabe: (isValid, bereinigter relativ-Pfad mit führendem '/')
// ------------------------------------------------------------------
QPair<bool, QString> sanitizePath(const QByteArray& rawPath) {
    // Query-Teil entfernen: "/a/b?x=1" → "/a/b"
    const int qm = rawPath.indexOf('?');
    const QByteArray p = (qm >= 0) ? rawPath.left(qm) : rawPath;

    QString path = QString::fromUtf8(p);

    // Normieren: Mehrere Slashes → ein Slash
    path.replace(QRegularExpression(QStringLiteral("/{2,}")), "/");

    // Browser schicken manchmal URL-encoded → sicherheitshalber decodieren
    path = QString::fromUtf8(QByteArray::fromPercentEncoding(path.toUtf8()));

    // Leerpfad → "/"
    if (path.isEmpty()) path = "/";

    // Verbotene Sequenzen
    if (path.contains("..")) return {false, QString()};
    if (path.startsWith("\\") || path.contains(":\\")) return {false, QString()}; // Windows-Laufwerk

    // Immer mit führendem "/" arbeiten
    if (!path.startsWith('/')) path.prepend('/');

    return {true, path};
}

// ------------------------------------------------------------------
// computeHmacSha256: Standard HMAC-SHA256 via QMessageAuthenticationCode.
// Rückgabe als Hex-String (lowercase), damit gut vergleichbar/übertragbar.
// ------------------------------------------------------------------
QByteArray computeHmacSha256(const QByteArray& key, const QByteArray& msg) {
    const QByteArray mac = QMessageAuthenticationCode::hash(msg, key, QCryptographicHash::Sha256);
    return mac.toHex(); // hexadezimaler String (ASCII) → bequem in JSON zu transportieren
}

// Zeitsicherer Byte-Vergleich (verhindert Timing-Angriffe)
static bool constTimeEq(const QByteArray& a, const QByteArray& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    const int n = a.size();
    for (int i = 0; i < n; ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

// Einfacher KeyId-Validator (erlaubt [A-Za-z0-9_-], 3..64 Zeichen)
static bool isValidKeyId(const QString& kid) {
    static const QRegularExpression rx("^[A-Za-z0-9_-]{3,64}$");
    return rx.match(kid).hasMatch();
}

// Secret-Erzeugung: 32 zufällige Bytes → Base64url (ohne '=')
static QString genDeviceSecretB64Url(int byteLen = 32) {
    QByteArray buf(byteLen, Qt::Uninitialized);
    QRandomGenerator::global()->generate(reinterpret_cast<quint32*>(buf.data()),
                                         reinterpret_cast<quint32*>(buf.data()) + (byteLen/4));
    return buf.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

static QByteArray b64urlToBytes(const QString& sIn)
{
    QByteArray s = sIn.toUtf8();
    s.replace('-', '+');
    s.replace('_', '/');
    while (s.size() % 4) s.append('=');          // auf 4er-Länge auffüllen
    return QByteArray::fromBase64(s);            // echte Schlüsselbytes
}

static int headerValueToInt(const QList<QPair<QByteArray,QByteArray>>& hs,
                            const QByteArray& key, int def=0) {
    for (auto &h : hs) if (h.first.compare(key, Qt::CaseInsensitive)==0)
            return h.second.trimmed().toInt();
    return def;
}

static QByteArray headerValue(const QList<QPair<QByteArray,QByteArray>>& hs,
                              const QByteArray& key) {
    for (auto &h : hs) if (h.first.compare(key, Qt::CaseInsensitive)==0)
            return h.second.trimmed();
    return {};
}

/*
// Timing-sicherer Vergleich zweier QByteArrays
static bool bytesEqualCT(const QByteArray& a, const QByteArray& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    const int n = a.size();
    const unsigned char* pa = reinterpret_cast<const unsigned char*>(a.constData());
    const unsigned char* pb = reinterpret_cast<const unsigned char*>(b.constData());
    for (int i = 0; i < n; ++i) diff |= (pa[i] ^ pb[i]);
    return diff == 0;
}



// PBKDF2-HMAC-SHA256 (RFC 8018), kompakt und kommentiert
static QByteArray pbkdf2HmacSha256(const QByteArray& password,
                                     const QByteArray& salt,
                                     int iterations,
                                     int dkLen = 32) {
    const int hLen = 32; // SHA-256 output
    const int l = (dkLen + hLen - 1) / hLen;
    QByteArray dk; dk.reserve(l * hLen);
    for (int i = 1; i <= l; ++i) {
        QByteArray saltBlock = salt;
        saltBlock.append(char((i >> 24) & 0xFF));
        saltBlock.append(char((i >> 16) & 0xFF));
        saltBlock.append(char((i >>  8) & 0xFF));
        saltBlock.append(char((i >>  0) & 0xFF));
        QByteArray u = QMessageAuthenticationCode::hash(saltBlock, password, QCryptographicHash::Sha256);
        QByteArray t = u;
        for (int j = 2; j <= iterations; ++j) {
            u = QMessageAuthenticationCode::hash(u, password, QCryptographicHash::Sha256);
            for (int k = 0; k < hLen; ++k) t[k] = t[k] ^ u[k];
        }
        dk.append(t);
    }
    dk.truncate(dkLen);
    return dk;
}

// Optional: 16-Byte Salt-Generator, falls du ihn hier brauchst
static QByteArray genSalt16() {
    QByteArray s(16, Qt::Uninitialized);
    // fülle 16 Bytes zufällig
    QRandomGenerator::global()->generate(
        reinterpret_cast<quint32*>(s.data()),
        reinterpret_cast<quint32*>(s.data()) + (s.size()/4)
        );
    return s;
}

void createAdmin(void)
{
    Storage st(this);
    QByteArray salt = genSalt16();
    const int iters = 100000;
    QByteArray hash = pbkdf2HmacSha256("secret_admin", salt, iters);
    st.upsertUser("admin", hash, salt, iters, "admin");
}   */


} // namespace (anonyme Helfer)

// ============================================================================
// Konstruktor & StateMachine
// ============================================================================

HttpConnection::HttpConnection(QSslSocket* s,
                               QString documentRoot,
                               std::function<void(int)> onNumber,
                               std::function<void(QString)> log,
                               QByteArray jwtSecret,
                               std::function<void(QString, QString)> audit,
                               std::function<void(QString)> wsBroadcast,
                               QObject* parent,
                               Storage* storage)
    : QObject(parent),
    sock(s),
    docRoot(std::move(documentRoot)),
    onNumber_(std::move(onNumber)),
    log_(std::move(log)),
    jwtSecret_(std::move(jwtSecret)),
    wsBroadcast_(std::move(wsBroadcast)),
    audit_(std::move(audit)),
    storage_(storage)
{
    // StateMachine aufsetzen (nur einfache Lebenszykluszustände).
    setupStateMachine();

    // Signals vom TLS-Socket:
    // - encrypted: TLS-Handshake fertig → wir können HTTP sprechen.
    // - readyRead: Daten verfügbar → in 'buffer' einlesen und parsen.
    // - disconnected: Verbindung beendet → State wechseln + Objekt aufräumen.
    connect(sock, &QSslSocket::encrypted,   this, &HttpConnection::onEncrypted);
    connect(sock, &QSslSocket::readyRead,   this, &HttpConnection::onReadyRead);
    connect(sock, &QSslSocket::disconnected,this, &HttpConnection::onDisconnected);
}

void HttpConnection::setupStateMachine() {
    // Zustände anlegen (Eltern = machine, damit Auto-Lifetime passt)
    stateConnected     = new QState(&machine);
    stateTlsOk         = new QState(&machine);
    stateAuthenticated = new QState(&machine); // derzeit optional (JWT/mTLS), vorbereitet
    stateClosed        = new QState(&machine);

    // Initialzustand
    machine.setInitialState(stateConnected);

    // Entry-Actions → nützliches Audit-Logging
    connect(stateConnected, &QState::entered, this, [this]{
        currentStateName = "connected";
        if (audit_) audit_("http", "state=connected");
    });
    connect(stateTlsOk, &QState::entered, this, [this]{
        currentStateName = "tls-ok";
        if (audit_) audit_("http", "state=tls-ok");
    });
    connect(stateAuthenticated, &QState::entered, this, [this]{
        currentStateName = "authenticated";
        if (audit_) audit_("http", "state=authenticated");
    });
    connect(stateClosed, &QState::entered, this, [this]{
        currentStateName = "closed";
        if (audit_) audit_("http", "state=closed");
    });

    // Transitionen:
    // - Nach TLS-Handshake → tls-ok
    stateConnected->addTransition(this, &HttpConnection::tlsOk, stateTlsOk);
    // - (später) nach erfolgreicher App-Auth → authenticated
    stateTlsOk->addTransition(this, &HttpConnection::authenticated, stateAuthenticated);
    // - Disconnect führt aus allen aktiven Zuständen nach closed
    stateConnected->addTransition(this, &HttpConnection::closed, stateClosed);
    stateTlsOk->addTransition(this, &HttpConnection::closed, stateClosed);
    stateAuthenticated->addTransition(this, &HttpConnection::closed, stateClosed);

    machine.start();
}

// ============================================================================
// Socket-Ereignisse
// ============================================================================

void HttpConnection::onEncrypted() {
    // TLS steht → höherer Zustand + optionales Logging
    emit tlsOk();
}

void HttpConnection::onDisconnected() {
    // Verbindung beendet (vom Client oder von uns initiiert)
    emit closed();
    sock->deleteLater(); // QSslSocket wird sauber freigegeben
}

// ============================================================================
// HTTP-Verarbeitung
// ============================================================================

void HttpConnection::onReadyRead() {

  //  if (log_) log_(QString("[DBG] buffer.bytes=%1").arg(buffer.size()));
    // Bytes aus dem TLS-Socket abholen und zum Puffer addieren
  //  buffer += sock->readAll();
    rx_ += sock->readAll();
    if (log_) log_(QString("[DBG] rx_.bytes=%1").arg(rx_.size()));
    parseIncoming();

    /*
    // Wir parsen so lange Requests, bis 'parseHttp' sagt: unvollständig
    HttpReq req;
    while (parseHttp(buffer, req)) {
        // --- Pfad-Sanitisierung & Routing-Schiene ---
        const auto sane = sanitizePath(req.path);
        if (!sane.first) {
            send(400, "text/plain; charset=utf-8", "Bad Request");
            req = {};     // für den nächsten Zyklus
            continue;
        }
        const QString cleanPath = sane.second;

        // A) Statische Ressourcen: GET /  → index.html
        if (req.method == "GET" && (cleanPath == "/" || cleanPath == "/index.html")) {
            serveIndex();
        }
        // B) Einfaches Formular-POST: POST /submit  (body: value=123)
        else if (req.method == "POST" && cleanPath == "/submit") {
            handleSubmit(req.body);
        }
        // C) Login-API (Demo): POST /login  (JSON: {"user":"..","pass":".."})
        else if (req.method == "POST" && cleanPath == "/login") {
            handleLogin(req.body);
        }
        // D) REST-API: /api/...
        else if (cleanPath.startsWith("/api/")) {
            // Für die API interessiert uns ggf. auch der Body → direkt weiterreichen
            handleApiRequest(req.method, req.path, req.body, req.headers); // Achtung: hier übergeben wir die "raw" path-Bytes (inkl. Query), wie in der Header-Signatur vorgesehen
        }
        // E) Beliebige GET-Anfragen → statische Dateien ausliefern (documentRoot)
        else if (req.method == "GET") {
            // Query entfernen, wenn vorhanden
            const int qm = req.path.indexOf('?');
            const QByteArray pathNoQuery = (qm >= 0) ? req.path.left(qm) : req.path;

            // Pfad absichern (nochmal) und lokale Datei suchen
            const auto sane2 = sanitizePath(pathNoQuery);
            if (!sane2.first) { send(400,"text/plain; charset=utf-8","Bad Request"); req={}; continue; }
            const QString rel = sane2.second; // beginnt mit '/'

            // "root + rel" → echte Datei
            const QString full = docRoot + rel;
            QFile file(full);
            if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
                send(404, "text/plain; charset=utf-8", "Not Found");
            } else {
                send(200, simpleContentType(full), file.readAll());
            }
        }
        // F) Alles andere → 405
        else {
            send(405, "text/plain; charset=utf-8", "Method Not Allowed");
        }

        // Request-Objekt leeren und ggf. nächsten Request aus 'buffer' versuchen
        req = {};
    }
    */

    // Hinweis: Wir arbeiten bewusst "Connection: close" → d. h., wir schließen
    // die Verbindung nach *jeder* Antwort (siehe send()). So müssen wir keine
    // Keep-Alive-States pflegen. Für mehr Durchsatz kann man später Keep-Alive
    // implementieren (dann send() nicht disconnecten lassen und Request-Pipeline
    // in 'while(parseHttp(...))' weiter bedienen).
}

// ============================================================================
// Routen-Handler
// ============================================================================

void HttpConnection::serveIndex() {
    // Liefert die Hauptseite aus dem documentRoot
    QFile f(docRoot + "/index.html");
    if (!f.open(QIODevice::ReadOnly)) {
        send(404, "text/plain; charset=utf-8", "index.html not found");
        return;
    }
    send(200, "text/html; charset=utf-8", f.readAll());
}

void HttpConnection::handleSubmit(const QByteArray& body) {
    // Erwartetes Format: application/x-www-form-urlencoded mit Feld "value"
    const auto form = parseWwwForm(body);
    bool ok = false;
    const int value = QString::fromUtf8(form.value("value")).toInt(&ok);
    if (!ok) {
        send(400, "text/plain; charset=utf-8", "invalid value");
        return;
    }

    // Callback ins Hauptprogramm (z. B. DB speichern, GUI auffrischen, WS-Broadcast)
    if (onNumber_) onNumber_(value);

    // Audit-Log für Nachvollziehbarkeit
    if (audit_) audit_("http", QString("submit value=%1").arg(value));

    // Einfache Text-Antwort
    send(200, "text/plain; charset=utf-8", "ok");
}

void HttpConnection::handleLogin(const QByteArray& body) {
    QJsonParseError pe; const auto doc = QJsonDocument::fromJson(body, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        send(400, "application/json", R"({"error":"invalid json"})");
        return;
    }
    const auto o = doc.object();
    const QString user = o.value("user").toString();
    const QString pass = o.value("pass").toString();
    if (user.isEmpty() || pass.isEmpty()) {
        send(400, "application/json", R"({"error":"missing fields"})");
        return;
    }

    QByteArray dbHash, salt; int iters = 0; QString role;
    if (!storage_ || !storage_->findUser(user, &dbHash, &salt, &iters, &role)) {
        if (audit_) audit_("auth", "login failed user="+user);
        send(401, "application/json", R"({"error":"invalid credentials"})");
        return;
    }

    QByteArray calc = pbkdf2HmacSha256(pass.toUtf8(), salt, iters, 32);
    if (!constTimeEq(calc, dbHash)) {
        if (audit_) audit_("auth", "login failed user="+user);
        send(401, "application/json", R"({"error":"invalid credentials"})");
        return;
    }

    // JWT bauen (HS256 mit jwtSecret_)
    Jwt jwt(jwtSecret_);
    QJsonObject claims{
        {"sub", user},
        {"role", role},
        {"iat", static_cast<qint64>(QDateTime::currentSecsSinceEpoch())},
        {"exp", static_cast<qint64>(QDateTime::currentSecsSinceEpoch()+3600)}
    };
    const QString token = jwt.sign(claims);

    if (audit_) audit_("auth", "login ok user="+user);

    // Optional: auch als HttpOnly+Secure Cookie setzen
    QByteArray payload = QJsonDocument(QJsonObject{{"token", token}}).toJson(QJsonDocument::Compact);
    QByteArray head;
    head += "HTTP/1.1 200 OK\r\n";
    head += "Content-Type: application/json\r\n";
    head += "Content-Length: " + QByteArray::number(payload.size()) + "\r\n";
    head += "Set-Cookie: token=" + token.toUtf8() + "; Max-Age=3600; Path=/; HttpOnly; Secure; SameSite=Strict\r\n";
    head += "Connection: close\r\n\r\n";
    sock->write(head);
    sock->write(payload);
    sock->disconnectFromHost();
}

void HttpConnection::handleApiRequest(const QByteArray& method,
                                      const QByteArray& pathRaw,
                                      const QByteArray& body,
                                      const QList<QPair<QByteArray,QByteArray>>& headers) {


    // Strings für den Router vorbereiten
    // Routing-Hilfsvariablen:
    const QString m = QString::fromLatin1(method).toUpper();  // "GET", "POST", ...
    const int qm   = pathRaw.indexOf('?');
    const QByteArray pathOnly = (qm >= 0) ? pathRaw.left(qm) : pathRaw;
    const QByteArray query    = (qm >= 0) ? pathRaw.mid(qm + 1) : QByteArray();
    const QString path = QString::fromUtf8(pathOnly);         // <-- genau dieses 'path' nutzt du unten
if (log_) log_(QString("[API] %1 %2").arg(m, path));
    // Header-Liste in Map (für HMAC-Verify etc.)
    QMap<QString, QString> hdrs;
    for (const auto& h : headers) {
        const QString k = QString::fromLatin1(h.first).toLower();   // <-- lowercase key
        const QString v = QString::fromLatin1(h.second);
        hdrs.insert(k, v);
    }
if (log_) log_(QString("[API] %1 %2").arg(m, path));

    // ---- /api/sensor/latest?limit=100  (GET) --------------------------------
    if (path == "/api/sensor/latest") {
        int limit = 100; // Standard-Limit
        if (!query.isEmpty()) {
            const QUrlQuery q(QString::fromUtf8(query));
            bool okLim = false;
            const int l = q.queryItemValue("limit").toInt(&okLim);
            if (okLim && l > 0 && l <= 1000) limit = l;
        }

        // DB-Abfrage: letzte 'limit' Einträge aus 'data' (siehe Storage::selectLatest)

        QSqlQuery q = storage_->selectLatest(limit);

        QJsonArray items;
        while (q.next()) {
            // selectLatest liefert: id, name, value (siehe Storage.cpp)
            QJsonObject o;
            o["id"]    = q.value(0).toInt();
            o["name"]  = q.value(1).toString();
            o["value"] = q.value(2).toString();
            items.append(o);
        }

        QJsonObject res{{"items", items}};
        send(200, "application/json", QJsonDocument(res).toJson(QJsonDocument::Compact));
        return;
    }

    // ---- /api/sensor  (POST JSON) -------------------------------------------
    // Body-Format (Beispiel):
    // {
    //   "deviceId": "dev-123",
    //   "name":     "temp",
    //   "value":    "23.5",
    //   "ts":       1699999999,
    //   "nonce":    "550e8400-e29b-41d4-a716-446655440000",
    //   "signature":"<hex(HMAC-SHA256(key, deviceId|name|value|ts|nonce))>"
    // }
    // Signatur & Nonce dienen als Auth/Replay-Schutz für einfache Geräte.
    if (path == "/api/sensor") {
        const QJsonDocument doc = QJsonDocument::fromJson(body);
        if (!doc.isObject()) {
            send(400, "application/json", R"({"error":"invalid json"})");
            return;
        }
        const QJsonObject obj = doc.object();

        const QString deviceId = obj.value("deviceId").toString();
        const QString name     = obj.value("name").toString();
        const QString value    = obj.value("value").toString();
        const qint64  ts       = obj.value("ts").toVariant().toLongLong();
        const QString nonce    = obj.value("nonce").toString();
        const QByteArray sig   = obj.value("signature").toString().toUtf8();  // hex-codiert

        // Feld-Validierung
        if (deviceId.isEmpty() || name.isEmpty() || value.isEmpty() || ts <= 0 || nonce.isEmpty() || sig.isEmpty()) {
            send(400, "application/json", R"({"error":"missing fields"})");
            return;
        }

        // Erwartete Signatur berechnen (HMAC-SHA256)
        const QByteArray message = deviceId.toUtf8()
                                   + "|" + name.toUtf8()
                                   + "|" + value.toUtf8()
                                   + "|" + QByteArray::number(ts)
                                   + "|" + nonce.toUtf8();

        // Für die Demo nutzen wir 'jwtSecret_' als HMAC-Key.
        // Wenn du magst, führe separat 'hmacSecret' in der Config ein.
        const QByteArray expectHex = computeHmacSha256(jwtSecret_, message);

        // Vergleich (case-insensitiv auf Hex-String)
        if (!QString::fromUtf8(sig).compare(QString::fromUtf8(expectHex), Qt::CaseInsensitive) == 0) {
            if (audit_) audit_("sensor", "hmac invalid device="+deviceId);
            send(401, "application/json", R"({"error":"bad signature"})");
            return;
        }

        // Replay-Schutz: (deviceId, nonce) muss neu sein (PRIMARY KEY)
        if (!storage_->insertNonce(deviceId, nonce, ts)) {
            if (audit_) audit_("sensor", "replay blocked device="+deviceId);
            send(409, "application/json", R"({"error":"replay"})");
            return;
        }

        // Daten übernehmen
        if (!storage_->insertSensor(deviceId, name, value, ts)) {
            send(500, "application/json", R"({"error":"db"})");
            return;
        }

        if (audit_) audit_("sensor", "insert device="+deviceId+" "+name+"="+value);
        send(200, "application/json", R"({"status":"ok"})");
        return;
    }

    // ---- /api/ota  (PUT binary) ---------------------------------------------
    // Der rohe Body wird als Binärdatei unter "<docRoot>/ota/" abgelegt.
    // Dateiname: "fw-YYYYMMDD-hhmmss.bin"
    if (path == "/api/ota") {
        // Sicherstellen, dass Zielordner existiert
        QDir out(docRoot + "/ota");
        if (!out.exists()) out.mkpath(".");

        const QString fileName = "fw-" + QDateTime::currentDateTimeUtc().toString("yyyyMMdd-hhmmss") + ".bin";
        const QString fullPath = out.filePath(fileName);

        QFile f(fullPath);
        if (!f.open(QIODevice::WriteOnly)) {
            send(500, "application/json", R"({"error":"io"})");
            return;
        }
        f.write(body);
        f.close();

        if (audit_) audit_("ota", "uploaded "+fileName);

        // Hinweis: Wenn du nach dem Upload etwas triggern willst (Service neu starten,
        // Signatur prüfen, Flashen, ...), dann führe in deiner HttpsServer-Konfiguration
        // einen std::function-Callback ein (z. B. onOtaUploaded) und reiche ihn wie onNumber_
        // in den HttpConnection-Konstruktor. Hier könntest du ihn dann aufrufen.

        const QJsonObject res{{"status","ok"},{"file",fileName}};
        send(200, "application/json", QJsonDocument(res).toJson(QJsonDocument::Compact));
        return;
    }

    // HMAC-geschützter Geräte-Push (Sensorwerte)
    if (m == "POST" && path == "/api/sensor/push") {
        if (log_) log_(QString("[PUSH] got %1 bytes").arg(body.size()));
        if (log_) {
            log_(QString("[SENSOR] raw len=%1 head-CL=%2")
                     .arg(body.size())
                     .arg(hdrs.value("content-length")));
            log_(QString("[SENSOR] raw first40=%1")
                     .arg(QString::fromLatin1(body.left(40))));
            log_(QString("[API] %1 %2 from %3 len=%4")
                     .arg(m, path, sock->peerAddress().toString())
                     .arg(body.size()));
        }

        const QString deviceKey = verifyHmac("POST", "/api/sensor/push", hdrs, body);
        if (deviceKey.isEmpty()) {
            if (audit_) audit_("api",
                       QString("user=unknown sensor push auth failed ip=%1")
                           .arg(sock->peerAddress().toString()));
            send(401, "application/json", "{\"err\":\"unauthorized\"}");
            return;
        }

        QJsonParseError pe; auto doc = QJsonDocument::fromJson(body, &pe);
        if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
            send(400, "application/json", "{\"err\":\"bad_json\"}");
            return;
        }
        const auto obj    = doc.object();
        const qint64 ts   = obj.value("ts").toVariant().toLongLong();
        const auto values = obj.value("values").toObject();

        // lokal, wie bei /api/sensor/latest
        int count = 0;
        for (auto it = values.begin(); it != values.end(); ++it) {
            const QString name = it.key();
            const QString val  = it.value().toVariant().toString();
            if (storage_->insertSensor(deviceKey, name, val,
                                   ts ? ts : QDateTime::currentSecsSinceEpoch())) {
                ++count;
            }
        }

        if (audit_) audit_("sensor",
                   QString("user=%1 push ok ip=%2 count=%3")
                       .arg(deviceKey)
                       .arg(sock->peerAddress().toString())
                       .arg(count));

        // --- Live-Broadcast über WebSocket (nur wenn konfiguriert) ---
        if (wsBroadcast_) {
            const qint64 tsOut = ts ? ts : QDateTime::currentSecsSinceEpoch();
            QJsonObject valuesObj;
            for (auto it = values.begin(); it != values.end(); ++it)
                valuesObj.insert(it.key(), it.value());

            QJsonObject payload{
                { "sensor", QJsonObject{
                               { "device", deviceKey },
                               { "values", valuesObj },
                               { "ts", tsOut }
                           }}
            };
            const QString msg = QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact));
            wsBroadcast_(msg);
            if (log_) log_(QString("[WS] sensor broadcast sent: %1").arg(msg));
        }
        send(200, "application/json", R"({"ok":true})");
        return;
    }

    /*
     // Javasript zur Kommunikation mit "/api/sensor/push"
// === Werte aus Environment ===
// dev_key_id = deine key_id (z.B. afa646...)
// dev_secret = dein secret GENAU wie geliefert (Base64URL!)
const keyId  = pm.environment.get("dev_key_id");
const secret = (pm.environment.get("dev_secret") || "").trim();
if (!keyId || !secret) throw new Error("dev_key_id/dev_secret im Environment setzen.");

function b64url(buf){return CryptoJS.enc.Base64.stringify(buf).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function b64urlDecodeToWordArray(s){const pad='='.repeat((4 - s.length % 4) % 4);return CryptoJS.enc.Base64.parse(s.replace(/-/g,'+').replace(/_/g,'/') + pad);}

const method = "POST";
const path   = "/api/sensor/push";         // exakt so!
const bodyRaw = pm.request.body ? (pm.request.body.raw || "") : "";

// Hash über den ROH-Body, genau wie gesendet
const bodySha = CryptoJS.SHA256(CryptoJS.enc.Utf8.parse(bodyRaw));
const bodyB64 = b64url(bodySha);

// Header-Werte
const ts    = Math.floor(Date.now()/1000).toString();
const nonce = pm.variables.replaceIn("{{$guid}}"); // neue GUID pro Request

// Canonical-String
const canon = [method.toUpperCase(), path, bodyB64, ts, nonce].join("\n");

// WICHTIG: Secret Base64URL-DEKODIEREN -> Binärschlüssel!
const key   = b64urlDecodeToWordArray(secret);
const hmac  = CryptoJS.HmacSHA256(CryptoJS.enc.Utf8.parse(canon), key);
const sign  = b64url(hmac);

// Header setzen
pm.request.headers.upsert({ key: "x-auth-keyid", value: keyId });
pm.request.headers.upsert({ key: "x-auth-ts",    value: ts });
pm.request.headers.upsert({ key: "x-auth-nonce", value: nonce });
pm.request.headers.upsert({ key: "x-auth-sign",  value: sign });

// Debug in Postman Console
console.log({ keyId, ts, nonce, bodyB64, sign, keyFrom: "base64url-decoded" });
    */


    if (m == "PUT" && path == "/api/ota/upload") {
            // Header-Map "hdrs" hast du oben bereits gebaut
            QString user;
            if (!requireAdminJwt(hdrs, &user)) {
                send(401, "application/json", R"({"error":"unauthorized"})");
                return;
            }

            // Zielordner
            QDir out(docRoot + "/ota");
            if (!out.exists()) out.mkpath(".");

            // Name aus Query ?name=..., fallback Zeitstempel
            QString fileName = "fw-" + QDateTime::currentDateTimeUtc().toString("yyyyMMdd-hhmmss") + ".bin";
            if (!query.isEmpty()) {
                const QUrlQuery qq(QString::fromUtf8(query));
                const QString n = qq.queryItemValue("name");
                if (!n.isEmpty()) fileName = n;
            }
            const QString fullPath = out.filePath(fileName);

            // Datei schreiben
            QFile f(fullPath);
            if (!f.open(QIODevice::WriteOnly)) {
                send(500, "application/json", R"({"error":"io"})");
                return;
            }
            f.write(body);
            f.close();

            // sha256 berechnen (hex)
            const QByteArray shaHex = QCryptographicHash::hash(body, QCryptographicHash::Sha256).toHex();
            const qint64 size = body.size();

            // DB eintragen
            qint64 fileId = 0;
            if (!storage_->insertOtaFile(fileName, fullPath, size, QString::fromLatin1(shaHex), &fileId)) {
                send(500, "application/json", R"({"error":"db"})");
                return;
            }

            if (audit_) audit_("ota",
                       QString("user=%1 upload file=%2 id=%3 size=%4 sha256=%5")
                           .arg(user).arg(fileName).arg(fileId).arg(size).arg(QString::fromLatin1(shaHex)));

            QJsonObject res{
                {"file_id", static_cast<qint64>(fileId)},
                {"name",    fileName},
                {"size",    static_cast<qint64>(size)},
                {"sha256",  QString::fromLatin1(shaHex)}
            };
            send(200, "application/json", QJsonDocument(res).toJson(QJsonDocument::Compact));
            return;
        }
    if (m == "POST" && path == "/api/ota/assign") {
            QString user;
            if (!requireAdminJwt(hdrs, &user)) {
                send(401, "application/json", R"({"error":"unauthorized"})");
                return;
            }

            QJsonParseError pe; auto doc = QJsonDocument::fromJson(body, &pe);
            if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
                send(400, "application/json", R"({"error":"bad_json"})");
                return;
            }
            const auto obj = doc.object();
            const QString deviceKey = obj.value("device_key").toString();
            const qint64  fileId    = obj.value("file_id").toVariant().toLongLong();
            if (deviceKey.isEmpty() || fileId <= 0) {
                send(400, "application/json", R"({"error":"missing fields"})");
                return;
            }

            qint64 jobId = 0;
            if (!storage_->createOtaJob(deviceKey, fileId, &jobId)) {
                send(500, "application/json", R"({"error":"db"})");
                return;
            }

            if (audit_) audit_("ota",
                       QString("user=%1 assign device=%2 file_id=%3 job_id=%4")
                           .arg(user).arg(deviceKey).arg(fileId).arg(jobId));

            QJsonObject res{{"job_id", static_cast<qint64>(jobId)}};
            send(200, "application/json", QJsonDocument(res).toJson(QJsonDocument::Compact));
            return;
        }
    if (m == "GET" && path == "/api/ota/poll") {
            const QString deviceKey = verifyHmac("GET", "/api/ota/poll", hdrs, QByteArray());
            if (deviceKey.isEmpty()) {
                if (audit_) audit_("ota", "user=unknown poll unauthorized");
                send(401, "application/json", R"({"error":"unauthorized"})");
                return;
            }

            qint64 jobId=0, fileId=0, size=0; QString name, sha;
            //if (!storage_->selectQueuedOtaJob(deviceKey, &jobId, &fileId, &name, &size, &sha)) {
            if (!storage_->claimNextQueuedOtaJob(deviceKey, &jobId, &fileId, &name, &size, &sha)) {
            // Kein Job → leere Antwort (oder 204, aber wir bleiben bei JSON)
                send(200, "application/json", R"({"job":null})");
                return;
            }

            // Download-URL – simpel relativ; Gerät ruft später GET /api/ota/file/<id> ab
            QJsonObject job{
                {"job_id",  static_cast<qint64>(jobId)},
                {"file_id", static_cast<qint64>(fileId)},
                {"name",    name},
                {"size",    static_cast<qint64>(size)},
                {"sha256",  sha},
                {"url",     QString("/api/ota/file/%1").arg(fileId)}
            };
            QJsonObject res{{"job", job}};
            if (audit_) audit_("ota", QString("user=%1 poll ok job_id=%2").arg(deviceKey).arg(jobId));
            send(200, "application/json", QJsonDocument(res).toJson(QJsonDocument::Compact));
            return;
        }

        // Download: Gerät holt Binärdatei – HMAC-Auth wie gewohnt
    if (m == "GET" && path.startsWith("/api/ota/file/")) {
            // 1) Auth (Body leer → sha256("") in Canonical)
            //const QString deviceKey = verifyHmac("GET", "/api/ota/file", hdrs, QByteArray());
            // Hinweis: Für strikte Signatur könntest du auch den vollen Pfad ohne Query signieren.
            // Neu (empfohlen): voller Pfad ohne Query signieren
            const QString deviceKey = verifyHmac("GET", path, hdrs, QByteArray());
            if (deviceKey.isEmpty()) { send(401,"application/json",R"({"error":"unauthorized"})"); return; }

            bool okId=false;
            const qint64 fileId = QString(path.mid(QString("/api/ota/file/").size())).toLongLong(&okId);
            if (!okId || fileId<=0) { send(400,"application/json",R"({"error":"bad_file_id"})"); return; }

            QString fullPath,name,sha; qint64 fsize=0;
            if (!storage_->getOtaFile(fileId, &fullPath, &name, &fsize, &sha)) {
                send(404,"application/json",R"({"error":"not_found"})"); return;
            }

            QFile f(fullPath);
            if (!f.open(QIODevice::ReadOnly)) { send(500,"application/json",R"({"error":"io"})"); return; }

            // NEU (case-insensitiv, QString-basiert)
            const QString rangeHdr = hdrs.value("range");      // keys sind lowercase
            bool partial = false;
            qint64 start = 0, end = fsize - 1;

            if (!rangeHdr.isEmpty() && rangeHdr.startsWith(QStringLiteral("bytes="), Qt::CaseInsensitive)) {
                const QString spec = rangeHdr.mid(6);          // nach "bytes="
                const QStringList parts = spec.split('-', Qt::KeepEmptyParts);

                bool okS = false;
                const qint64 s = parts.value(0).toLongLong(&okS);
                if (okS && s >= 0 && s < fsize) {
                    start = s; partial = true;
                    if (parts.size() > 1 && !parts[1].isEmpty()) {
                        bool okE = false;
                        const qint64 e = parts[1].toLongLong(&okE);
                        if (okE && e >= start && e < fsize) end = e;
                    }
                }
            }
            const qint64 length = end - start + 1;
            f.seek(start);
            const QByteArray payload = f.read(length);

            // Header bauen
            QByteArray h;
            if (partial) {
                h += "HTTP/1.1 206 Partial Content\r\n";
                h += "Content-Range: bytes " + QByteArray::number(start) + "-" + QByteArray::number(end) +
                     "/" + QByteArray::number(fsize) + "\r\n";
            } else {
                h += "HTTP/1.1 200 OK\r\n";
            }
            h += "Content-Type: application/octet-stream\r\n";
            h += "Content-Length: " + QByteArray::number(payload.size()) + "\r\n";
            h += "Accept-Ranges: bytes\r\n";
            h += "Connection: close\r\n\r\n";

            sock->write(h);
            sock->write(payload);
            sock->disconnectFromHost();
            return;
        }

    if (m == "POST" && path == "/api/devices") {
            QString adminUser;
            if (!requireAdminJwt(hdrs, &adminUser)) { send(401,"application/json",R"({"error":"unauthorized"})"); return; }

            QJsonParseError pe; auto doc = QJsonDocument::fromJson(body, &pe);
            if (pe.error!=QJsonParseError::NoError || !doc.isObject()) { send(400,"application/json",R"({"error":"bad_json"})"); return; }
            const auto o = doc.object();

            QString keyId = o.value("key_id").toString().trimmed();
            if (keyId.isEmpty()) keyId = QUuid::createUuid().toString(QUuid::WithoutBraces).replace("-", "");
            if (!isValidKeyId(keyId)) { send(400,"application/json",R"({"error":"bad_key_id"})"); return; }

            QString secret = o.value("secret").toString();
            if (secret.isEmpty()) secret = genDeviceSecretB64Url(32);

            const bool enabled = o.contains("enabled") ? o.value("enabled").toBool(true) : true;
            const QString fw   = o.value("firmware").toString();   // <<<<<< deklarieren!

            if (!storage_->createDevice(keyId, secret, enabled, fw)) {
                send(409,"application/json",R"({"error":"conflict_or_db"})");
                return;
            }

            if (audit_) audit_("device", QString("user=%1 create key=%2 enabled=%3").arg(adminUser, keyId, enabled?"1":"0"));

            QJsonObject res{
                {"key_id", keyId},
                {"secret", secret},      // secret nur beim Erstellen zurückgeben
                {"enabled", enabled},
                {"firmware", fw},
                {"last_seen", 0}
            };
            send(200,"application/json", QJsonDocument(res).toJson(QJsonDocument::Compact));
            return;
        }

    if (m == "GET" && path.startsWith("/api/devices/")) {
        QString adminUser;
        if (!requireAdminJwt(hdrs, &adminUser)) {
            send(401,"application/json",R"({"error":"unauthorized"})"); return;
        }

        const QString keyId = QString(path.mid(QString("/api/devices/").size()));
        if (!isValidKeyId(keyId)) { send(400,"application/json",R"({"error":"bad_key_id"})"); return; }

        QString sec, fw; bool en=false; qint64 seen=0;
        if (!storage_->findDevice(keyId, &sec, &en, &fw, &seen)) {
            send(404,"application/json",R"({"error":"not_found"})"); return;
        }

        bool showSecret = false;
        if (!query.isEmpty()) {
            const QUrlQuery qq(QString::fromUtf8(query));
            showSecret = (qq.queryItemValue("show_secret") == "1");
        }

        QJsonObject res{
            {"key_id",  keyId},
            {"enabled", en},
            {"firmware", fw},
            {"last_seen", static_cast<qint64>(seen)}
        };
        if (showSecret) res["secret"] = sec;

        send(200,"application/json",
             QJsonDocument(res).toJson(QJsonDocument::Compact));
        return;
    }

    if (m == "PUT" && path.startsWith("/api/devices/")) {
            QString adminUser;
            if (!requireAdminJwt(hdrs, &adminUser)) { send(401,"application/json",R"({"error":"unauthorized"})"); return; }

            const QString keyId = QString(path.mid(QString("/api/devices/").size()));
            if (!isValidKeyId(keyId)) { send(400,"application/json",R"({"error":"bad_key_id"})"); return; }

            QJsonParseError pe; auto doc = QJsonDocument::fromJson(body, &pe);
            if (pe.error != QJsonParseError::NoError || !doc.isObject()) { send(400,"application/json",R"({"error":"bad_json"})"); return; }
            const auto o = doc.object();

            QJsonObject res{{"key_id", keyId}};

            if (o.contains("enabled")) {
                const bool en = o.value("enabled").toBool();
                if (storage_->updateDeviceEnabled(keyId, en)) { send(404,"application/json",R"({"error":"not_found"})"); return; }
                res["enabled"] = en;
            }
            if (o.contains("firmware")) {
                const QString fw = o.value("firmware").toString();
                if (!storage_->updateDeviceFirmware(keyId, fw)) { send(404,"application/json",R"({"error":"not_found"})"); return; }
                if (audit_) audit_("device", QString("user=%1 set-firmware key=%2 fw=%3").arg(adminUser, keyId, fw));
                res["firmware"] = fw;  // <<<<<< nicht 'firmware' un-deklar. verwenden
            }
            if (o.contains("rotate") && o.value("rotate").toBool()) {
                const QString newSec = genDeviceSecretB64Url(32);
                if (!storage_->updateDeviceSecret(keyId, newSec)) { send(404,"application/json",R"({"error":"not_found"})"); return; }
                res["secret"] = newSec; // nur hier einmal ausgeben
            }

            send(200,"application/json", QJsonDocument(res).toJson(QJsonDocument::Compact));
            return;
        }

    if (m == "DELETE" && path.startsWith("/api/devices/")) {
            QString adminUser;
            if (!requireAdminJwt(hdrs, &adminUser)) { send(401,"application/json",R"({"error":"unauthorized"})"); return; }

            const QString keyId = QString(path.mid(QString("/api/devices/").size()));
            if (!isValidKeyId(keyId)) { send(400,"application/json",R"({"error":"bad_key_id"})"); return; }

            if (!storage_->deleteDevice(keyId)) { send(404,"application/json",R"({"error":"not_found"})"); return; }

            if (audit_) audit_("device", QString("user=%1 delete key=%2").arg(adminUser, keyId));
            send(200,"application/json", R"({"ok":true})");
            return;
        }


    if (m == "GET" && path == "/api/devices") {
            QString adminUser;
            if (!requireAdminJwt(hdrs, &adminUser)) { send(401,"application/json",R"({"error":"unauthorized"})"); return; }

            // optional: ?limit=..., ?offset=...
            int limit=200, offset=0;
            if (!query.isEmpty()) {
                const QUrlQuery qq(QString::fromUtf8(query));
                bool okL=false, okO=false;
                const int L = qq.queryItemValue("limit").toInt(&okL);
                const int O = qq.queryItemValue("offset").toInt(&okO);
                if (okL && L>0 && L<=1000) limit=L;
                if (okO && O>=0) offset=O;
            }

            QSqlQuery q = storage_->listDevices(limit, offset);
            QJsonArray arr;
            while (q.next()) {
                QJsonObject d;
                d["id"]        = q.value(0).toInt();
                d["key_id"]    = q.value(1).toString();
                d["enabled"]   = (q.value(2).toInt()!=0);
                d["firmware"]  = q.value(3).toString();
                d["last_seen"] = q.value(4).toLongLong();
                arr.append(d);
            }
            send(200,"application/json", QJsonDocument(QJsonObject{{"items", arr}}).toJson(QJsonDocument::Compact));
            return;
        }


        if (m == "POST" && path == "/api/ota/progress") {
            const QString deviceKey = verifyHmac("POST", "/api/ota/progress", hdrs, body);
            if (deviceKey.isEmpty()) { send(401,"application/json",R"({"error":"unauthorized"})"); return; }

            QJsonParseError pe; auto doc = QJsonDocument::fromJson(body, &pe);
            if (pe.error!=QJsonParseError::NoError || !doc.isObject()) { send(400,"application/json",R"({"error":"bad_json"})"); return; }
            const auto o = doc.object();
            const qint64 jobId = o.value("job_id").toVariant().toLongLong();
            const QString state = o.value("state").toString();
            const int progress  = o.value("progress").toInt();
            const QString error = o.value("error").toString();

            if (jobId<=0 || state.isEmpty()) { send(400,"application/json",R"({"error":"missing_fields"})"); return; }

            // 1) Job nachschlagen und ownership prüfen
            QString jobDev;
            if (!storage_->getOtaJobDevice(jobId, &jobDev)) {
                send(404, "application/json", R"({"error":"job_not_found"})");
                return;
            }
            if (jobDev != deviceKey) {
                send(403, "application/json", R"({"error":"job_for_other_device"})");
                return;
            }

            // 2) Update durchführen
            if (!storage_->updateOtaJobState(jobId, state, progress)) {
                send(500,"application/json",R"({"error":"db"})"); return;
            }

            // 3) Audit + optional WS-Broadcast
            if (audit_) audit_("ota",
                       QString("user=%1 job=%2 state=%3 progress=%4 err=%5")
                           .arg(deviceKey).arg(jobId).arg(state).arg(progress).arg(error));

            if (wsBroadcast_) {
                QJsonObject payload{
                    {"ota", QJsonObject{
                                {"device", deviceKey},
                                {"job_id", static_cast<qint64>(jobId)},
                                {"state", state},
                                {"progress", progress},
                                {"error", error}
                            }}
                };
                wsBroadcast_(QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
            }

            send(200,"application/json",R"({"ok":true})");
            return;
        }
    // Fallback: Unbekannte API-Route
    send(404, "application/json", R"({"error":"not found"})");
}



// ============================================================================
// Antwort senden (einfacher HTTP/1.1-Writer; wir schließen die Verbindung)
// ============================================================================

void HttpConnection::send(int code, const QByteArray& ctype, const QByteArray& payload) {
    QByteArray head;
    head += "HTTP/1.1 " + QByteArray::number(code) + " ";
    // Sehr vereinfachte Reason-Phrase
    switch (code) {
    case 200: head += "OK\r\n"; break;
    case 400: head += "Bad Request\r\n"; break;
    case 401: head += "Unauthorized\r\n"; break;
    case 404: head += "Not Found\r\n"; break;
    case 405: head += "Method Not Allowed\r\n"; break;
    case 409: head += "Conflict\r\n"; break;
    case 500: head += "Internal Server Error\r\n"; break;
    default:  head += "\r\n"; break;
    }
    head += "Content-Type: "   + ctype + "\r\n";
    head += "Content-Length: " + QByteArray::number(payload.size()) + "\r\n";
    head += "Connection: close\r\n";             // wir schließen bewusst
    head += "\r\n";

    // Reihenfolge: Header → Body → Verbindung beenden
    sock->write(head);
    if (!payload.isEmpty()) sock->write(payload);
    sock->disconnectFromHost();                  // harten Abschluss vermeiden: sauber schließen
}

// ============================================================================
// (optional) URL-Decoding als kleine Utility (Header-Signatur sieht es vor)
// ============================================================================

// Vergleicht zwei QByteArrays timing-sicher (klein & ausreichend hier)
static bool constTimeEq1(const QByteArray& a, const QByteArray& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (int i = 0; i < a.size(); ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}
/*
// Base64URL ohne '='
static QByteArray b64url(const QByteArray& bin) {
    return bin.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

// SHA-256 Digest
static QByteArray sha256(const QByteArray& d) {
    return QCryptographicHash::hash(d, QCryptographicHash::Sha256);
}   */

QString HttpConnection::verifyHmac(const QString& method,
                                   const QString& path,
                                   const QMap<QString, QString>& headers,
                                   const QByteArray& body)
{
    // Header → lowercase Map
    QMap<QString, QString> hdrs;
    for (auto it = headers.constBegin(); it != headers.constEnd(); ++it)
        hdrs.insert(it.key().toLower(), it.value());

    const QString keyId = hdrs.value(QStringLiteral("x-auth-keyid"));
    const QString tsStr = hdrs.value(QStringLiteral("x-auth-ts"));
    const QString nonce = hdrs.value(QStringLiteral("x-auth-nonce"));
    const QString sign  = hdrs.value(QStringLiteral("x-auth-sign"));

    if (log_) log_(QString("[HMAC] recv keyId=%1 ts=%2 nonce=%3 sign.len=%4")
                 .arg(keyId, tsStr, nonce)
                 .arg(sign.size()));

    if (keyId.isEmpty() || tsStr.isEmpty() || nonce.isEmpty() || sign.isEmpty()) {
        if (log_) log_("[HMAC] missing header(s)");
        return {};
    }

    // Zeitfenster prüfen
    bool okTs=false;
    const qint64 ts  = tsStr.toLongLong(&okTs);
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 skew = now - ts;
    if (log_) log_(QString("[HMAC] time now=%1 ts=%2 skew=%3s").arg(now).arg(ts).arg(skew));
    if (!okTs || qAbs(skew) > 300) {
        if (log_) log_("[HMAC] ts out of window");
        return {};
    }

    // Device-Secret holen (nimm storage_ falls vorhanden)
    QString secret; bool enabled=false;
    bool devOk=false;
    if (storage_) {
        devOk = storage_->findDevice(keyId, &secret, &enabled);
    } else {
        Storage store; devOk = store.findDevice(keyId, &secret, &enabled);
    }
    if (!devOk || !enabled) {
        if (log_) log_(QString("[HMAC] device not found or disabled: %1").arg(keyId));
        return {};
    }

    // --- Body-Hash + Base64url (nur fürs Log sichtbar machen) ---
    // 1) HMAC-Key: Base64URL-Secret als BYTES dekodieren
    const QByteArray keyBytes = b64urlToBytes(secret);  // <--- WICHTIG
    const QByteArray bodySha = sha256(body);       // dein Helper
    const QByteArray bodyB64 = b64url(bodySha);    // dein Helper
    if (log_) log_(QString("[HMAC] path=%1 body.size=%2 bodySha.b64=%3")
                 .arg(path)
                 .arg(body.size())
                 .arg(QString::fromLatin1(bodyB64)));

    // --- Canonical genau wie gehabt ---
    QByteArray canon;
    canon += method.toUtf8().toUpper();  canon += '\n';
    canon += path.toUtf8();              canon += '\n';
    canon += bodyB64;                    canon += '\n';      // <== identisch zu b64url(sha256(body))
    canon += tsStr.toUtf8();             canon += '\n';
    canon += nonce.toUtf8();

    // HMAC berechnen
  //  const QByteArray mac    = QMessageAuthenticationCode::hash(canon, secret.toUtf8(), QCryptographicHash::Sha256);
    // (Base64URL-Decoding + Trim für Sicherheit):
    QByteArray sec = secret.trimmed().toUtf8();
    sec = QByteArray::fromBase64(sec, QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    //const QByteArray mac = QMessageAuthenticationCode::hash(canon, sec, QCryptographicHash::Sha256);
    const QByteArray mac    = QMessageAuthenticationCode::hash(canon, keyBytes, QCryptographicHash::Sha256);
    const QByteArray macB64 = b64url(mac);

    if (log_) {
        QString c = QString::fromLatin1(canon).replace('\n', "\\n");
        log_(QString("[HMAC] canon=\"%1\"").arg(c));
        log_(QString("[HMAC] expect.sign=%1 recv.sign=%2")
                 .arg(QString::fromLatin1(macB64), sign));
    }

    // 4) Timing-sicher vergleichen
    if (!bytesEqualCT(macB64, sign.toUtf8())) {
        if (log_) log_(QString("[HMAC] mismatch  expect=%1  recv=%2").arg(QString::fromLatin1(macB64), sign));
        return {};
    }

    // Nonce-Replay verhindern
    bool nonceOk=false;
    if (storage_) nonceOk = storage_->insertNonce(keyId, nonce, ts);
    else          nonceOk = Storage().insertNonce(keyId, nonce, ts);

    if (!nonceOk) {
        if (log_) log_("[HMAC] nonce replay (already used)");
        return {};
    }

    if (storage_) storage_->updateDeviceLastSeen(keyId, now);
    else          Storage().updateDeviceLastSeen(keyId, now);

    return keyId;
}

void HttpConnection::parseIncoming() {
    // Größenlimits (anpassbar)
    constexpr int kMaxHeader = 16 * 1024;
    constexpr int kMaxBody   = 256 * 1024;

    for (;;) {
        // ---------- 1) Header vollständig? ----------
        if (!headersDone_) {
            // Header-Limit (Slowloris-Protektor light)
            if (rx_.size() > kMaxHeader) {
                send(431, "text/plain", "header too large");
                rx_.clear();
                resetRequestState();
                sock->disconnectFromHost();
                return;
            }

            const int p = rx_.indexOf("\r\n\r\n");
            if (p < 0) {
                // unvollständig → auf mehr Daten warten
                return;
            }

            // Headerteil + Request-Line parsen
            headerEnd_ = p + 4;
            const QByteArray head = rx_.left(p);
            const QList<QByteArray> lines = head.split('\n');
            if (lines.isEmpty()) { rx_.remove(0, headerEnd_); continue; }

            const QByteArray rl = lines.first().trimmed();          // "METHOD /path HTTP/1.1"
            const QList<QByteArray> parts = rl.split(' ');
            if (parts.size() < 2) { rx_.remove(0, headerEnd_); continue; }
            method_ = parts[0];
            path_   = parts[1];

            hdrs_.clear();
            for (int i = 1; i < lines.size(); ++i) {
                QByteArray line = lines[i].trimmed();
                if (line.isEmpty()) continue;
                const int c = line.indexOf(':');
                if (c > 0) {
                    QByteArray k = line.left(c).trimmed();
                    QByteArray v = line.mid(c + 1).trimmed();
                    hdrs_.append({k, v});
                }
            }

            // Transfer-Encoding: chunked → derzeit nicht unterstützt
            // → semantisch korrekt als 501 melden
            bool isChunked = false;
            for (const auto& kv : hdrs_) {
                if (kv.first.compare("Transfer-Encoding", Qt::CaseInsensitive) == 0) {
                    if (kv.second.contains("chunked", Qt::CaseInsensitive)) {
                        isChunked = true; break;
                    }
                }
            }
            if (isChunked) {
                send(501, "text/plain", "chunked unsupported");
                rx_.clear();
                resetRequestState();
                return;
            }

            // Content-Length ermitteln (nicht vorhanden → 0)
            contentLen_ = 0;
            for (const auto& kv : hdrs_) {
                if (kv.first.compare("Content-Length", Qt::CaseInsensitive) == 0) {
                    bool ok = false;
                    const int cl = QString::fromLatin1(kv.second).trimmed().toInt(&ok);
                    if (!ok || cl < 0) {
                        send(400, "text/plain", "bad content-length");
                        rx_.clear();
                        resetRequestState();
                        return;
                    }
                    contentLen_ = cl;
                    break;
                }
            }

            // Body-Limit
            if (contentLen_ > kMaxBody) {
                send(413, "text/plain", "body too large");
                rx_.clear();
                resetRequestState();
                sock->disconnectFromHost();
                return;
            }

            headersDone_ = true;
            if (log_) log_(QString("[parse] CL=%1 buf=%2").arg(contentLen_).arg(rx_.size()));
        }

        // ---------- 2) Genug Body im Puffer? ----------
        const int have = rx_.size() - headerEnd_;
        if (have < contentLen_) {
            // noch unvollständig → warten
            return;
        }

        // ---------- 3) Request ist vollständig ----------
        const QByteArray body = (contentLen_ > 0)
                                    ? rx_.mid(headerEnd_, contentLen_)
                                    : QByteArray();

        if (log_) log_(QString("[parse] body.size=%1 path=%2")
                     .arg(body.size())
                     .arg(QString::fromUtf8(path_)));

        // ---------- 4) Router/Handler ----------
        // Achte darauf: Wir übergeben *raw* method/path + alle Header
        handleApiRequest(method_, path_, body, hdrs_);  // neue Signatur ist bereits im Header deklariert. :contentReference[oaicite:0]{index=0}

        // ---------- 5) Puffer zuschneiden & State zurücksetzen ----------
        rx_.remove(0, headerEnd_ + contentLen_);
        resetRequestState();

        // ---------- 6) Nächsten Request aus dem Buffer (falls vorhanden) ----------
        if (rx_.isEmpty()) return;
    }
}

/*
QString HttpConnection::verifyHmac(const QString& method,
                                   const QString& path,
                                   const QMap<QString, QString>& headers,
                                   const QByteArray& body)
{
    // 1) Header-Map case-insensitiv machen (alles lowercase)
    QMap<QString, QString> hdrs;
    for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
        hdrs.insert(it.key().toLower(), it.value());
    }

    const QString keyId = hdrs.value(QStringLiteral("x-auth-keyid"));
    const QString tsStr = hdrs.value(QStringLiteral("x-auth-ts"));
    const QString nonce = hdrs.value(QStringLiteral("x-auth-nonce"));
    const QString sign  = hdrs.value(QStringLiteral("x-auth-sign"));

    if (log_) log_(QString("[HMAC] recv keyId=%1 ts=%2 nonce=%3 sign.len=%4")
                 .arg(keyId, tsStr, nonce)
                 .arg(sign.size()));

    if (keyId.isEmpty() || tsStr.isEmpty() || nonce.isEmpty() || sign.isEmpty()){
        if (log_) log_("[HMAC] missing header(s)");
        return {};
    }

    // 2) Zeitfenster prüfen (±300s Skew)
    bool okTs=false;
    const qint64 ts = tsStr.toLongLong(&okTs);
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 skew = now - ts;
    if (log_) log_(QString("[HMAC] time now=%1 ts=%2 skew=%3s").arg(now).arg(ts).arg(skew));
    if (!okTs || qAbs(skew) > 300) {
        if (log_) log_("[HMAC] ts out of window");
        return {};
    }


    // 3) Secret + enabled aus DB holen
    QString secret;
    bool enabled = false;
    if (!storage_->findDevice(keyId, &secret, &enabled) || !enabled){
        if (log_) log_(QString("[HMAC] device not found or disabled: %1").arg(keyId));
        return {};
    }

    // 4) Replay-Schutz per Nonce: (keyId, nonce) muss neu sein
    if (!storage_->insertNonce(keyId, nonce, ts)){
        if (log_) log_("[HMAC] nonce replay (already used)");
        return {};
    }

    // 5) Canonical-String aufbauen:
    //    METHOD(upper) \n PATH \n b64url(sha256(body)) \n TS \n NONCE
    QByteArray canon;
    canon += method.toUtf8().toUpper();  canon += '\n';
    canon += path.toUtf8();              canon += '\n';
    canon += b64url(sha256(body));       canon += '\n';
    canon += tsStr.toUtf8();             canon += '\n';
    canon += nonce.toUtf8();

    // 6) HMAC-SHA256 berechnen und Base64URL encodieren
    const QByteArray mac    = QMessageAuthenticationCode::hash(canon, secret.toUtf8(), QCryptographicHash::Sha256);
    const QByteArray macB64 = b64url(mac);
    if (log_) {
        QString c = QString::fromLatin1(canon).replace('\n',"\\n");
        log_(QString("[HMAC] canon=\"%1\"").arg(c));
        log_(QString("[HMAC] expect.sign=%1 recv.sign=%2").arg(QString::fromLatin1(macB64), sign));
    }

    // 7) Timing-sicher vergleichen
    if (!bytesEqualCT(macB64, sign.toUtf8())){
        if (log_) log_("[HMAC] signature mismatch");
        return {};
    }

    // 8) Erfolg → last_seen aktualisieren
    storage_->updateDeviceLastSeen(keyId, now);

    return keyId; // ✅ authentifiziertes Gerät
}
*/

void HttpConnection::resetRequestState()
{
    method_.clear();
    path_.clear();
    hdrs_.clear();

    headersDone_ = false;
    headerEnd_   = 0;
    contentLen_  = 0;

    // rx_ NICHT leeren! (der Rest des Streams kann noch weitere Requests enthalten)
}

bool HttpConnection::requireAdminJwt(const QMap<QString, QString>& hdrs, QString* userOut)
{
    // 1) Token holen: Authorization: Bearer <jwt>  oder  Cookie: token=<jwt>
    QString tok;
    const QString auth = hdrs.value("authorization");
    if (auth.startsWith("Bearer ", Qt::CaseInsensitive))
        tok = auth.mid(7).trimmed();

    if (tok.isEmpty()) {
        const QString cookie = hdrs.value("cookie");
        const auto parts = cookie.split(';', Qt::SkipEmptyParts);
        for (const auto& p : parts) {
            const auto kv = p.trimmed().split('=');
            if (kv.size() == 2 && kv[0].trimmed() == "token") {
                tok = kv[1].trimmed();
                break;
            }
        }
    }

    if (tok.isEmpty()) {
        if (log_) log_("[AUTH] no JWT provided");
        return false;
    }

    // 2) Verifizieren (HS256, exp wird in Jwt::verify geprüft)
    Jwt jwt(jwtSecret_);
    const QJsonObject claims = jwt.verify(tok);
    if (claims.isEmpty()) {
        if (log_) log_("[AUTH] JWT verify failed/expired");
        return false;
    }

    // 3) Rolle prüfen
    const QString role = claims.value("role").toString();
    const QString sub  = claims.value("sub").toString();
    if (userOut) *userOut = sub;

    const bool isAdmin = (role.compare("admin", Qt::CaseInsensitive) == 0);
    if (!isAdmin) {
        if (log_) log_(QString("[AUTH] forbidden, role=%1 user=%2").arg(role, sub));
        return false;
    }
    return true;
}
/*
// Liest "Authorization: Bearer <JWT>" und prüft via Jwt(jwtSecret_)
bool HttpConnection::requireAdminJwt(const QMap<QString,QString>& hdrs, QString* userOut) {
    const QString auth = hdrs.value("Authorization", hdrs.value("authorization"));
    if (!auth.startsWith("Bearer ")) return false;
    const QString token = auth.mid(7).trimmed();

    Jwt jwt(jwtSecret_);
    const QJsonObject claims = jwt.verify(token);
    if (claims.isEmpty()) return false;
    const QString sub  = claims.value("sub").toString();
    const QString role = claims.value("role").toString(); // optional
    if (userOut) *userOut = sub;
    // Optional: rolle prüfen
    if (!role.isEmpty() && role != "admin") return false;  // falls du Rollen nutzt
    return true;
}  */


/*
#include "HttpConnection.h"
#include "Jwt.h"
#include <QtNetwork/QSslSocket>
#include <QtNetwork/QSslCertificate>
#include <QtCore/QFile>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QCryptographicHash>
#include <QtCore/QSet>
#include <QJsonObject>
#include "HmacAuth.h"
#include <QJsonDocument>
#include <QJsonArray>


HttpConnection::HttpConnection(QSslSocket* s, QString documentRoot,
                               std::function<void(int)> onNumber,
                               std::function<void(QString)> log,
                               QByteArray jwtSecret,
                               std::function<void(QString, QString)> audit,
                               QObject* parent)
    : QObject(parent),
    sock(s),
    docRoot(std::move(documentRoot)),
    onNumber_(std::move(onNumber)),
    log_(std::move(log)),
    jwtSecret_(std::move(jwtSecret)),
    audit_(std::move(audit))
{
    QObject::connect(sock, &QSslSocket::encrypted,    this, [this]{ onEncrypted(); });
    QObject::connect(sock, &QSslSocket::readyRead,    this, [this]{ onReadyRead(); });
    QObject::connect(sock, &QSslSocket::disconnected, this, [this]{ onDisconnected(); });

    setupStateMachine();
}

// ---------------- StateMachine ----------------

void HttpConnection::setupStateMachine() {
    stateConnected     = new QState();
    stateTlsOk         = new QState();
    stateAuthenticated = new QState();
    stateClosed        = new QState();

    machine.addState(stateConnected);
    machine.addState(stateTlsOk);
    machine.addState(stateAuthenticated);
    machine.addState(stateClosed);
    machine.setInitialState(stateConnected);

    // Transitions via signals
    stateConnected->addTransition(this, &HttpConnection::tlsOk, stateTlsOk);
    stateTlsOk->addTransition(this, &HttpConnection::authenticated, stateAuthenticated);
    stateConnected->addTransition(this, &HttpConnection::closed, stateClosed);
    stateTlsOk->addTransition(this, &HttpConnection::closed, stateClosed);
    stateAuthenticated->addTransition(this, &HttpConnection::closed, stateClosed);

    // Entry actions
    connect(stateConnected, &QState::entered, this, [this]{
        currentStateName = "Connected";
        if (audit_) audit_("state", "Connected");
    });
    connect(stateTlsOk, &QState::entered, this, [this]{
        currentStateName = "TlsOk";
        if (audit_) audit_("state", "TLS_OK");
    });
    connect(stateAuthenticated, &QState::entered, this, [this]{
        currentStateName = "Authenticated";
        if (audit_) audit_("state", "Authenticated");
    });
    connect(stateClosed, &QState::entered, this, [this]{
        currentStateName = "Closed";
        if (audit_) audit_("state", "Closed");
    });

    machine.start();
}

// ---------------- TLS Handshake ----------------

void HttpConnection::onEncrypted() {
    if (log_) log_(QStringLiteral("TLS handshake complete from %1").arg(sock->peerAddress().toString()));

    static const QSet<QString> kAllowedCN = {
        QStringLiteral("test-client"),
    };

    const QSslCertificate pc = sock->peerCertificate();
    if (pc.isNull()) {
        if (log_) log_("mTLS deny: no client certificate");
        if (audit_) audit_("mTLS", "deny: no client certificate");
        sock->abort();
        return;
    }

    const QString cn = pc.subjectInfo(QSslCertificate::CommonName).join(", ");
    const QByteArray fp = pc.digest(QCryptographicHash::Sha256).toHex().toLower();

    bool allowed = false;
    if (!kAllowedCN.isEmpty() && kAllowedCN.contains(cn)) allowed = true;

    if (!allowed) {
        if (log_) log_(QStringLiteral("mTLS deny: CN=%1, FP=%2").arg(cn, QString::fromUtf8(fp)));
        if (audit_) audit_("mTLS", QString("deny: CN=%1").arg(cn));
        sock->abort();
        return;
    }

    if (log_) {
        const QString issuer = pc.issuerInfo(QSslCertificate::CommonName).join(", ");
        log_(QStringLiteral("mTLS accept: CN=%1, Issuer=%2, FP=%3").arg(cn, issuer, QString::fromUtf8(fp)));
    }
    if (audit_) audit_("mTLS", QString("accept: CN=%1").arg(cn));

    emit tlsOk();
}

// ---------------- HTTP Parser / Router ----------------

void HttpConnection::onReadyRead() {
    buffer += sock->readAll();

    const int headerEnd = buffer.indexOf("\r\n\r\n");
    if (headerEnd < 0) return;
    const QByteArray header = buffer.left(headerEnd);
    const QList<QByteArray> lines = header.split('\n');
    if (lines.isEmpty()) return;

    const QByteArray reqLine = lines.first().trimmed();
    const QList<QByteArray> parts = reqLine.split(' ');
    if (parts.size() < 3) return;
    const QByteArray method = parts[0];
    const QByteArray path   = parts[1];

    int contentLength = 0;
    for (int i=1;i<lines.size();++i) {
        const auto l = lines[i].trimmed().toLower();
        if (l.startsWith("content-length:")) {
            const int idx = l.indexOf(':');
            if (idx > 0) contentLength = l.mid(idx+1).trimmed().toInt();
        }
    }

    const int totalNeeded = headerEnd + 4 + contentLength;
    if (buffer.size() < totalNeeded) return;
    const QByteArray body = buffer.mid(headerEnd+4, contentLength);

    // ---------------- Routing je nach State ----------------
    if (currentStateName == "TlsOk") {
        if (method == "POST" && path == "/login") {
            handleLogin(body);
        } else if (method == "GET" && (path == "/" || path == "/index.html")) {
            serveIndex();
        } else {
            send(403, "application/json", "{\"error\":\"not authenticated\"}");
        }
    }
    else if (currentStateName == "Authenticated") {
        if (path.startsWith("/api/")) {
            handleApiRequest(path, body);
        } else if (method == "POST" && path == "/submit") {
            handleSubmit(body);
        } else {
            send(404, "application/json", "{\"error\":\"not found\"}");
        }
    }
    else {
        send(403, "application/json", "{\"error\":\"invalid state\"}");
    }

    sock->disconnectFromHost();
}

void HttpConnection::onDisconnected() {
    emit closed();
    deleteLater();
}

// ---------------- Handlers ----------------

void HttpConnection::serveIndex() {
    const QString p = QDir(docRoot).filePath(QStringLiteral("index.html"));
    QFile f(p);
    if (f.open(QIODevice::ReadOnly)) {
        const QByteArray html = f.readAll();
        send(200, "text/html; charset=utf-8", html);
    } else {
        const QByteArray html =
            "<!doctype html><html><body>"
            "<h1>Qt TLS/mTLS Server mit JWT + StateMachine</h1>"
            "<form action=\"/submit\" method=\"post\">"
            "<label>Zahl: <input type=\"number\" name=\"value\" required></label>"
            "<button type=\"submit\">Senden</button>"
            "</form>"
            "</body></html>";
        send(200, "text/html; charset=utf-8", html);
    }
}

void HttpConnection::handleSubmit(const QByteArray& body) {
    int number = 0; bool found = false;
    const QList<QByteArray> params = body.split('&');
    for (const auto& p : params) {
        const auto kv = p.split('=');
        if (kv.size()==2 && kv[0]=="value") {
            const QByteArray dec = urlDecode(kv[1]);
            bool ok=false; int v = QString::fromUtf8(dec).toInt(&ok);
            if (ok) { number=v; found=true; break; }
        }
    }
    if (!found) { send(400, "text/plain; charset=utf-8", "Bad Request: missing value"); return; }
    if (onNumber_) onNumber_(number);
    if (audit_) audit_("submit", QString("number=%1").arg(number));
    send(200, "text/plain; charset=utf-8", QByteArray("OK ") + QByteArray::number(number));
}

void HttpConnection::handleLogin(const QByteArray& body) {
    QString user, pass;
    for (const auto& p : body.split('&')) {
        const auto kv = p.split('=');
        if (kv.size()==2) {
            const auto key = kv[0];
            const auto val = QString::fromUtf8(urlDecode(kv[1]));
            if (key=="user") user=val;
            else if (key=="pass") pass=val;
        }
    }

    if (user=="alice" && pass=="secret") {
        Jwt jwt(jwtSecret_);
        QJsonObject claims;
        claims["sub"] = user;
        QString token = jwt.sign(claims, 3600);
        send(200, "application/json", QByteArray("{\"token\":\"") + token.toUtf8() + "\"}");
        if (audit_) audit_("login", QString("user=%1 success").arg(user));
        emit authenticated();
    } else {
        send(401, "application/json", "{\"error\":\"invalid credentials\"}");
        if (audit_) audit_("login", QString("user=%1 failed").arg(user));
    }
}

void HttpConnection::handleApiRequest(const QByteArray& path, const QByteArray& body) {
    QList<QByteArray> headers = buffer.left(buffer.indexOf("\r\n\r\n")).split('\n');
    QString authHeader;
    for (const auto& h : headers) {
        if (h.trimmed().toLower().startsWith("authorization:")) {
            authHeader = QString::fromUtf8(h.mid(h.indexOf(':')+1)).trimmed();
            break;
        }
    }

    if (!authHeader.startsWith("Bearer ")) {
        send(401, "application/json", "{\"error\":\"missing bearer token\"}");
        if (audit_) audit_("api", "missing bearer token");
        return;
    }

    QString token = authHeader.mid(QString("Bearer ").size());
    Jwt jwt(jwtSecret_);
    QJsonObject claims = jwt.verify(token);
    if (claims.isEmpty()) {
        send(401, "application/json", "{\"error\":\"invalid or expired token\"}");
        if (audit_) audit_("api", "invalid token");
        return;
    }

    QString subject = claims.value("sub").toString();
    if (path == "/api/hello") {
        send(200, "application/json",
             QByteArray("{\"msg\":\"Hello, ") + subject.toUtf8() + "\"}");
        if (audit_) audit_("api", QString("user=%1 hello").arg(subject));
    }

    // -------------------------------------------------------------------------
    // NEU: REST – Sensor-Upload via HMAC-SHA256
    // -------------------------------------------------------------------------
    else if (path == "/api/v1/sensor") {
        QString dev = subject; // alternativ aus Claims lesen
        QString nonce = "none"; // optional
        qint64 ts = QDateTime::currentSecsSinceEpoch();

        // In realen Clients: Header mit Signatur mitsenden (hier Dummy-Test)
        QByteArray sig = "dummy";

        HmacAuth auth(jwtSecret_);  // du kannst dafür cfg_.hmacSecret nutzen, falls vorhanden
        QString err;
        if (!auth.verify(dev, ts, nonce, body, sig, &err)) {
            send(401, "application/json",
                 QByteArray("{\"error\":\"unauthorized\",\"detail\":\"") + err.toUtf8() + "\"}");
            if (audit_) audit_("sensor", "invalid HMAC signature");
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(body);
        if (!doc.isObject()) {
            send(400, "application/json", "{\"error\":\"bad json\"}");
            return;
        }

        QJsonArray arr = doc.object().value("measurements").toArray();
        for (const auto& v : arr) {
            const QJsonObject o = v.toObject();
            QString name = o["name"].toString();
            QString value = o["value"].toVariant().toString();
            if (onNumber_) onNumber_(value.toInt());
            if (audit_) audit_("sensor", QString("%1=%2").arg(name, value));
        }

        send(200, "application/json", "{\"status\":\"ok\"}");
        if (audit_) audit_("sensor", QString("user=%1 sensor data accepted").arg(subject));
    }
    else {
        send(404, "application/json", "{\"error\":\"api not found\"}");
        if (audit_) audit_("api", QString("user=%1 unknown path=%2")
                              .arg(subject, QString::fromUtf8(path)));
    }

}

// ---------------- Helpers ----------------

void HttpConnection::send(int code, const QByteArray& ctype, const QByteArray& payload) {
    QByteArray status = QByteArray::number(code);
    const char* text = (code==200?"OK":code==400?"Bad Request":code==401?"Unauthorized":code==403?"Forbidden":code==404?"Not Found":"");
    QByteArray resp;
    resp += "HTTP/1.1 " + status + " " + text + "\r\n";
    resp += "Date: " + QDateTime::currentDateTimeUtc().toString("ddd, dd MMM yyyy HH:mm:ss 'GMT'").toUtf8() + "\r\n";
    resp += "Connection: close\r\n";
    resp += "Content-Type: " + ctype + "\r\n";
    resp += "Content-Length: " + QByteArray::number(payload.size()) + "\r\n\r\n";
    resp += payload;
    sock->write(resp);
    sock->flush();
}

QByteArray HttpConnection::urlDecode(const QByteArray& in) {
    QByteArray out; out.reserve(in.size());
    for (int i=0;i<in.size();++i) {
        if (in[i]=='+') out.append(' ');
        else if (in[i]=='%' && i+2<in.size()) {
            bool ok=false; int hex = QByteArray(in.mid(i+1,2)).toInt(&ok,16);
            if (ok){ out.append(char(hex)); i+=2; } else out.append('%');
        } else out.append(in[i]);
    }
    return out;
}


*/
