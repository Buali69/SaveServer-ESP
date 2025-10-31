# QtSecureServer

Ein schrittweise erweitertes Qt-Projekt mit mTLS-Server, JWT, Audit-Logger, StateMachine und WebSockets.  
Getestet unter **Windows 10/11 mit Qt 6.9.3** und CMake.

---

## 🚀 Features

- **HTTPS-Server mit mTLS-Unterstützung**
- **JWT-Login + Bearer Auth**
- **Audit-Logger** (Datenbank + GUI-Tabellen)
- **Qt StateMachine** (im MainWindow und für WS-Clients)
- **WebSocket-Server mit JWT-Authentifizierung**
- **Separate Tools** im Ordner `src/tools/` (z. B. `jwtgen`)

---

## 📦 Projektstruktur

```
src/
 ├── main.cpp
 ├── ui/                # MainWindow GUI
 │    ├── MainWindow.cpp
 │    └── MainWindow.h
 ├── http/              # Server-Komponenten
 │    ├── HttpsServer.cpp/.h
 │    ├── HttpConnection.cpp/.h
 │    ├── WsServer.cpp/.h
 │    ├── jwt.cpp/.h
 ├── db/                # SQLite Storage
 │    ├── Storage.cpp/.h
 └── tools/             # Hilfstools (werden automatisch gebaut)
      └── jwtgen.cpp
```

---

## 🔨 Bauen mit CMake

```bash
# Projekt konfigurieren
cmake -B build -S .

# Bauen
cmake --build build --config Release
```

Ergebnis:
- `QtSecureServer.exe` (GUI-Hauptprogramm)
- `jwtgen.exe` (Kommandozeilen-Tool zum Erzeugen von Tokens)

---

## 🖥️ Start des Servers

1. `QtSecureServer.exe` starten.  
2. Ports einstellen (HTTPS + WebSocket).  
3. Zertifikate auswählen (server.crt, server.key, ca.crt).  
4. **Start** klicken → Server läuft.  

---

## 🔑 JWT erzeugen mit jwtgen

Mitgeliefertes Tool `jwtgen` erzeugt gültige JWT-Tokens für deine Tests.

```powershell
# Syntax
jwtgen --user <Name> --secret <Secret>

# Beispiel
jwtgen --user alice --secret changeme-secret
```

Ausgabe:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Diesen Token kannst du z. B. in der mitgelieferten Testseite (`ws_test.html`) eintragen.

---

## 🌐 WebSocket Testseite

Öffne `ws_test.html` im Browser, trage die Server-URL (z. B. `ws://localhost:9443`) und das JWT ein und klicke **Verbinden**.

- Erste Nachricht: Token → Server antwortet `"auth ok"`
- Danach: freie Kommunikation (z. B. `"Echo: ..."`)

---

## 📋 TODO / Erweiterungen

- REST-Endpunkt `/login` für HTTP-basierte JWT-Ausgabe
- MQTT-Schnittstelle
- Erweiterte StateMachine für IoT-Workflows
