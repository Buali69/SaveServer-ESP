# Server2mTLSTest (Qt 6) — modular

**Was es ist:** Qt Widgets UI + HTTPS-Server (TLS/mTLS umschaltbar) + einfache Weboberfläche + SQLite-Speicher.
Getrennte Module: UI, HTTP/HTTPS, DB, Web.

## Build (Qt Creator 15 / Qt 6.8.x, MinGW)
1. `File → Open File or Project…` → `CMakeLists.txt` wählen.
2. Kit wählen (Desktop Qt 6.8.x MinGW 64-bit).
3. Build.
4. Start.

## Start in der App
- DocRoot: Ordner `web` (darin liegt `index.html`).
- server.crt, server.key, ca.crt auswählen.
- Modus: TLS oder mTLS.
- Port (z. B. 8443) → Start.

## Test (von anderem Rechner)
- Browser: `https://<SERVER_IP>:8443/` → Zahl absenden → landet in SQLite (UI zeigt Tabelle).
- mTLS: Client braucht `client.p12` im Benutzerstore (Windows) oder im Firefox-Zertifikatsmanager.

## DLLs deployen (Windows)
Für Start außerhalb des Qt Creators:
```
"C:\Qt\6.8.1\mingw_64\bin\windeployqt.exe" --release --compiler-runtime "<Pfad>\Server2mTLSTest.exe"
copy "C:\Program Files\OpenSSL-Win64\bin\libcrypto-3-x64.dll" "<Pfad>\"
copy "C:\Program Files\OpenSSL-Win64\bin\libssl-3-x64.dll"    "<Pfad>\"
```
(oder Debug-Variante ohne `--release`)

## mTLS-Hinweise
- Server: lädt `server.crt` + `server.key`, und bei mTLS zusätzlich **CA** unter `ca.crt` (die Client-Zerts signiert).
- Client: benötigt ein Zertifikat **mit privatem Schlüssel** (z. B. `client.p12`) im Benutzerstore.
- Test ohne Browser:
```
"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" s_client -connect <SERVER_IP>:8443 -servername <SERVER_IP> -cert client.crt -key client.key -CAfile ca.crt -verify 1
```
