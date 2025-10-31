#include "http_client.h"
#include "config.h"
#include "crypto_helpers.h"
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

static inline const std::vector<uint8_t>& deviceSecretBytes() {
  static std::vector<uint8_t> k = b64urlDecode(DEVICE_SECRET_B64URL);
  return k;
}
static String makeNonce() {
  char buf[37]; uint32_t r0=esp_random(), r1=esp_random(), r2=esp_random(), r3=esp_random();
  snprintf(buf,sizeof(buf), "%08x-%04x-%04x-%04x-%08x", r0,(uint16_t)r1,(uint16_t)(r1>>16),(uint16_t)r2,r3);
  return String(buf);
}
static void setupTls(WiFiClientSecure& net) {
  net.setTimeout(30000);
  if (TLS_CA_CERT_PEM && strlen(TLS_CA_CERT_PEM)>0) net.setCACert(TLS_CA_CERT_PEM);
  else net.setInsecure(); // nur testweise
}

HmacHeaders makeHmacHeaders(const String& method, const String& path, const String& bodyJson) {
  const auto& KEY = deviceSecretBytes();
  const String ts = String((uint32_t)time(nullptr));
  const String nonce = makeNonce();
  const String bodyB64 = b64urlOfSha256(bodyJson);
  const String canon = method + "\n" + path + "\n" + bodyB64 + "\n" + ts + "\n" + nonce;
  auto mac = hmacSha256(KEY.data(), KEY.size(), (const uint8_t*)canon.c_str(), canon.length());
  const String sign = b64urlEncode(mac.data(), mac.size());
  return { String(DEVICE_KEY_ID), ts, nonce, sign };
}

bool httpsPostJson(const String& path, const String& json, int* httpCodeOut, String* respOut) {
  WiFiClientSecure net; setupTls(net);
  if (!net.connect(SERVER_HOST, SERVER_HTTPS_PORT)) {
    if (httpCodeOut) *httpCodeOut = -1;
    Serial.println("[POST/raw] TLS connect failed");
    return false;
  }
  const auto H = makeHmacHeaders("POST", path, json);
  String req;
  req.reserve(256 + json.length());
  req  = "POST " + path + " HTTP/1.1\r\n";
  req += "Host: " + String(SERVER_HOST) + ":" + String(SERVER_HTTPS_PORT) + "\r\n";
  req += "Content-Type: application/json\r\n";
  req += "Content-Length: " + String(json.length()) + "\r\n";
  req += "Connection: close\r\n";
  req += "x-auth-keyid: " + H.keyId + "\r\n";
  req += "x-auth-ts: "    + H.ts    + "\r\n";
  req += "x-auth-nonce: " + H.nonce + "\r\n";
  req += "x-auth-sign: "  + H.sign  + "\r\n";
  req += "\r\n";
  req += json;

  size_t want = req.length();
  int wrote = net.write((const uint8_t*)req.c_str(), want);
  if (wrote != (int)want) {
    if (httpCodeOut) *httpCodeOut = -3;
    Serial.printf("[POST/raw] write short (%d/%u)\n", wrote, (unsigned)want);
    net.stop(); return false;
  }
  net.flush();

  uint32_t t0 = millis();
  while (!net.available() && (millis()-t0) < 30000) delay(10);
  if (!net.available()) {
    if (httpCodeOut) *httpCodeOut = -11;
    Serial.println("[POST/raw] no response (timeout)");
    net.stop(); return false;
  }

  String status = net.readStringUntil('\n'); status.trim();
  int code = 0;
  if (status.startsWith("HTTP/1.1 ")) {
    int sp = status.indexOf(' ', 9);
    code = status.substring(9, sp>0? sp : status.length()).toInt();
  }
  // Header skip bis Leerzeile
  while (net.connected()) { String h = net.readStringUntil('\n'); if (h=="\r" || h.length()==0) break; }
  // Body lesen
  String body;
  while (net.connected() || net.available()) { while (net.available()) body += (char)net.read(); delay(2); }
  net.stop();

  if (httpCodeOut) *httpCodeOut = code;
  if (respOut) *respOut = body;
  return (code > 0);
}

bool httpsPostJson_fragmented(const String& path, const String& json,
                              int* httpCodeOut, String* respOut)
{
  WiFiClientSecure net;
  setupTls(net);
  net.setTimeout(30000);

  if (!net.connect(SERVER_HOST, SERVER_HTTPS_PORT)) {
    if (httpCodeOut) *httpCodeOut = -1;
    return false;
  }

  const auto H = makeHmacHeaders("POST", path, json);

  // 1) Header ohne die Leerzeile + Body getrennt schicken
  String hdr;
  hdr.reserve(256 + json.length());
  hdr  = "POST " + path + " HTTP/1.1\r\n";
  hdr += "Host: " + String(SERVER_HOST) + ":" + String(SERVER_HTTPS_PORT) + "\r\n";
  hdr += "Content-Type: application/json\r\n";
  hdr += "Content-Length: " + String(json.length()) + "\r\n";
  hdr += "Connection: close\r\n";
  hdr += "x-auth-keyid: " + H.keyId + "\r\n";
  hdr += "x-auth-ts: "    + H.ts    + "\r\n";
  hdr += "x-auth-nonce: " + H.nonce + "\r\n";
  hdr += "x-auth-sign: "  + H.sign  + "\r\n";
  hdr += "\r\n"; // Header Ende

  // Fragment 1: Header
  net.write((const uint8_t*)hdr.c_str(), hdr.length());
  delay(5); // kleine Pause → sicheres Fragment

  // Fragment 2: Body
  net.write((const uint8_t*)json.c_str(), json.length());
  net.flush();

  uint32_t t0 = millis();
  while (!net.available() && (millis()-t0) < 30000) delay(10);
  if (!net.available()) {
    if (httpCodeOut) *httpCodeOut = -11;
    Serial.println("[POST/raw] no response (timeout)");
    net.stop(); return false;
  }

  String status = net.readStringUntil('\n'); status.trim();
  int code = 0;
  if (status.startsWith("HTTP/1.1 ")) {
    int sp = status.indexOf(' ', 9);
    code = status.substring(9, sp>0? sp : status.length()).toInt();
  }
  // Header skip bis Leerzeile
  while (net.connected()) { String h = net.readStringUntil('\n'); if (h=="\r" || h.length()==0) break; }
  // Body lesen
  String body;
  while (net.connected() || net.available()) { while (net.available()) body += (char)net.read(); delay(2); }
  net.stop();

  if (httpCodeOut) *httpCodeOut = code;
  if (respOut) *respOut = body;
  return (code > 0);

  // Antwort exakt wie in deiner Raw-Variante auslesen …
  // (Statuszeile, Header bis Leerzeile, Body)
  // ... (identischer Code wie in deiner funktionierenden httpsPostJson)
  // (aus Platzgründen hier nicht nochmal eingefügt)
  // Fülle httpCodeOut/respOut entsprechend.

  // → Du kannst hier 1:1 deinen Lese-Teil aus httpsPostJson übernehmen.
  // Wichtig ist nur, dass wir in zwei Writes gesendet haben.
  // ...
  return true; // wenn Code > 0 und ggf. 200
}

bool httpsGet(const String& path, int* httpCodeOut, String* respOut) {
  WiFiClientSecure net; setupTls(net);
  HTTPClient http;
  const String url = String("https://") + SERVER_HOST + ":" + SERVER_HTTPS_PORT + path;
  if (!http.begin(net, url)) return false;
  http.setTimeout(8000);
  int code = http.GET();
  String body = http.getString();
  http.end();
  if (httpCodeOut) *httpCodeOut = code;
  if (respOut) *respOut = body;
  return (code > 0);
}