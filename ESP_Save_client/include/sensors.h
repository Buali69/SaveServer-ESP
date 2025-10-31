#pragma once
#include <ArduinoJson.h>
#include "http_client.h"

inline bool sendSensorValues(float temp, float hum) {
   const uint32_t ts = (uint32_t)time(nullptr);
  char buf[128];
  snprintf(buf,sizeof(buf),
    "{\"ts\":%lu,\"values\":{\"temp\":\"%.1f\",\"hum\":\"%.1f\"}}",
    (unsigned long)ts, temp, hum);
  String body(buf);
  int code=0; String resp;
 // bool ok = httpsPostJson("/api/sensor/push", body, &code, &resp);            //kompletter Body
  bool ok = httpsPostJson_fragmented("/api/sensor/push", body, &code, &resp);   //Fragmente Body
  Serial.printf("sensor.push http=%d ok=%d\n", code, (ok && code==200));
  return ok && (code==200);
}

/*
// Beispiel: zwei Werte senden
// include/sensors.h
inline bool sendSensorValues(float temp, float hum) {
  DynamicJsonDocument doc(256);
  doc["ts"] = (uint32_t)time(nullptr);
  JsonObject vals = doc.createNestedObject("values");
  vals["temp"] = String(temp, 1);
  vals["hum"]  = String(hum, 1);

  String body; 
  serializeJson(doc, body);

  // ---- DEBUG: HMAC/Felder zeigen (muss GENAU dem Request entsprechen) ----
  const String method = "POST";
  const String path   = "/api/sensor/push";
  const String bodyB64 = b64urlOfSha256(body);
  const auto H = makeHmacHeaders(method, path, body);

  Serial.println("=== HMAC DEBUG (ESP) ===");
  Serial.printf("keyId=%s\n", H.keyId.c_str());
  Serial.printf("ts=%s nonce=%s\n", H.ts.c_str(), H.nonce.c_str());
  Serial.printf("body=%s\n", body.c_str());
  Serial.printf("bodyB64=%s\n", bodyB64.c_str());
  Serial.printf("canon=%s\\n%s\\n%s\\n%s\\n%s\n",
                method.c_str(), path.c_str(), bodyB64.c_str(),
                H.ts.c_str(), H.nonce.c_str());
  Serial.printf("sign=%s\n", H.sign.c_str());

  int code=0; String resp;
  bool ok = httpsPostJson(path, body, &code, &resp);
  Serial.printf("sensor.push http=%d resp=%s\n", code, resp.c_str());
  return ok && (code==200);
}   */
/*
inline bool sendSensorValues(float temp, float hum) {
  DynamicJsonDocument doc(256);
  doc["ts"] = (uint32_t)time(nullptr);
  JsonObject vals = doc.createNestedObject("values");
  vals["temp"] = String(temp, 1);
  vals["hum"]  = String(hum, 1);

  String body; serializeJson(doc, body);
  int code=0; String resp;
  bool ok = httpsPostJson("/api/sensor/push", body, &code, &resp);
  // optional Logging:
  Serial.printf("sensor.push http=%d body=%s\n", code, resp.c_str());
  return ok && (code==200);
}
*/