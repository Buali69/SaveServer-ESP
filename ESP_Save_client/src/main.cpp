// src/main.cpp
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>

// mbedTLS (für Base64, SHA256, HMAC)
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>

#include "config.h"   // -> enthält SERVER_HOST, SERVER_HTTPS_PORT, DEVICE_KEY_ID,
//                      DEVICE_SECRET_B64URL, TLS_CA_CERT_PEM, NTP_POOL,
//                      TZ_OFFSET_SEC, TZ_DST_SEC

#include "time_sync.h"
#include "sensors.h"
// #include "ota_client.h" // später wieder aktivieren

static const char* WIFI_SSID = "RSN_WLAN";
static const char* WIFI_PASS  = "JENNITIMOSILVIRUDI";
// Falls du statische IP verwenden willst, definiere diese in config.h ODER hier:
IPAddress local_IP(192,168,1,99);
IPAddress gateway (192,168,1,5);
IPAddress subnet  (255,255,255,0);
IPAddress dns1    (192,168,1,5);
IPAddress dns2    (8,8,8,8);


bool timeSynced = false;

void setup() {
  Serial.begin(115200);
  delay(100);

  // Statische IP (aus config.h)
  if (!WiFi.config(local_IP, gateway, subnet, dns1, dns2)) {
    Serial.println("[WiFi] config failed");
  }

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.printf("[WiFi] Verbinde zu '%s' ...\n", WIFI_SSID);
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) {
    delay(250); Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("[WiFi] OK, IP=%s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("[WiFi] Verbindung fehlgeschlagen");
  }

  timeSynced = syncTimeOnce(); // NTP → damit HMAC ts stimmt
  Serial.printf("[TIME] epoch=%lu synced=%d\n", (unsigned long)time(nullptr), (int)timeSynced);
}

uint32_t lastSensor=0;
// uint32_t lastPoll=0;

void loop() {
  static wl_status_t last = WL_IDLE_STATUS;
  wl_status_t st = WiFi.status();
  if (st == WL_CONNECTED && last != WL_CONNECTED && !timeSynced) {
    timeSynced = syncTimeOnce();
    Serial.printf("[TIME] epoch=%lu synced=%d\n", (unsigned long)time(nullptr), (int)timeSynced);
  }
  last = st;

  if (!timeSynced || st != WL_CONNECTED) { delay(100); return; }

  uint32_t tick = millis();

  if (tick - lastSensor > 5000) {
    lastSensor = tick;
    float temp = 20.0f + (float)(esp_random() % 100) / 10.0f;
    float hum  = 40.0f + (float)(esp_random() % 300) / 10.0f;

    bool ok = sendSensorValues(temp, hum);
    Serial.printf("sensor push: %s\n", ok?"ok":"fail");
  }

  // OTA später wieder:
  // if (tick - lastPoll > 15000) { ... }
    // alle 15s OTA poll
/*  if (tick - lastPoll > 15000) {
    lastPoll = tick;
    OtaJob job;
    if (pollOta(job)) {
      Serial.printf("OTA job %llu file=%llu %s size=%lld\n",
        job.job_id, job.file_id, job.name.c_str(), (long long)job.size);
      runOtaJob(job);
    } 
  } */

//  delay(50);


  delay(50);
}