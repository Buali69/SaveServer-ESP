#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>
#include <Update.h>

#include "http_client.h"       // httpsGet, httpsGetStream, httpsPostJson
#include "crypto_helpers.h"    // Sha256Stream, bytesEqualCT (optional)

// ----------- Status an Server melden (/api/ota/progress) -----------
inline void postProgress(uint64_t jobId,
                         const String& state,
                         int progress,
                         const String& errorMsg = "") {
  DynamicJsonDocument doc(256);
  doc["job_id"]   = (uint64_t)jobId;
  doc["state"]    = state;              // downloading | installing | done | failed
  doc["progress"] = progress;           // 0..100
  if (errorMsg.length()) doc["error"] = errorMsg;

  String body; serializeJson(doc, body);
  int code = 0; String resp;
  (void)httpsPostJson("/api/ota/progress", body, &code, &resp);
}

// ----------- OTA-Job-Struktur vom Server -----------
struct OtaJob {
  uint64_t job_id = 0;
  uint64_t file_id = 0;
  String   name;
  int64_t  size = 0;
  String   sha256hex;    // lowercase/uppercase egal – wir vergleichen case-insensitive
  String   url;          // z. B. "/api/ota/file/123"
};

// ----------- Job vom Server abholen (/api/ota/poll) -----------
inline bool pollOta(OtaJob& out) {
  int code = 0; String resp;
  if (!httpsGet("/api/ota/poll", &code, &resp)) return false;
  if (code != 200) return false;

  DynamicJsonDocument doc(512);
  if (deserializeJson(doc, resp)) return false;

  if (doc["job"].isNull()) return false;

  JsonObject j = doc["job"];
  out.job_id    = j["job_id"]  | 0ULL;
  out.file_id   = j["file_id"] | 0ULL;
  out.name      = String((const char*)j["name"]);
  out.size      = j["size"]    | 0LL;
  out.sha256hex = String((const char*)j["sha256"]);
  out.url       = String((const char*)j["url"]);
  return (out.job_id != 0);
}

// ----------- SHA256-Digest (32 Byte) vs. Hex-String vergleichen -----------
inline bool hexEquals(const std::array<uint8_t,32>& dig, const String& hexStr) {
  // calc → lowercase hex
  char buf[65];
  for (int i = 0; i < 32; ++i) sprintf(buf + i*2, "%02x", dig[i]);
  buf[64] = 0;

  // case-insensitive Vergleich
  String calc(buf);
  String ref = hexStr;
  calc.toLowerCase();
  ref.toLowerCase();
  return calc == ref;
}

/*
// ----------- OTA ausführen: Download → Verify → Flash → Restart -----------
inline bool runOtaJob(const OtaJob& job) {
  postProgress(job.job_id, "downloading", 0);

  // Streaming SHA-256 (md-API, versionsstabil)
  Sha256Stream sha;
  if (!sha.begin()) {
    postProgress(job.job_id, "failed", 0, "sha256 init");
    return false;
  }

  size_t received = 0;
  bool success = false;

  // Streaming-GET; http_client.h ruft unseren Lambda mit Stream/Content-Length auf
  bool httpOk = httpsGetStream(job.url,
    [&](WiFiClient& stream, int contentLen)
    {
      // Begin Update (Content-Length kann -1 sein → UPDATE_SIZE_UNKNOWN)
      if (!Update.begin(contentLen > 0 ? (size_t)contentLen : (size_t)UPDATE_SIZE_UNKNOWN)) {
        postProgress(job.job_id, "failed", 0, "Update.begin");
        return;
      }

      postProgress(job.job_id, "installing", 0);

      const size_t BUF = 4096;
      std::unique_ptr<uint8_t[]> buf(new uint8_t[BUF]);
      uint32_t lastPct = 0;

      while (true) {
        int n = stream.read(buf.get(), BUF);
        if (n < 0) { Update.abort(); postProgress(job.job_id, "failed", lastPct, "read"); return; }
        if (n == 0) break; // Stream fertig

        // Hash inkrementell
        if (!sha.update(buf.get(), (size_t)n)) {
          Update.abort(); postProgress(job.job_id, "failed", lastPct, "sha update"); return;
        }

        // Flashen
        if (Update.write(buf.get(), (size_t)n) != (size_t)n) {
          Update.abort(); postProgress(job.job_id, "failed", lastPct, "write"); return;
        }

        received += (size_t)n;

        // Fortschritt (nur wenn Länge bekannt)
        if (contentLen > 0) {
          uint32_t pct = (uint32_t)((received * 100ULL) / (uint64_t)contentLen);
          if (pct != lastPct && pct <= 100) {
            lastPct = pct;
            postProgress(job.job_id, "installing", (int)pct);
          }
        }
        yield();
      }

      // Flash abschließen (true = allow reboot)
      if (!Update.end(true)) {
        postProgress(job.job_id, "failed", 100, "Update.end");
        return;
      }

      // SHA-256 finalisieren & vergleichen
      std::array<uint8_t,32> dig{};
      if (!sha.finish(dig.data())) {
        postProgress(job.job_id, "failed", 100, "sha finish");
        return;
      }

      if (!hexEquals(dig, job.sha256hex)) {
        postProgress(job.job_id, "failed", 100, "sha256 mismatch");
        return;
      }

      // Erfolg
      postProgress(job.job_id, "done", 100);
      success = true;

      // kleiner Delay, dann Neustart (Update.end(true) erlaubt reboot)
      delay(300);
      ESP.restart();
    },
  //   httpCodeOut =  nullptr
  );

  // httpsGetStream lieferte gar nicht? (TLS/HTTP Problem)
  if (!httpOk) {
    postProgress(job.job_id, "failed", 0, "http");
    return false;
  }

  return success;
}

*/