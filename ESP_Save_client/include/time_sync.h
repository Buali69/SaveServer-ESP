#include <NTPClient.h>
#include <WiFiUdp.h>
#include <sys/time.h>   // settimeofday
#include <time.h>

#ifndef NTP_POOL
#define NTP_POOL "pool.ntp.org"
#endif

#ifndef TZ_OFFSET_SEC
#define TZ_OFFSET_SEC 0
#endif
#ifndef TZ_DST_SEC
#define TZ_DST_SEC 0
#endif

// Einmalige Synchronisation; returns true wenn Unix-Zeit plausibel ist.
inline bool syncTimeOnce(uint32_t timeoutMs = 10000) {
  static WiFiUDP udp; // darf statisch sein
  //NTPClient ntp(udp, NTP_POOL, TZ_OFFSET_SEC + TZ_DST_SEC, 10 * 1000);
  NTPClient ntp(udp, NTP_POOL, /*offset*/ 0, 10 * 1000);  // <<< Offset 0 = UTC

  ntp.begin();

  uint32_t t0 = millis();
  bool ok = ntp.update();
  if (!ok) ntp.forceUpdate();

  while (!ok && (millis() - t0) < timeoutMs) {
    delay(200);
    ok = ntp.update();
  }
  if (!ok) {
    Serial.println("[TIME] NTP failed");
    return false;
  }

  // Systemzeit setzen (explizit Felder setzen!)
  struct timeval tv;
  tv.tv_sec  = ntp.getEpochTime(); // sekunden seit 1970
  tv.tv_usec = 0;
  settimeofday(&tv, nullptr);

  // Plausibilitätscheck
  time_t now = time(nullptr);
  if (now < 1700000000) {
    Serial.printf("[TIME] settimeofday failed? now=%ld\n", (long)now);
    return false;
  }
  Serial.printf("[TIME] synced ok: %ld\n", (long)now);
  return true;
}