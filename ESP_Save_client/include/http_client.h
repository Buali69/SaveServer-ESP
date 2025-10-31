#pragma once
#include <Arduino.h>
#include <functional>
#include <WiFiClient.h>

struct HmacHeaders { String keyId, ts, nonce, sign; };

HmacHeaders makeHmacHeaders(const String& method, const String& path, const String& bodyJson);

// „Raw“-POST, wie in deinem File (eine Write-Operation, stabil)
bool httpsPostJson(const String& path, const String& json,
                   int* httpCodeOut=nullptr, String* respOut=nullptr);

// Optional: GET via HTTPClient (für Smoke-Test)
bool httpsGet(const String& path, int* httpCodeOut=nullptr, String* respOut=nullptr);
bool httpsPostJson_fragmented(const String& path, const String& json,
                              int* httpCodeOut=nullptr, String* respOut=nullptr);