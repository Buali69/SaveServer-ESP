#pragma once
#include <Arduino.h>
#include <vector>
#include <array>

// mbedTLS (nur die "md"-API + base64, ist versionsstabil)
#include <mbedtls/base64.h>
#include <mbedtls/md.h>

// ---------- Base64url ----------

// base64url encode (ohne '=')
inline String b64urlEncode(const uint8_t* data, size_t len) {
  size_t outLen = 0;
  (void)mbedtls_base64_encode(nullptr, 0, &outLen, data, len);
  std::vector<unsigned char> out(outLen + 4, 0);
  size_t written = 0;
  if (mbedtls_base64_encode(out.data(), out.size(), &written, data, len) != 0) return String();
  String s((const char*)out.data(), written);
  s.replace('+','-'); s.replace('/','_');
  while (s.endsWith("=")) s.remove(s.length()-1);
  return s;
}

// base64url decode
inline std::vector<uint8_t> b64urlDecode(const String& inB64url) {
  String s = inB64url;
  s.replace('-', '+'); s.replace('_', '/');
  while ((s.length() % 4) != 0) s += '=';
  size_t outLen = 0;
  (void)mbedtls_base64_decode(nullptr, 0, &outLen,
                              (const unsigned char*)s.c_str(), s.length());
  std::vector<uint8_t> out(outLen + 4);
  size_t written = 0;
  int rc = mbedtls_base64_decode(out.data(), out.size(), &written,
                                 (const unsigned char*)s.c_str(), s.length());
  if (rc != 0) { out.clear(); return out; }
  out.resize(written);
  return out;
}

// ---------- SHA-256 (Streaming über mbedTLS md-API) ----------

struct Sha256Stream {
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t* info = nullptr;
  Sha256Stream() { mbedtls_md_init(&ctx); }
  bool begin() {
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return false;
    if (mbedtls_md_setup(&ctx, info, 0) != 0) return false;
    return mbedtls_md_starts(&ctx) == 0;
  }
  bool update(const uint8_t* p, size_t n) { return mbedtls_md_update(&ctx, p, n) == 0; }
  bool finish(uint8_t out[32]) { return mbedtls_md_finish(&ctx, out) == 0; }
  ~Sha256Stream() { mbedtls_md_free(&ctx); }
};

// sha256(all-at-once)
inline std::array<uint8_t,32> sha256(const uint8_t* d, size_t n) {
  std::array<uint8_t,32> out{};
  Sha256Stream s; if (!s.begin()) return out;
  (void)s.update(d, n);
  (void)s.finish(out.data());
  return out;
}
inline std::array<uint8_t,32> sha256(const std::vector<uint8_t>& v) { return sha256(v.data(), v.size()); }
inline std::array<uint8_t,32> sha256(const String& s) { return sha256((const uint8_t*)s.c_str(), s.length()); }

// b64url(sha256(body))
inline String b64urlOfSha256(const String& body) {
  auto dig = sha256((const uint8_t*)body.c_str(), body.length());
  return b64urlEncode(dig.data(), dig.size());
}

// ---------- HMAC-SHA256 (md-API) ----------
inline std::array<uint8_t,32> hmacSha256(const uint8_t* key, size_t keyLen,
                                         const uint8_t* msg, size_t msgLen) {
  std::array<uint8_t,32> mac{};
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, md, 1) != 0) { mbedtls_md_free(&ctx); return mac; }
  mbedtls_md_hmac_starts(&ctx, key, keyLen);
  mbedtls_md_hmac_update(&ctx, msg, msgLen);
  mbedtls_md_hmac_finish(&ctx, mac.data());
  mbedtls_md_free(&ctx);
  return mac;
}

// Timing-sicher
inline bool bytesEqualCT(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t diff = 0; for (size_t i=0;i<n;i++) diff |= (a[i]^b[i]); return diff == 0;
}