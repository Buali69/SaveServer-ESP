#pragma once
#include <Arduino.h>

// --- Server ---
static const char* SERVER_HOST = "192.168.1.68";
static const uint16_t SERVER_HTTPS_PORT = 8443;

// --- Device Identity ---
static const char* DEVICE_KEY_ID = "d2397bbf86194967aa9af424326cce19";
// Device secret = Base64URL-String (GENAU so, wie aus deinem Server ausgegeben),
// auf dem ESP speichern (Provisioning / Flash / Preferences)
static const char* DEVICE_SECRET_B64URL = "w_w6dW9iaFC1p9n3ONMhOwHqqARLVu_lm4HnVpffNrI";

// --- TLS ---
/* Option A: CA-Pinning (empfohlen)
   Füge dein CA- oder Server-Zert in PEM ein (-----BEGIN CERTIFICATE----- ...).
*/
static const char* TLS_CA_CERT_PEM = R"PEM(
-----BEGIN CERTIFICATE-----
MIIFozCCA4ugAwIBAgIUFKwLLd3FtFrRnNXaxTqWNCtiRcYwDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVy
bGluMRAwDgYDVQQKDAdUZXN0IENBMQwwCgYDVQQLDANEZXYxEDAOBgNVBAMMB1Rl
c3QtQ0EwHhcNMjUwOTI3MTY1ODQxWhcNMzUwOTI1MTY1ODQxWjBhMQswCQYDVQQG
EwJERTEPMA0GA1UECAwGQmVybGluMQ8wDQYDVQQHDAZCZXJsaW4xEDAOBgNVBAoM
B1Rlc3QgQ0ExDDAKBgNVBAsMA0RldjEQMA4GA1UEAwwHVGVzdC1DQTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJ0XStCh8MfkO/sx2tobxWOFJgvk8P/g
VfT8r39nI96RkPEeE3PPb0kPqkiC2VKIvOxUTucIII7ML9suDSWFB4oIaSxQktkK
6HbZ25ENl+hAiOjktXad9OHmEtfPDo4xPT95S4E5gSedxgNqq9ZrDg63kKFE0U1s
xA70Qw0zRZKqwWCieoq+0ZOtKQ8ZR7t7xOJEpicEXZNuo7tq/wwMU8Qa2LO8yhRt
k0+Bbg1SGrHxSronYo9uD5EskT+0RbwfuPEBVQNHwkEazOPW3cebZXw8/sdUXroh
AHOfIdoZoqSlxM76S/UpqtbjQTSps+yxP68fIiiLr2r8X16Pw1RFrUpUUF6OR7xT
l3/1hoAVh50WlRSVc3GtXrGTqfHw3DoT9C5FqtXDcZJ32QEbmwyKtqNby1/AYfJA
wHZaDt/MrQ5KmHSlshvaaJxWvczTLCvsxGb+0NoXFCxmM4VPMrS6owYys8Coot5Q
G9/FhSDxGqTHx4z0eCNfvWRHwoxFGlgQETtO7qxBlEjIza1Cr67Oh/Ay7hJI3pRK
pnIEIRsrhYz2F3nOVHkmOGK5uJtWxyKHlGV/f6VawT2onkfqPEIFGdNez9g2hA5p
TGyz4G1+CJ0zf+BdeOPi0zHjTGqUgCGo+R67/2mQ92xqaruIFM2HpeN2uk+Re2bw
h/Nez2TPOmZRAgMBAAGjUzBRMB0GA1UdDgQWBBTUh9k9vdTtpqPo7mifUXs3LKjJ
tTAfBgNVHSMEGDAWgBTUh9k9vdTtpqPo7mifUXs3LKjJtTAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCJDC6YcgmSMAZlgE5SHZwoB813HfN+y0Am
AcsNZz7WG1I7lr7hOYtVskAGyC9iaUql6+vB8VaKNmXDo4/03xwOY7QmeUiFS6S5
JFAU8W2UsNxrNAqAMLHI09KofTo23z8uiiWeMeiO5x7ROjQpIjrzubqlh1z9uAyk
E4DyfHYdHsftNCoCY9yZEiPUrf3NLIHMqblRxad/C/mg+gbMtv2O5TCP8sYnRLUN
JxmRB3v1geua7JM55jtrT4qJuv0mwbCH47GfkqY7Vobf7B35EzQT2hIV68C6NLD6
5Dr8FhvyLXO12sDrQJePBOHqGUxm09jI+/bkuwRmHLzFr9WXFRSk8lOFxtfYZ4Xg
HbPylVme2ceT08d2yHF+LqWA6wnR0glchFeqiugmSNIBGluVGP8NM3QtEjDCMNV3
/CNvfrWZ81pW6QxLmko/6ptsMh532Uzi/CwB7Xu4d5gDcOGyK7yA2ID8YrQDqxy3
cAcnkRfKNSbG6AE5ZEB2E94jfSIs0dmTjD1kCtkreBNHEa0juPO2HvkujRE+vRui
BWUqu7dRBOnaZZNJj+1jIsy9adlSJAmkDRpb28W3kejn3YeErk8PCsIG0O7/c0CZ
GjQX6RgsGsciNW3Er9JH0cj8ObRa9EfxjUSiea1Y/0/Hk0sRLjFMf3omERtzZNeZ
VB3jSf+7fA==
-----END CERTIFICATE-----
)PEM";

// --- OTA ---
static const uint32_t OTA_HTTP_TIMEOUT_MS = 30000;

// --- NTP ---
static const char* NTP_POOL = "pool.ntp.org";
static const long  TZ_OFFSET_SEC = 0;     // UTC
static const int   TZ_DST_SEC = 0;        // no DST
