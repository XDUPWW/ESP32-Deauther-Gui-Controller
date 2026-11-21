// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "hal_wifi/hal_wifi.h"
#include "services_private.h"
#include "wbus/wbus.h"
#include "wifi_frame/frames.h"
#include "wifi_frame/ie_parse.h"
#include "wtarget/wtarget.h"

static const char *TAG = "scan";

#define SCAN_OWNER "scan"
#define SCAN_CHANNELS 13
#define SCAN_DWELL_DEFAULT 250
#define STA_MAX_PER_AP 8

static bool s_listening;
static uint8_t s_dwell_ms = SCAN_DWELL_DEFAULT;
static uint8_t s_channel = 1;
static uint32_t s_last_hop_ms;
static uint32_t s_ap_new;
static uint32_t s_sta_new;
static uint32_t s_frames;
static uint32_t s_beacons;
static uint32_t s_probe_resp;

static const char *auth_name(uint8_t mode) {
    switch (mode) {
        case 0:
            return "open";
        case 1:
            return "wep";
        case 2:
        case 3:
        case 4:
        case 6:
            return "wpa2";
        case 5:
            return "wpa";
        case 7:
        case 8:
        case 9:
        case 10:
            return "wpa3";
        default:
            return "?";
    }
}

static void format_mac(char *out, size_t cap, const uint8_t mac[6]) {
    snprintf(out, cap, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4],
             mac[5]);
}

static void record_ap(const wf_bss_t *bss, int8_t rssi, uint8_t channel) {
    wt_entry_t entry = {
        .kind = WT_KIND_AP,
        .rssi = rssi,
        .channel = (channel != 0) ? channel : bss->channel,
        .ssid_len = bss->ssid_len,
        .sae = bss->sae,
        .mfpr = bss->mfpr,
    };
    memcpy(entry.bssid, bss->bssid, 6);
    memcpy(entry.mac, bss->bssid, 6);
    memcpy(entry.ssid, bss->ssid, sizeof(entry.ssid));
    entry.ssid[sizeof(entry.ssid) - 1] = '\0';

    const uint32_t before = wt_count();
    if (wt_add(&entry) == ESP_OK && wt_count() > before) {
        s_ap_new++;
        char mac[18];
        format_mac(mac, sizeof(mac), entry.bssid);
        wb_emit("scan", "ap", "idx=%u bssid=%s ch=%u rssi=%d ssid=\"%s\" sae=%d pmf=%d",
                (unsigned)wt_count(), mac, (unsigned)entry.channel, (int)rssi, entry.ssid,
                entry.sae ? 1 : 0, entry.mfpr ? 1 : 0);
    }
}

static void record_sta(const uint8_t mac[6], const uint8_t bssid[6], int8_t rssi,
                       uint8_t channel) {
    if (mac[0] & 0x01) {
        return;
    }
    wt_entry_t entry = {
        .kind = WT_KIND_STA,
        .rssi = rssi,
        .channel = channel,
    };
    memcpy(entry.mac, mac, 6);
    memcpy(entry.bssid, bssid, 6);

    const uint32_t before = wt_count();
    if (wt_add(&entry) == ESP_OK && wt_count() > before) {
        s_sta_new++;
        char sta[18];
        char ap[18];
        format_mac(sta, sizeof(sta), mac);
        format_mac(ap, sizeof(ap), bssid);
        wb_emit("scan", "sta", "idx=%u mac=%s bssid=%s ch=%u rssi=%d", (unsigned)wt_count(), sta,
                ap, (unsigned)channel, (int)rssi);
    }
}

static void on_rx(const uint8_t *frame, uint16_t len, const hal_wifi_rx_meta_t *meta, void *ctx) {
    (void)ctx;
    if (!s_listening || meta == NULL || len < WF_MGMT_HDR_LEN) {
        return;
    }
    const int8_t rssi = meta->rssi;
    const uint8_t channel = meta->channel;
    s_frames++;

    const uint8_t fc = frame[0];
    const uint8_t type = (uint8_t)((fc >> 2) & 0x03);
    const uint8_t subtype = (uint8_t)(fc & 0xF0);

    if (type == 0 && (subtype == WF_ST_BEACON || subtype == WF_ST_PROBE_RESP)) {
        if (subtype == WF_ST_BEACON) {
            s_beacons++;
        } else {
            s_probe_resp++;
        }
        wf_bss_t bss;
        if (wf_parse_beacon(frame, len, &bss)) {
            record_ap(&bss, rssi, channel);
        }
        return;
    }

    // Any management or uplink data frame not sent by the AP itself carries a
    // station address in addr2. A probe request has no AP yet, so keep the BSSID
    // field empty instead of storing the broadcast address.
    const uint8_t *addr2 = frame + 10;
    const uint8_t *addr3 = frame + 16;
    const bool uplink = (type == 0 && subtype != WF_ST_BEACON) ||
                        (type == 2 && (fc & 0x01) != 0);
    if (uplink && memcmp(addr2, addr3, 6) != 0) {
        static const uint8_t kZero[6] = {0};
        record_sta(addr2, (addr3[0] & 0x01) ? kZero : addr3, rssi, channel);
    }
}

void services_scan_attach_rx(void) {
    hal_wifi_rx_subscribe(on_rx, NULL);
}

static esp_err_t stop_listening(void) {
    if (!s_listening) {
        return ESP_OK;
    }
    s_listening = false;
    hal_wifi_sniffer_enable(false);
    hal_wifi_channel_release(SCAN_OWNER);
    return ESP_OK;
}

static esp_err_t start_listening(uint8_t dwell_ms) {
    if (s_listening) {
        s_dwell_ms = dwell_ms;
        return ESP_OK;
    }
    const esp_err_t err = hal_wifi_channel_acquire(SCAN_OWNER, HAL_CH_ROAMING, 0, 0);
    if (err != ESP_OK) {
        return err;
    }
    s_dwell_ms = dwell_ms;
    s_channel = 1;
    s_last_hop_ms = 0;
    s_ap_new = 0;
    s_sta_new = 0;
    s_frames = 0;
    hal_wifi_channel_select(SCAN_OWNER, s_channel);
    if (hal_wifi_sniffer_enable(true) != ESP_OK) {
        hal_wifi_channel_release(SCAN_OWNER);
        return ESP_FAIL;
    }
    s_listening = true;
    return ESP_OK;
}

void services_scan_tick(uint32_t now_ms) {
    if (!s_listening) {
        return;
    }
    if (s_last_hop_ms != 0 && (now_ms - s_last_hop_ms) < s_dwell_ms) {
        return;
    }
    s_last_hop_ms = now_ms;
    s_channel = (uint8_t)((s_channel % SCAN_CHANNELS) + 1);
    hal_wifi_channel_select(SCAN_OWNER, s_channel);
}

static esp_err_t scan_ap(wb_args_t *args, wb_reply_t *reply) {
    const uint8_t dwell = (uint8_t)wb_args_u32(args, "dwell");
    const bool was_listening = s_listening;

    // esp_wifi_scan_start() does not run while promiscuous mode is on.
    if (was_listening) {
        hal_wifi_sniffer_enable(false);
    }
    const esp_err_t err = hal_wifi_scan_blocking(dwell);
    if (was_listening) {
        hal_wifi_sniffer_enable(true);
    }
    if (err != ESP_OK) {
        wb_reply_fail(reply, "scan failed (%s)", esp_err_to_name(err));
        return err;
    }

    const uint32_t found = hal_wifi_scan_count();
    for (uint32_t i = 0; i < found; i++) {
        const hal_scan_ap_t *ap = hal_wifi_scan_at(i);
        wf_bss_t bss;
        memset(&bss, 0, sizeof(bss));
        memcpy(bss.bssid, ap->bssid, 6);
        memcpy(bss.ssid, ap->ssid, sizeof(bss.ssid));
        bss.ssid_len = (uint8_t)strlen(bss.ssid);
        bss.channel = ap->channel;
        record_ap(&bss, ap->rssi, ap->channel);
        wb_reply_line(reply, "ch=%-3u rssi=%-4d auth=%-5s bssid=%02x:%02x:%02x:%02x:%02x:%02x ssid=\"%s\"",
                      (unsigned)ap->channel, (int)ap->rssi, auth_name(ap->authmode), ap->bssid[0],
                      ap->bssid[1], ap->bssid[2], ap->bssid[3], ap->bssid[4], ap->bssid[5],
                      ap->ssid);
    }
    wb_reply_line(reply, "scan ap count=%u total=%u", (unsigned)found, (unsigned)wt_count());
    ESP_LOGI(TAG, "active scan %u ap", (unsigned)found);
    return ESP_OK;
}

static esp_err_t scan_listen(wb_args_t *args, wb_reply_t *reply) {
    const uint8_t dwell = (uint8_t)wb_args_u32(args, "dwell");
    const esp_err_t err = start_listening(dwell);
    if (err == ESP_ERR_INVALID_STATE) {
        wb_reply_fail(reply, "channel busy with %s", hal_wifi_channel_owner());
        return err;
    }
    if (err != ESP_OK) {
        wb_reply_fail(reply, "listen start failed (%s)", esp_err_to_name(err));
        return err;
    }
    wb_reply_line(reply, "listening dwell=%ums channels=1..%u", (unsigned)dwell,
                  (unsigned)SCAN_CHANNELS);
    return ESP_OK;
}

static esp_err_t scan_stop(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    stop_listening();
    wb_reply_line(reply, "stopped ap_new=%u sta_new=%u frames=%u", (unsigned)s_ap_new,
                  (unsigned)s_sta_new, (unsigned)s_frames);
    return ESP_OK;
}

static esp_err_t scan_status(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    hal_wifi_stats_t stats;
    hal_wifi_stats(&stats);
    wb_reply_line(reply, "listening=%d dwell=%ums channel=%u owner=%s", s_listening ? 1 : 0,
                  (unsigned)s_dwell_ms, (unsigned)hal_wifi_channel(), hal_wifi_channel_owner());
    wb_reply_line(reply, "ap_new=%u sta_new=%u frames=%u beacon=%u probe_resp=%u", (unsigned)s_ap_new,
                  (unsigned)s_sta_new, (unsigned)s_frames, (unsigned)s_beacons,
                  (unsigned)s_probe_resp);
    wb_reply_line(reply, "rx=%u dropped=%u", (unsigned)stats.rx_frames,
                  (unsigned)stats.rx_dropped);
    return ESP_OK;
}

static esp_err_t scan_list(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t count = wt_count();
    for (uint32_t i = 0; i < count; i++) {
        const wt_entry_t *entry = wt_at(i);
        if (entry->kind == WT_KIND_AP) {
            wb_reply_line(reply, "%u ap  %02x:%02x:%02x:%02x:%02x:%02x ch=%-3u rssi=%-4d sae=%d pmf=%d \"%s\"",
                          (unsigned)(i + 1), entry->bssid[0], entry->bssid[1], entry->bssid[2],
                          entry->bssid[3], entry->bssid[4], entry->bssid[5],
                          (unsigned)entry->channel, (int)entry->rssi, entry->sae ? 1 : 0,
                          entry->mfpr ? 1 : 0, entry->ssid);
        } else {
            wb_reply_line(reply, "%u sta %02x:%02x:%02x:%02x:%02x:%02x via=%02x:%02x:%02x:%02x:%02x:%02x rssi=%d",
                          (unsigned)(i + 1), entry->mac[0], entry->mac[1], entry->mac[2],
                          entry->mac[3], entry->mac[4], entry->mac[5], entry->bssid[0],
                          entry->bssid[1], entry->bssid[2], entry->bssid[3], entry->bssid[4],
                          entry->bssid[5], (int)entry->rssi);
        }
    }
    wb_reply_line(reply, "total=%u", (unsigned)count);
    return ESP_OK;
}

static esp_err_t scan_clear(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    wt_clear();
    s_ap_new = 0;
    s_sta_new = 0;
    wb_reply_line(reply, "cleared");
    return ESP_OK;
}

static const wb_policy_t kApPolicy[] = {
    {.name = "dwell", .type = WB_T_U32, .required = false, .min = 1, .max = 500, .def = 80},
};

static const wb_policy_t kListenPolicy[] = {
    {.name = "dwell", .type = WB_T_U32, .required = false, .min = 20, .max = 2000, .def = 250},
};

static const wb_method_t kScanMethods[] = {
    {"ap", scan_ap, "[dwell=1..500]", kApPolicy, 1},
    {"listen", scan_listen, "[dwell=20..2000]", kListenPolicy, 1},
    {"stop", scan_stop, "", NULL, 0},
    {"status", scan_status, "", NULL, 0},
    {"list", scan_list, "", NULL, 0},
    {"clear", scan_clear, "", NULL, 0},
};

static const wb_object_t kScanObject = {
    .name = "scan",
    .methods = kScanMethods,
    .n_methods = sizeof(kScanMethods) / sizeof(kScanMethods[0]),
};

const wb_object_t *services_scan_object(void) {
    return &kScanObject;
}
