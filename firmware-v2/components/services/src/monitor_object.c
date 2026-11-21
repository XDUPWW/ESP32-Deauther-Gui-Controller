// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include <stdio.h>
#include <string.h>

#include "esp_timer.h"
#include "hal_wifi/hal_wifi.h"
#include "services_private.h"
#include "wbus/wbus.h"
#include "wifi_frame/frames.h"
#include "wifi_frame/mac.h"

#define MONITOR_OWNER "monitor"

typedef enum {
    MON_FILTER_ALL = 0,
    MON_FILTER_MGMT = 1,
    MON_FILTER_CTRL = 2,
    MON_FILTER_DATA = 3,
} mon_filter_t;

static bool s_on;
static mon_filter_t s_filter = MON_FILTER_ALL;
static bool s_has_ta;
static uint8_t s_ta[6];
static uint32_t s_printed;
static uint32_t s_matched;
static uint32_t s_total;
static uint32_t s_skipped;
static uint32_t s_max_per_s = 20;
static uint32_t s_window_ms;
static uint32_t s_window_count;

static const char *type_name(uint8_t type) {
    switch (type) {
        case 0:
            return "mgmt";
        case 1:
            return "ctrl";
        case 2:
            return "data";
        default:
            return "ext";
    }
}

static bool passes(uint8_t type) {
    switch (s_filter) {
        case MON_FILTER_MGMT:
            return type == 0;
        case MON_FILTER_CTRL:
            return type == 1;
        case MON_FILTER_DATA:
            return type == 2;
        default:
            return true;
    }
}

static void on_rx(const uint8_t *frame, uint16_t len, const hal_wifi_rx_meta_t *meta, void *ctx) {
    (void)ctx;
    if (!s_on || meta == NULL || len < 10) {
        return;
    }
    const int8_t rssi = meta->rssi;
    const uint8_t channel = meta->channel;
    s_total++;
    const uint8_t type = (uint8_t)((frame[0] >> 2) & 0x03);
    const uint8_t subtype = (uint8_t)((frame[0] >> 4) & 0x0F);
    if (!passes(type)) {
        return;
    }
    if (s_has_ta && memcmp(frame + 10, s_ta, 6) != 0) {
        return;
    }
    s_matched++;
    // 打印是 UART 上最慢的一环（一行 ~100 字节 ≈ 8.7 ms @115200），
    // 超过每秒上限就只计数不打印，否则 RX 队列会被拖垮
    const uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    if (now - s_window_ms >= 1000) {
        s_window_ms = now;
        s_window_count = 0;
    }
    if (s_window_count >= s_max_per_s) {
        s_skipped++;
        return;
    }
    s_window_count++;

    // 驱动给的 len 含 4 字节 FCS，这里按真实帧长算
    const uint16_t payload_len = (len >= 4) ? (uint16_t)(len - 4) : len;

    char a1[18];
    char a2[18];
    char a3[18] = "-";
    wf_mac_format(a1, frame + 4);
    wf_mac_format(a2, frame + 10);
    // 控制帧只有两个地址，后面那几个字节是帧体，别当成 addr3 打出来
    if (payload_len >= 24) {
        wf_mac_format(a3, frame + 16);
    }
    // 速率只有混杂回调的元数据里有：legacy 帧看 rate 索引，HT 帧看 mcs
    char rate_text[24];
    if (meta->sig_mode == 0) {
        snprintf(rate_text, sizeof(rate_text), "%.1fM", (double)hal_wifi_rx_mbps(meta));
    } else {
        snprintf(rate_text, sizeof(rate_text), "mcs%u%s", (unsigned)meta->mcs,
                 meta->sgi ? "/sgi" : "");
    }
    wb_emit("monitor", "rx", "t=%s s=%u len=%u ch=%u rssi=%d rate=%s a1=%s a2=%s a3=%s",
            type_name(type), (unsigned)subtype, (unsigned)payload_len, (unsigned)channel, (int)rssi,
            rate_text, a1, a2, a3);
    s_printed++;
}

static mon_filter_t parse_kind(const char *kind) {
    if (strcmp(kind, "mgmt") == 0) {
        return MON_FILTER_MGMT;
    }
    if (strcmp(kind, "ctrl") == 0) {
        return MON_FILTER_CTRL;
    }
    if (strcmp(kind, "data") == 0) {
        return MON_FILTER_DATA;
    }
    return MON_FILTER_ALL;
}

static esp_err_t monitor_start(wb_args_t *args, wb_reply_t *reply) {
    s_filter = parse_kind(wb_args_str(args, "kind"));
    s_has_ta = false;
    const char *ta = wb_args_str(args, "ta");
    if (ta[0] != 0) {
        if (!wf_mac_parse(ta, s_ta)) {
            wb_reply_fail(reply, "ta must be aa:bb:cc:dd:ee:ff");
            return ESP_ERR_INVALID_ARG;
        }
        s_has_ta = true;
    }
    s_printed = 0;
    s_matched = 0;
    s_total = 0;
    s_skipped = 0;
    s_max_per_s = wb_args_u32(args, "max");
    s_window_ms = (uint32_t)(esp_timer_get_time() / 1000);
    s_window_count = 0;

    hal_wifi_rx_set_filter(true, true, true);
    const esp_err_t err = hal_wifi_sniffer_enable(true);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "sniffer failed (%s)", esp_err_to_name(err));
        return err;
    }
    s_on = true;
    wb_reply_line(reply, "monitor on kind=%s ta=%s ch=%u max=%u", wb_args_str(args, "kind"),
                  s_has_ta ? wb_args_str(args, "ta") : "any", (unsigned)hal_wifi_channel(),
                  (unsigned)s_max_per_s);
    return ESP_OK;
}

static esp_err_t monitor_stop(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    s_on = false;
    hal_wifi_sniffer_enable(false);
    hal_wifi_channel_release(MONITOR_OWNER);
    wb_reply_line(reply, "monitor off total=%u matched=%u printed=%u skipped=%u",
                  (unsigned)s_total, (unsigned)s_matched, (unsigned)s_printed,
                  (unsigned)s_skipped);
    return ESP_OK;
}

static esp_err_t monitor_status(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    hal_wifi_stats_t stats;
    hal_wifi_stats(&stats);
    wb_reply_line(reply, "on=%d ch=%u owner=%s max=%u total=%u matched=%u printed=%u skipped=%u",
                  s_on ? 1 : 0, (unsigned)hal_wifi_channel(), hal_wifi_channel_owner(),
                  (unsigned)s_max_per_s, (unsigned)s_total, (unsigned)s_matched,
                  (unsigned)s_printed, (unsigned)s_skipped);
    wb_reply_line(reply, "rx=%u dropped=%u too_long=%u", (unsigned)stats.rx_frames,
                  (unsigned)stats.rx_dropped, (unsigned)stats.rx_too_long);
    return ESP_OK;
}

static esp_err_t monitor_chan(wb_args_t *args, wb_reply_t *reply) {
    const uint8_t channel = (uint8_t)wb_args_u32(args, "ch");
    esp_err_t err = hal_wifi_channel_acquire(MONITOR_OWNER, HAL_CH_PINNED, channel, 0);
    if (err == ESP_ERR_INVALID_STATE) {
        wb_reply_fail(reply, "channel busy with %s", hal_wifi_channel_owner());
        return err;
    }
    if (err != ESP_OK) {
        wb_reply_fail(reply, "set channel failed (%s)", esp_err_to_name(err));
        return err;
    }
    wb_reply_line(reply, "channel=%u", (unsigned)hal_wifi_channel());
    return ESP_OK;
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "kind", .type = WB_T_STR, .required = false, .def_str = "all"},
    {.name = "ta", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "max", .type = WB_T_U32, .required = false, .min = 1, .max = 1000, .def = 20},
};

static const wb_policy_t kChanPolicy[] = {
    {.name = "ch", .type = WB_T_U32, .required = true, .min = 1, .max = HAL_WIFI_CHANNEL_MAX},
};

static const wb_method_t kMonitorMethods[] = {
    {"start", monitor_start, "[kind=all|mgmt|ctrl|data] [ta=aa:..] [max=1..1000]",
     kStartPolicy, 3},
    {"stop", monitor_stop, "", NULL, 0},
    {"status", monitor_status, "", NULL, 0},
    {"chan", monitor_chan, "ch=1..196", kChanPolicy, 1},
};

static const wb_object_t kMonitorObject = {
    .name = "monitor",
    .methods = kMonitorMethods,
    .n_methods = sizeof(kMonitorMethods) / sizeof(kMonitorMethods[0]),
};

const wb_object_t *services_monitor_object(void) {
    return &kMonitorObject;
}

void services_monitor_attach_rx(void) {
    hal_wifi_rx_subscribe(on_rx, NULL);
}
