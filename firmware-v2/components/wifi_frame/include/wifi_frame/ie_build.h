// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wifi_frame/frames.h"

// 往一块 buffer 里连续追加 IE。长度不够就置 ok=false，后续调用全部空转，
// 调用方最后看 ok 就够，不用每步判长度。
typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t off;
    bool ok;
} wf_ie_writer_t;

void wf_ie_begin(wf_ie_writer_t *w, uint8_t *buf, size_t cap);

bool wf_ie_ok(const wf_ie_writer_t *w);

size_t wf_ie_len(const wf_ie_writer_t *w);

// 裸 IE：id + 长度 + 内容
bool wf_ie_put(wf_ie_writer_t *w, uint8_t id, const void *data, size_t len);

bool wf_ie_ssid(wf_ie_writer_t *w, const char *ssid, size_t len);

// 速率的最高位表示"这是基础速率"，0x80|rate
bool wf_ie_rates(wf_ie_writer_t *w, uint8_t basic, uint8_t others);

bool wf_ie_ds(wf_ie_writer_t *w, uint8_t channel);

bool wf_ie_tim(wf_ie_writer_t *w, uint8_t dtim_count, uint8_t dtim_period, uint8_t bitmap_control,
               const uint8_t *pvbitmap, size_t pv_len);

bool wf_ie_csa(wf_ie_writer_t *w, uint8_t channel, uint8_t count);

// WPA2-PSK：一组 AES-CCMP 组播 + 一组 PSK AKM
bool wf_ie_rsn_psk(wf_ie_writer_t *w);

// WPA3-SAE 过渡模式：CCMP + PSK + SAE
bool wf_ie_rsn_sae(wf_ie_writer_t *w);

// Extended Capabilities，只有 BSS Transition 位（802.11v，第 6 字节 bit 3）
bool wf_ie_extcap_btm(wf_ie_writer_t *w);

// 把一段现成 IE 原样搬过来，可跳过指定 id（克隆 beacon 换 TIM/CSA 时用）。
// 返回搬了多少字节。
size_t wf_ie_copy(wf_ie_writer_t *w, const uint8_t *ies, size_t len, int skip_id);
