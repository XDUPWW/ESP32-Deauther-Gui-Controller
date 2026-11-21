// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "wifi_frame/ie_build.h"

#include <string.h>

void wf_ie_begin(wf_ie_writer_t *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->off = 0;
    w->ok = (buf != NULL);
}

bool wf_ie_ok(const wf_ie_writer_t *w) {
    return w->ok;
}

size_t wf_ie_len(const wf_ie_writer_t *w) {
    return w->off;
}

bool wf_ie_put(wf_ie_writer_t *w, uint8_t id, const void *data, size_t len) {
    if (!w->ok) {
        return false;
    }
    if (len > 255 || w->off + 2 + len > w->cap) {
        w->ok = false;
        return false;
    }
    w->buf[w->off++] = id;
    w->buf[w->off++] = (uint8_t)len;
    if (len > 0) {
        memcpy(w->buf + w->off, data, len);
        w->off += len;
    }
    return true;
}

bool wf_ie_ssid(wf_ie_writer_t *w, const char *ssid, size_t len) {
    if (ssid == NULL && len > 0) {
        return false;
    }
    if (len > 32) {
        len = 32;
    }
    return wf_ie_put(w, WF_IE_SSID, ssid, len);
}

bool wf_ie_rates(wf_ie_writer_t *w, uint8_t basic, uint8_t others) {
    const uint8_t rates[2] = {0x80 | (basic & 0x7F), others & 0x7F};
    return wf_ie_put(w, WF_IE_SUPPORTED_RATES, rates, sizeof(rates));
}

bool wf_ie_ds(wf_ie_writer_t *w, uint8_t channel) {
    return wf_ie_put(w, WF_IE_DS_PARAMS, &channel, 1);
}

bool wf_ie_tim(wf_ie_writer_t *w, uint8_t dtim_count, uint8_t dtim_period, uint8_t bitmap_control,
               const uint8_t *pvbitmap, size_t pv_len) {
    if (pv_len > 251) {
        return false;
    }
    uint8_t body[255];
    body[0] = dtim_count;
    body[1] = dtim_period;
    body[2] = bitmap_control;
    if (pv_len > 0 && pvbitmap != NULL) {
        memcpy(body + 3, pvbitmap, pv_len);
    }
    return wf_ie_put(w, WF_IE_TIM, body, 3 + pv_len);
}

bool wf_ie_csa(wf_ie_writer_t *w, uint8_t channel, uint8_t count) {
    const uint8_t body[3] = {0, channel, count};
    return wf_ie_put(w, WF_IE_CSA, body, sizeof(body));
}

// RSN 的公共头：版本 1、CCMP 组播、CCMP 单播
static void rsn_prefix(uint8_t *body, size_t *n) {
    static const uint8_t kPrefix[] = {
        0x01, 0x00,                          // version 1
        0x00, 0x0F, 0xAC, 0x04,              // group: CCMP
        0x01, 0x00,                          // pairwise count 1
        0x00, 0x0F, 0xAC, 0x04,              // pairwise: CCMP
    };
    memcpy(body, kPrefix, sizeof(kPrefix));
    *n = sizeof(kPrefix);
}

bool wf_ie_rsn_psk(wf_ie_writer_t *w) {
    uint8_t body[32];
    size_t n = 0;
    rsn_prefix(body, &n);
    static const uint8_t kAkm[] = {
        0x01, 0x00,             // AKM count 1
        0x00, 0x0F, 0xAC, 0x02, // PSK
        0x00, 0x00,             // capabilities
    };
    memcpy(body + n, kAkm, sizeof(kAkm));
    n += sizeof(kAkm);
    return wf_ie_put(w, WF_IE_RSN, body, n);
}

bool wf_ie_rsn_sae(wf_ie_writer_t *w) {
    uint8_t body[40];
    size_t n = 0;
    rsn_prefix(body, &n);
    static const uint8_t kAkm[] = {
        0x02, 0x00,             // AKM count 2
        0x00, 0x0F, 0xAC, 0x02, // PSK
        0x00, 0x0F, 0xAC, 0x08, // SAE
        0x00, 0x00,             // capabilities
    };
    memcpy(body + n, kAkm, sizeof(kAkm));
    n += sizeof(kAkm);
    return wf_ie_put(w, WF_IE_RSN, body, n);
}

bool wf_ie_extcap_btm(wf_ie_writer_t *w) {
    // BSS Transition 是整个 capability 字段的 bit 19，也就是第 3 个字节的 bit 3
    const uint8_t body[3] = {0x00, 0x00, 0x08};
    return wf_ie_put(w, WF_IE_EXT_CAP, body, sizeof(body));
}

size_t wf_ie_copy(wf_ie_writer_t *w, const uint8_t *ies, size_t len, int skip_id) {
    if (!w->ok || ies == NULL) {
        return 0;
    }
    size_t start = w->off;
    size_t p = 0;
    while (p + 2 <= len) {
        const uint8_t id = ies[p];
        const size_t body = ies[p + 1];
        if (p + 2 + body > len) {
            break;  // 尾巴不完整，别照搬
        }
        if ((int)id != skip_id) {
            if (!wf_ie_put(w, id, ies + p + 2, body)) {
                break;
            }
        }
        p += 2 + body;
    }
    return w->off - start;
}
