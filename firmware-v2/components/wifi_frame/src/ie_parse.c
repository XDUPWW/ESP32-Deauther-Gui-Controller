// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 契约占位：IE 解析在后续阶段实现，签名先固定下来。

#include "wifi_frame/ie_parse.h"

const uint8_t *wf_ie_find(const uint8_t *ies, size_t len, uint8_t id, size_t *out_len) {
    (void)ies, (void)len, (void)id;
    if (out_len != NULL) {
        *out_len = 0;
    }
    return NULL;
}

bool wf_rsn_has_akm(const uint8_t *rsn, size_t len, uint8_t akm_type) {
    (void)rsn, (void)len, (void)akm_type;
    return false;
}

bool wf_rsn_mfpr_required(const uint8_t *rsn, size_t len) {
    (void)rsn, (void)len;
    return false;
}

bool wf_extcap_has_bss_transition(const uint8_t *extcap, size_t len) {
    (void)extcap, (void)len;
    return false;
}

bool wf_tim_parse(const uint8_t *ie, size_t len, wf_tim_t *out) {
    (void)ie, (void)len, (void)out;
    return false;
}

bool wf_tim_is_multicast_set(const wf_tim_t *tim) {
    (void)tim;
    return false;
}

bool wf_tim_aid_set(const wf_tim_t *tim, uint16_t aid) {
    (void)tim, (void)aid;
    return false;
}

bool wf_csa_parse(const uint8_t *ie, size_t len, uint8_t *channel, uint8_t *count) {
    (void)ie, (void)len, (void)channel, (void)count;
    return false;
}
