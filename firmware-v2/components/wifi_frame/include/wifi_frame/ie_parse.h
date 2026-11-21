// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wifi_frame/frames.h"

typedef struct {
    uint8_t dtim_count;
    uint8_t dtim_period;
    uint8_t bitmap_control;
    const uint8_t *pvbitmap;
    size_t pv_len;
} wf_tim_t;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t ssid_len;
    uint8_t channel;
    bool has_rsn;
    bool sae;
    bool mfpr;
    bool bss_transition;
} wf_bss_t;

const uint8_t *wf_ie_find(const uint8_t *ies, size_t len, uint8_t id, size_t *out_len);

bool wf_parse_beacon(const uint8_t *frame, size_t len, wf_bss_t *out);

bool wf_rsn_has_akm(const uint8_t *rsn, size_t len, uint8_t akm_type);

bool wf_rsn_mfpr_required(const uint8_t *rsn, size_t len);

bool wf_extcap_has_bss_transition(const uint8_t *extcap, size_t len);

bool wf_tim_parse(const uint8_t *ie, size_t len, wf_tim_t *out);

bool wf_tim_is_multicast_set(const wf_tim_t *tim);

bool wf_tim_aid_set(const wf_tim_t *tim, uint16_t aid);

bool wf_csa_parse(const uint8_t *ie, size_t len, uint8_t *channel, uint8_t *count);
