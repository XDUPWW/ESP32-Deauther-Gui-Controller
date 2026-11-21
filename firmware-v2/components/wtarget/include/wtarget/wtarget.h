// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

typedef enum {
    WT_KIND_AP = 0,
    WT_KIND_STA = 1,
} wt_kind_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t mac[6];
    int8_t rssi;
    uint8_t channel;
    wt_kind_t kind;
} wt_entry_t;

esp_err_t wt_clear(void);

uint32_t wt_count(void);

const wt_entry_t *wt_at(uint32_t index);

esp_err_t wt_add(const wt_entry_t *entry);

const wt_entry_t *wt_find_mac(const uint8_t mac[6]);

esp_err_t wt_select(uint32_t index);

const wt_entry_t *wt_selected(void);
