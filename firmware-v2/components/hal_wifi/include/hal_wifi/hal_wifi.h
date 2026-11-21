// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#define HAL_WIFI_UNICAST_SLOT_MS 45

typedef struct {
    uint32_t tx_ok;
    uint32_t tx_err;
    uint32_t tx_throttled;
    uint32_t rx_frames;
} hal_wifi_stats_t;

typedef void (*hal_wifi_rx_fn)(const uint8_t *frame, uint16_t len, int8_t rssi, uint8_t channel,
                               void *ctx);

esp_err_t hal_wifi_init(void);

esp_err_t hal_wifi_set_channel(uint8_t channel);

uint8_t hal_wifi_channel(void);

esp_err_t hal_wifi_tx(const uint8_t *frame, uint16_t len, bool is_broadcast);

esp_err_t hal_wifi_rx_subscribe(hal_wifi_rx_fn fn, void *ctx);

esp_err_t hal_wifi_sniffer_enable(bool enable);

esp_err_t hal_wifi_scan_begin(void);

uint64_t hal_wifi_tsf(void);

void hal_wifi_stats(hal_wifi_stats_t *out);
