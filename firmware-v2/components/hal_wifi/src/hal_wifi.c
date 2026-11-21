// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "hal_wifi/hal_wifi.h"

static uint8_t s_channel;

esp_err_t hal_wifi_init(void) {
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t hal_wifi_set_channel(uint8_t channel) {
    s_channel = channel;
    return ESP_ERR_NOT_SUPPORTED;
}

uint8_t hal_wifi_channel(void) {
    return s_channel;
}

esp_err_t hal_wifi_tx(const uint8_t *frame, uint16_t len, bool is_broadcast) {
    (void)frame;
    (void)len;
    (void)is_broadcast;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t hal_wifi_rx_subscribe(hal_wifi_rx_fn fn, void *ctx) {
    (void)fn;
    (void)ctx;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t hal_wifi_sniffer_enable(bool enable) {
    (void)enable;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t hal_wifi_scan_begin(void) {
    return ESP_ERR_NOT_SUPPORTED;
}

uint64_t hal_wifi_tsf(void) {
    return 0;
}

void hal_wifi_stats(hal_wifi_stats_t *out) {
    if (out != NULL) {
        *out = (hal_wifi_stats_t){0};
    }
}
