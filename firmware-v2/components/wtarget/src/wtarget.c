// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 契约占位：设备登记表在扫描模块接入时实现，签名先固定下来。

#include "wtarget/wtarget.h"

esp_err_t wt_clear(void) {
    return ESP_ERR_NOT_SUPPORTED;
}

uint32_t wt_count(void) {
    return 0;
}

const wt_entry_t *wt_at(uint32_t index) {
    (void)index;
    return NULL;
}

esp_err_t wt_add(const wt_entry_t *entry) {
    (void)entry;
    return ESP_ERR_NOT_SUPPORTED;
}

const wt_entry_t *wt_find_mac(const uint8_t mac[6]) {
    (void)mac;
    return NULL;
}

esp_err_t wt_select(uint32_t index) {
    (void)index;
    return ESP_ERR_NOT_SUPPORTED;
}

const wt_entry_t *wt_selected(void) {
    return NULL;
}
