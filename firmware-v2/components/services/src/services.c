// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "services/services.h"

#include "esp_log.h"
#include "hal_wifi/hal_wifi.h"
#include "services_private.h"
#include "wbus/wbus.h"

static const char *TAG = "services";

void services_start(void) {
    wb_register(services_system_object());
    wb_register(services_ui_object());
    wb_register(services_radio_object());
    wb_register(services_scan_object());
    services_scan_attach_rx();
    ESP_LOGI(TAG, "objects registered");
}

void services_tick(uint32_t now_ms) {
    hal_wifi_channel_tick(now_ms);
    services_scan_tick(now_ms);
}
