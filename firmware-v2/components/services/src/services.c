// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "services/services.h"

#include "esp_log.h"
#include "hal_wifi/hal_wifi.h"
#include "sdkconfig.h"
#include "services_private.h"
#include "wbus/wbus.h"

static const char *TAG = "services";

void services_start(void) {
    wb_register(services_system_object());
    wb_register(services_ui_object());
    wb_register(services_radio_object());
    wb_register(services_scan_object());
    wb_register(services_monitor_object());
#if CONFIG_WB_BLE
    wb_register(services_ble_object());
#endif
    services_scan_attach_rx();
    services_monitor_attach_rx();
    ESP_LOGI(TAG, "objects registered");
}

void services_tick(uint32_t now_ms) {
    hal_wifi_channel_tick(now_ms);
    services_scan_tick(now_ms);
}
