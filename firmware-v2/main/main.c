// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include <stdint.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "attacks/attack.h"
#include "board_cyd/board_cyd.h"
#include "hal_wifi/hal_wifi.h"
#include "platform/plat_display.h"
#include "platform/plat_led.h"
#include "platform/plat_console.h"
#include "platform/plat_storage.h"
#include "services/services.h"
#include "transport/transport.h"
#include "wireless_ui/wireless_ui.h"

static const char *TAG = "main";

#define LOOP_PERIOD_MS 50

static const services_ui_ops_t kUiOps = {
    .screen = wireless_ui_selftest,
    .status = wireless_ui_status,
    .touch = wireless_ui_touch_report,
    .touch_cal = wireless_ui_touch_calib,
    .tap = wireless_ui_tap,
    .dump = wireless_ui_dump,
};

void app_main(void) {
    static const char kBoot[] = "INFO boot";

    plat_storage_init();
    plat_led_init();
    plat_display_bind(board_cyd_display_ops());
    if (plat_console_init() != ESP_OK) {
        ESP_LOGE(TAG, "console init failed");
        return;
    }

    services_start();
    hal_rate_t startup_rate = HAL_RATE_DEFAULT;
    uint8_t stored_rate = 0;
    if (plat_storage_get("tx_rate", &stored_rate, sizeof(stored_rate))) {
        startup_rate = (hal_rate_t)stored_rate;
    }
    if (hal_wifi_init(startup_rate) != ESP_OK) {
        ESP_LOGW(TAG, "radio layer not wired yet");
    }
    attacks_start();

    if (transport_start() != ESP_OK) {
        ESP_LOGE(TAG, "transport start failed");
        return;
    }
    transport_add(transport_serial_text());
    transport_out(kBoot);

    if (wireless_ui_start()) {
        services_ui_bind(&kUiOps);
        transport_out("INFO display ready");
    } else {
        transport_out("WARN no display, headless");
    }

    for (;;) {
        const uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        services_tick(now);
        attacks_tick(now);
        vTaskDelay(pdMS_TO_TICKS(LOOP_PERIOD_MS));
    }
}
