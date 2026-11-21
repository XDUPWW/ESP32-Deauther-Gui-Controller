// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "platform/plat_console.h"
#include "platform/plat_led.h"
#include "platform/plat_storage.h"
#include "transport/console.h"
#include "wireless_ui/wireless_ui.h"

void app_main(void) {
    plat_storage_init();
    plat_led_init();
    if (plat_console_init() != ESP_OK) {
        return;
    }

    transport_console_start();
    transport_console_out("INFO boot");

    if (wireless_ui_start()) {
        transport_console_out("INFO display ready");
    } else {
        transport_console_out("WARN no display, headless mode");
    }

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
