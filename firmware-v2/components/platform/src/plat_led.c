// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "platform/plat_led.h"

#include "driver/gpio.h"
#include "esp_check.h"

static const char *TAG = "plat_led";

#define PIN_LED 4
#define LED_ACTIVE_LOW 1

esp_err_t plat_led_init(void) {
    const gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << PIN_LED,
        .mode = GPIO_MODE_OUTPUT,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&cfg), TAG, "led gpio failed");
    plat_led_set(false);
    return ESP_OK;
}

void plat_led_set(bool on) {
#if LED_ACTIVE_LOW
    gpio_set_level(PIN_LED, on ? 0 : 1);
#else
    gpio_set_level(PIN_LED, on ? 1 : 0);
#endif
}
