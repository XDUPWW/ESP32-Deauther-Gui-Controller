// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "platform/plat_console.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "driver/uart.h"
#include "esp_check.h"

static const char *TAG = "plat_console";

#define CONSOLE_UART UART_NUM_0
#define CONSOLE_BAUD 115200
#define CONSOLE_RX_BUF 2048

esp_err_t plat_console_init(void) {
    static bool ready;
    if (ready) {
        return ESP_OK;
    }
    const uart_config_t cfg = {
        .baud_rate = CONSOLE_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_RETURN_ON_ERROR(uart_driver_install(CONSOLE_UART, CONSOLE_RX_BUF, 0, 0, NULL, 0), TAG,
                        "uart driver install failed");
    ESP_RETURN_ON_ERROR(uart_param_config(CONSOLE_UART, &cfg), TAG, "uart param config failed");
    ESP_RETURN_ON_ERROR(uart_set_pin(CONSOLE_UART, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE,
                                     UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE),
                        TAG, "uart pin config failed");
    ready = true;
    return ESP_OK;
}

int plat_console_read(uint8_t *buf, size_t cap, uint32_t timeout_ms) {
    if (buf == NULL || cap == 0) {
        return 0;
    }
    return uart_read_bytes(CONSOLE_UART, buf, cap, pdMS_TO_TICKS(timeout_ms));
}

void plat_console_write(const char *text) {
    if (text == NULL) {
        return;
    }
    uart_write_bytes(CONSOLE_UART, text, strlen(text));
}

void plat_console_printf(const char *fmt, ...) {
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n <= 0) {
        return;
    }
    uart_write_bytes(CONSOLE_UART, line, (size_t)((n < (int)sizeof(line)) ? n : (int)sizeof(line) - 1));
}
