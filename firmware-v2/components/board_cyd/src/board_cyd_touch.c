// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// CYD 上的 XPT2046：独立的 SPI2 总线，没有 PENIRQ，按原始值窗口判断有没有按下。

#include <stddef.h>

#include "driver/spi_master.h"
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "platform/plat_display.h"

#define TOUCH_HOST SPI2_HOST
#define PIN_TOUCH_MOSI 32
#define PIN_TOUCH_MISO 39
#define PIN_TOUCH_SCLK 25
#define PIN_TOUCH_CS 33

#define TOUCH_SPI_CLOCK_HZ (2 * 1000 * 1000)
#define TOUCH_CMD_A 0x90
#define TOUCH_CMD_B 0xD0

// 没按压时两个轴贴在 0 / 4095 上，落在这个窗口里才算真的按住了
#define TOUCH_RAW_MIN 120
#define TOUCH_RAW_MAX 3975

static const char *TAG = "board_cyd_touch";

static spi_device_handle_t s_touch;
static SemaphoreHandle_t s_lock;

static uint16_t read_axis(uint8_t command) {
    uint8_t tx[3] = {command, 0x00, 0x00};
    uint8_t rx[3] = {0};
    spi_transaction_t trans = {
        .length = 8 * sizeof(tx),
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    if (spi_device_transmit(s_touch, &trans) != ESP_OK) {
        return 0;
    }
    return (uint16_t)((((uint16_t)rx[1] << 8) | rx[2]) >> 3) & 0x0FFF;
}

esp_err_t cyd_touch_init(void) {
    const spi_bus_config_t bus_cfg = {
        .mosi_io_num = PIN_TOUCH_MOSI,
        .miso_io_num = PIN_TOUCH_MISO,
        .sclk_io_num = PIN_TOUCH_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_RETURN_ON_ERROR(spi_bus_initialize(TOUCH_HOST, &bus_cfg, SPI_DMA_CH_AUTO), TAG,
                        "touch spi bus failed");

    const spi_device_interface_config_t dev_cfg = {
        .mode = 0,
        .clock_speed_hz = TOUCH_SPI_CLOCK_HZ,
        .spics_io_num = PIN_TOUCH_CS,
        .queue_size = 2,
    };
    ESP_RETURN_ON_ERROR(spi_bus_add_device(TOUCH_HOST, &dev_cfg, &s_touch), TAG,
                        "touch spi device failed");

    s_lock = xSemaphoreCreateMutex();
    ESP_RETURN_ON_FALSE(s_lock != NULL, ESP_ERR_NO_MEM, TAG, "touch lock failed");
    return ESP_OK;
}

bool cyd_touch_read(int *raw_x, int *raw_y) {
    if (s_touch == NULL || s_lock == NULL) {
        return false;
    }
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) != pdTRUE) {
        return false;
    }
    const int a1 = read_axis(TOUCH_CMD_A);
    const int b1 = read_axis(TOUCH_CMD_B);
    const int a2 = read_axis(TOUCH_CMD_A);
    const int b2 = read_axis(TOUCH_CMD_B);
    xSemaphoreGive(s_lock);

    const int a = (a1 + a2) / 2;
    const int b = (b1 + b2) / 2;
    if (raw_x != NULL) {
        *raw_x = a;
    }
    if (raw_y != NULL) {
        *raw_y = b;
    }
    const bool a_ok = a > TOUCH_RAW_MIN && a < TOUCH_RAW_MAX;
    const bool b_ok = b > TOUCH_RAW_MIN && b < TOUCH_RAW_MAX;
    return a_ok && b_ok;
}
