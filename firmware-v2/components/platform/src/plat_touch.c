// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "platform/plat_display.h"

#include "sdkconfig.h"

#if CONFIG_IDF_TARGET_ESP32

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_check.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define TOUCH_HOST SPI2_HOST
#define PIN_TOUCH_MOSI 32
#define PIN_TOUCH_MISO 39
#define PIN_TOUCH_SCLK 25
#define PIN_TOUCH_CS 33

#define TOUCH_SPI_CLOCK_HZ (2 * 1000 * 1000)
#define TOUCH_CMD_X 0x90
#define TOUCH_CMD_Y 0xD0

#define TOUCH_RAW_MIN 120
#define TOUCH_RAW_MAX 3975

static const char *TAG = "plat_touch";

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

esp_err_t plat_touch_init(void) {
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

bool plat_touch_read(int *raw_x, int *raw_y) {
    if (s_touch == NULL || s_lock == NULL) {
        return false;
    }
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) != pdTRUE) {
        return false;
    }
    const int x1 = read_axis(TOUCH_CMD_X);
    const int y1 = read_axis(TOUCH_CMD_Y);
    const int x2 = read_axis(TOUCH_CMD_X);
    const int y2 = read_axis(TOUCH_CMD_Y);
    xSemaphoreGive(s_lock);

    const int x = (x1 + x2) / 2;
    const int y = (y1 + y2) / 2;
    if (raw_x != NULL) {
        *raw_x = x;
    }
    if (raw_y != NULL) {
        *raw_y = y;
    }
    const bool x_ok = x > TOUCH_RAW_MIN && x < TOUCH_RAW_MAX;
    const bool y_ok = y > TOUCH_RAW_MIN && y < TOUCH_RAW_MAX;
    return x_ok && y_ok;
}

#else

esp_err_t plat_touch_init(void) {
    return ESP_ERR_NOT_SUPPORTED;
}

bool plat_touch_read(int *raw_x, int *raw_y) {
    (void)raw_x;
    (void)raw_y;
    return false;
}

#endif
