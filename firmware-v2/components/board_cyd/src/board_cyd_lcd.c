// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// ESP32-2432S028R（CYD）这块板：ILI9341 走 SPI3，XPT2046 走 SPI2，背光 GPIO21。

#include <stddef.h>

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_check.h"
#include "esp_lcd_ili9341.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_log.h"
#include "platform/plat_display.h"

static const char *TAG = "board_cyd";

#define LCD_HOST SPI3_HOST
#define PIN_LCD_MISO 12
#define PIN_LCD_MOSI 13
#define PIN_LCD_SCLK 14
#define PIN_LCD_CS 15
#define PIN_LCD_DC 2
#define PIN_LCD_RST (-1)
#define PIN_LCD_BL 21

#define LCD_H_RES 320
#define LCD_V_RES 240
#define LCD_DRAW_LINES 20
#define LCD_PIXEL_CLOCK_HZ (40 * 1000 * 1000)

static esp_lcd_panel_handle_t s_panel;
static esp_lcd_panel_io_handle_t s_io;

esp_err_t cyd_lcd_init(plat_lcd_t *lcd) {
    ESP_RETURN_ON_FALSE(lcd != NULL, ESP_ERR_INVALID_ARG, TAG, "lcd handle is null");

    const gpio_config_t bl_cfg = {
        .pin_bit_mask = 1ULL << PIN_LCD_BL,
        .mode = GPIO_MODE_OUTPUT,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&bl_cfg), TAG, "backlight gpio failed");
    gpio_set_level(PIN_LCD_BL, 0);

    const spi_bus_config_t bus_cfg = {
        .miso_io_num = PIN_LCD_MISO,
        .mosi_io_num = PIN_LCD_MOSI,
        .sclk_io_num = PIN_LCD_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = LCD_H_RES * LCD_DRAW_LINES * sizeof(uint16_t),
    };
    ESP_RETURN_ON_ERROR(spi_bus_initialize(LCD_HOST, &bus_cfg, SPI_DMA_CH_AUTO), TAG,
                        "lcd spi bus failed");

    const esp_lcd_panel_io_spi_config_t io_cfg = {
        .cs_gpio_num = PIN_LCD_CS,
        .dc_gpio_num = PIN_LCD_DC,
        .spi_mode = 0,
        .pclk_hz = LCD_PIXEL_CLOCK_HZ,
        .trans_queue_depth = 10,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
    };
    ESP_RETURN_ON_ERROR(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)LCD_HOST, &io_cfg, &s_io),
                        TAG, "panel io failed");

    const esp_lcd_panel_dev_config_t panel_cfg = {
        .reset_gpio_num = PIN_LCD_RST,
        .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_BGR,
        .bits_per_pixel = 16,
    };
    ESP_RETURN_ON_ERROR(esp_lcd_new_panel_ili9341(s_io, &panel_cfg, &s_panel), TAG, "ili9341 failed");
    ESP_RETURN_ON_ERROR(esp_lcd_panel_reset(s_panel), TAG, "panel reset failed");
    ESP_RETURN_ON_ERROR(esp_lcd_panel_init(s_panel), TAG, "panel init failed");
    ESP_RETURN_ON_ERROR(esp_lcd_panel_invert_color(s_panel, true), TAG, "panel invert failed");
    ESP_RETURN_ON_ERROR(esp_lcd_panel_disp_on_off(s_panel, true), TAG, "panel on failed");

    lcd->panel = s_panel;
    lcd->io = s_io;
    lcd->width = LCD_H_RES;
    lcd->height = LCD_V_RES;
    lcd->swap_xy = true;
    lcd->mirror_x = true;
    lcd->mirror_y = true;
    ESP_LOGI(TAG, "ili9341 %dx%d ready", LCD_H_RES, LCD_V_RES);
    return ESP_OK;
}

void cyd_backlight(bool on) {
    gpio_set_level(PIN_LCD_BL, on ? 1 : 0);
}
