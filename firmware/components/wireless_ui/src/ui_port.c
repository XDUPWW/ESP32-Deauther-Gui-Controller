// LCD (ILI9341, VSPI) + touch (XPT2046, own SPI) port for the ESP32-2432S028R
// "CYD" board, wired into LVGL through esp_lvgl_port.
//
// Pin map taken from esp_touch_project/5_2_XPT2046_Touch_Test:
//   LCD  : MISO 12, MOSI 13, SCLK 14, CS 15, DC 2, RST -1, backlight 21
//   Touch: MOSI 32, MISO 39, SCLK 25, CS 33, IRQ 36
//
// The touch panel is driven directly (small XPT2046 reader) so the firmware does
// not depend on an out-of-tree touch component; only LVGL + esp_lvgl_port +
// esp_lcd_ili9341 are used.

#include "sdkconfig.h"

#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT

#include "ui_port.h"

#include <stdint.h>

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_check.h"
#include "esp_lcd_ili9341.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_log.h"
#include "esp_lvgl_port.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

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

#define TOUCH_HOST SPI2_HOST
#define PIN_TOUCH_MOSI 32
#define PIN_TOUCH_MISO 39
#define PIN_TOUCH_SCLK 25
#define PIN_TOUCH_CS 33
#define PIN_TOUCH_IRQ 36
#define TOUCH_SPI_CLOCK_HZ (2 * 1000 * 1000)

// Untouched XPT2046 readings sit at the rails (0 or 4095), so anything inside
// this window counts as a real touch and lets us work without the PENIRQ line.
#define TOUCH_RAW_VALID_MIN 120
#define TOUCH_RAW_VALID_MAX 3975

static const char *TAG = "wui_port";

static spi_device_handle_t s_touch;
static esp_lcd_panel_handle_t s_panel;
static esp_lcd_panel_io_handle_t s_io;
static wui_calib_t s_calib;
static int s_touch_irq_level = 1;
static SemaphoreHandle_t s_touch_mutex;

int wireless_ui_port_touch_irq_level(void) {
    return s_touch_irq_level;
}

static uint16_t touch_read_axis(uint8_t command) {
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

static int16_t clamp_to(int32_t value, int32_t limit) {
    if (value < 0) return 0;
    if (value > limit) return (int16_t)limit;
    return (int16_t)value;
}

static bool touch_sample(int *raw_x, int *raw_y) {
    // The LVGL indev callback and the calibration poll run in different tasks and
    // share this SPI device; without the lock their transactions interleave and
    // produce garbage coordinates.
    if (s_touch_mutex == NULL || xSemaphoreTake(s_touch_mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        return false;
    }
    // Note: PENIRQ (GPIO36) is not wired on this board, so pressed/released is
    // derived from the raw window only; callers add a stability filter on top.
    const int x1 = touch_read_axis(0x90);
    const int y1 = touch_read_axis(0xD0);
    const int x2 = touch_read_axis(0x90);
    const int y2 = touch_read_axis(0xD0);
    *raw_x = (x1 + x2) / 2;
    *raw_y = (y1 + y2) / 2;
    const bool x_ok = *raw_x > TOUCH_RAW_VALID_MIN && *raw_x < TOUCH_RAW_VALID_MAX;
    const bool y_ok = *raw_y > TOUCH_RAW_VALID_MIN && *raw_y < TOUCH_RAW_VALID_MAX;
    xSemaphoreGive(s_touch_mutex);
    return x_ok && y_ok;
}

static void touch_map(int raw_x, int raw_y, int *screen_x, int *screen_y) {
    wui_calib_apply(&s_calib, raw_x, raw_y, LCD_H_RES, LCD_V_RES, screen_x, screen_y);
}

void wireless_ui_port_set_calib(const wui_calib_t *calib) {
    if (calib != NULL && calib->valid) {
        s_calib = *calib;
    }
}

const wui_calib_t *wireless_ui_port_get_calib(void) {
    return &s_calib;
}

bool wireless_ui_port_touch_read(int *raw_x, int *raw_y, int *screen_x, int *screen_y, bool *pressed) {
    int rx = 0;
    int ry = 0;
    const bool down = touch_sample(&rx, &ry);
    s_touch_irq_level = gpio_get_level(PIN_TOUCH_IRQ);
    int sx = 0;
    int sy = 0;
    touch_map(rx, ry, &sx, &sy);
    if (raw_x) *raw_x = rx;
    if (raw_y) *raw_y = ry;
    if (screen_x) *screen_x = sx;
    if (screen_y) *screen_y = sy;
    if (pressed) *pressed = down;
    return true;
}

static void touch_read_cb(lv_indev_t *indev, lv_indev_data_t *data) {
    (void)indev;
    static int16_t last_x = 0;
    static int16_t last_y = 0;
    int raw_x = 0;
    int raw_y = 0;
    int sx = 0;
    int sy = 0;
    const bool down = touch_sample(&raw_x, &raw_y);
    if (down) {
        touch_map(raw_x, raw_y, &sx, &sy);
        last_x = (int16_t)sx;
        last_y = (int16_t)sy;
    }
    data->point.x = last_x;
    data->point.y = last_y;
    data->state = down ? LV_INDEV_STATE_PRESSED : LV_INDEV_STATE_RELEASED;
}

static esp_err_t lcd_init(void) {
    const gpio_config_t bl_cfg = {
        .pin_bit_mask = 1ULL << PIN_LCD_BL,
        .mode = GPIO_MODE_OUTPUT,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&bl_cfg), TAG, "backlight gpio");
    gpio_set_level(PIN_LCD_BL, 1);

    const spi_bus_config_t bus_cfg = {
        .miso_io_num = PIN_LCD_MISO,
        .mosi_io_num = PIN_LCD_MOSI,
        .sclk_io_num = PIN_LCD_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = LCD_H_RES * LCD_DRAW_LINES * sizeof(uint16_t),
    };
    ESP_RETURN_ON_ERROR(spi_bus_initialize(LCD_HOST, &bus_cfg, SPI_DMA_CH_AUTO), TAG, "lcd spi bus");

    const esp_lcd_panel_io_spi_config_t io_cfg = {
        .cs_gpio_num = PIN_LCD_CS,
        .dc_gpio_num = PIN_LCD_DC,
        .spi_mode = 0,
        .pclk_hz = LCD_PIXEL_CLOCK_HZ,
        .trans_queue_depth = 10,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
    };
    ESP_RETURN_ON_ERROR(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)LCD_HOST, &io_cfg, &s_io), TAG, "panel io");

    const esp_lcd_panel_dev_config_t panel_cfg = {
        .reset_gpio_num = PIN_LCD_RST,
        .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_BGR,
        .bits_per_pixel = 16,
    };
    ESP_RETURN_ON_ERROR(esp_lcd_new_panel_ili9341(s_io, &panel_cfg, &s_panel), TAG, "ili9341");
    ESP_RETURN_ON_ERROR(esp_lcd_panel_reset(s_panel), TAG, "panel reset");
    ESP_RETURN_ON_ERROR(esp_lcd_panel_init(s_panel), TAG, "panel init");
    ESP_RETURN_ON_ERROR(esp_lcd_panel_invert_color(s_panel, true), TAG, "panel invert");
    ESP_RETURN_ON_ERROR(esp_lcd_panel_disp_on_off(s_panel, true), TAG, "panel on");
    return ESP_OK;
}

static esp_err_t touch_init(lv_display_t *disp) {
    const spi_bus_config_t bus_cfg = {
        .mosi_io_num = PIN_TOUCH_MOSI,
        .miso_io_num = PIN_TOUCH_MISO,
        .sclk_io_num = PIN_TOUCH_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_RETURN_ON_ERROR(spi_bus_initialize(TOUCH_HOST, &bus_cfg, SPI_DMA_CH_AUTO), TAG, "touch spi bus");

    const gpio_config_t irq_cfg = {
        .pin_bit_mask = 1ULL << PIN_TOUCH_IRQ,
        .mode = GPIO_MODE_INPUT,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&irq_cfg), TAG, "touch irq gpio");

    const spi_device_interface_config_t dev_cfg = {
        .mode = 0,
        .clock_speed_hz = TOUCH_SPI_CLOCK_HZ,
        .spics_io_num = PIN_TOUCH_CS,
        .queue_size = 2,
    };
    ESP_RETURN_ON_ERROR(spi_bus_add_device(TOUCH_HOST, &dev_cfg, &s_touch), TAG, "touch spi device");
    s_touch_mutex = xSemaphoreCreateMutex();
    ESP_RETURN_ON_FALSE(s_touch_mutex != NULL, ESP_ERR_NO_MEM, TAG, "touch mutex");


    lv_indev_t *indev = lv_indev_create();
    if (indev == NULL) {
        return ESP_ERR_NO_MEM;
    }
    lv_indev_set_type(indev, LV_INDEV_TYPE_POINTER);
    lv_indev_set_read_cb(indev, touch_read_cb);
    lv_indev_set_display(indev, disp);
    return ESP_OK;
}

lv_display_t *wireless_ui_port_init(void) {
    if (!wui_calib_load(&s_calib)) {
        wui_calib_defaults(&s_calib);
    }
    if (lcd_init() != ESP_OK) {
        return NULL;
    }

    const lvgl_port_cfg_t port_cfg = ESP_LVGL_PORT_INIT_CONFIG();
    if (lvgl_port_init(&port_cfg) != ESP_OK) {
        ESP_LOGE(TAG, "lvgl_port_init failed");
        return NULL;
    }

    const lvgl_port_display_cfg_t disp_cfg = {
        .io_handle = s_io,
        .panel_handle = s_panel,
        .buffer_size = LCD_H_RES * LCD_DRAW_LINES,
        .double_buffer = false,
        .hres = LCD_H_RES,
        .vres = LCD_V_RES,
        .monochrome = false,
        .color_format = LV_COLOR_FORMAT_RGB565,
        .rotation =
            {
                .swap_xy = true,
                .mirror_x = true,
                .mirror_y = true,
            },
        .flags =
            {
                .buff_dma = true,
                .swap_bytes = true,
            },
    };
    lv_display_t *disp = lvgl_port_add_disp(&disp_cfg);
    if (disp == NULL) {
        ESP_LOGE(TAG, "lvgl_port_add_disp failed");
        return NULL;
    }

    if (touch_init(disp) != ESP_OK) {
        ESP_LOGW(TAG, "touch init failed, display stays read-only");
    }
    ESP_LOGI(TAG, "display %dx%d ready", LCD_H_RES, LCD_V_RES);
    return disp;
}

bool wireless_ui_port_lock(uint32_t timeout_ms) {
    return lvgl_port_lock(timeout_ms);
}

void wireless_ui_port_unlock(void) {
    lvgl_port_unlock();
}

#endif  // CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
