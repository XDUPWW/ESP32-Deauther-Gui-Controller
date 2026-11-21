// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "ui_calib.h"

#include <math.h>
#include <string.h>

#include "esp_log.h"
#include "platform/plat_storage.h"

static const char *TAG = "ui_calib";
static const char *KEY = "touch_cal";

static int clamp_int(int value, int limit) {
    if (value < 0) {
        return 0;
    }
    if (value > limit) {
        return limit;
    }
    return value;
}

void ui_calib_defaults(ui_calib_t *calib) {
    if (calib == NULL) {
        return;
    }
    memset(calib, 0, sizeof(*calib));
    calib->valid = true;
    calib->axis_x = 1;
    calib->axis_y = 0;
    calib->off_x = 240.0f;
    calib->gain_x = (320.0f - 1.0f - 2.0f * UI_CALIB_INSET) / (3750.0f - 240.0f);
    calib->off_y = 200.0f;
    calib->gain_y = (240.0f - 1.0f - 2.0f * UI_CALIB_INSET) / (3700.0f - 200.0f);
    calib->inset = (float)UI_CALIB_INSET;
}

bool ui_calib_load(ui_calib_t *calib) {
    if (calib == NULL) {
        return false;
    }
    ui_calib_t tmp;
    if (!plat_storage_get(KEY, &tmp, sizeof(tmp)) || !tmp.valid) {
        return false;
    }
    *calib = tmp;
    ESP_LOGI(TAG, "calibration restored ax=%u ay=%u", tmp.axis_x, tmp.axis_y);
    return true;
}

void ui_calib_save(const ui_calib_t *calib) {
    if (calib == NULL) {
        return;
    }
    ui_calib_t tmp = *calib;
    tmp.valid = true;
    if (plat_storage_set(KEY, &tmp, sizeof(tmp)) != ESP_OK) {
        ESP_LOGW(TAG, "calibration save failed");
    }
}

void ui_calib_clear(void) {
    plat_storage_erase(KEY);
}

void ui_calib_apply(const ui_calib_t *calib, int raw_x, int raw_y, int width, int height,
                    int *screen_x, int *screen_y) {
    ui_calib_t fallback;
    if (calib == NULL || !calib->valid) {
        ui_calib_defaults(&fallback);
        calib = &fallback;
    }
    const float a = (calib->axis_x == 1) ? (float)raw_y : (float)raw_x;
    const float b = (calib->axis_y == 1) ? (float)raw_y : (float)raw_x;
    const float inset = (calib->inset > 0.0f) ? calib->inset : (float)UI_CALIB_INSET;
    const int sx = (int)lroundf(inset + (a - calib->off_x) * calib->gain_x);
    const int sy = (int)lroundf(inset + (b - calib->off_y) * calib->gain_y);
    if (screen_x != NULL) {
        *screen_x = clamp_int(sx, width - 1);
    }
    if (screen_y != NULL) {
        *screen_y = clamp_int(sy, height - 1);
    }
}
