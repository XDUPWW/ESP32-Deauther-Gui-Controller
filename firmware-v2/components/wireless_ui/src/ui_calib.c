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
    // 本机 CYD 实测：屏的 X 取 raw_x，两个轴都是反向的
    calib->axis_x = 0;
    calib->axis_y = 1;
    calib->off_x = 3249.0f;
    calib->gain_x = -0.0933f;
    calib->off_y = 3280.0f;
    calib->gain_y = -0.0693f;
    calib->inset = (float)UI_CALIB_INSET;
}

static float edge_mean(const int16_t raw[4][2], int axis, int a, int b) {
    return ((float)raw[a][axis] + (float)raw[b][axis]) * 0.5f;
}

bool ui_calib_solve(const int16_t raw[4][2], int16_t width, int16_t height, int16_t inset,
                    ui_calib_t *calib) {
    if (raw == NULL || calib == NULL) {
        return false;
    }
    memset(calib, 0, sizeof(*calib));

    // 上边两点哪个轴的跨度大，那个轴就是屏的 X 方向
    const float dx_x = fabsf((float)raw[1][0] - (float)raw[0][0]);
    const float dx_y = fabsf((float)raw[1][1] - (float)raw[0][1]);
    calib->axis_x = (dx_y > dx_x) ? 1 : 0;
    calib->axis_y = calib->axis_x ? 0 : 1;

    const float x0 = edge_mean(raw, calib->axis_x, 0, 3);  // 左边缘
    const float x1 = edge_mean(raw, calib->axis_x, 1, 2);  // 右边缘
    const float y0 = edge_mean(raw, calib->axis_y, 0, 1);  // 上边缘
    const float y1 = edge_mean(raw, calib->axis_y, 3, 2);  // 下边缘

    const float span_x = (float)(width - 1 - 2 * inset);
    const float span_y = (float)(height - 1 - 2 * inset);
    calib->off_x = x0;
    calib->gain_x = (fabsf(x1 - x0) > 1.0f) ? span_x / (x1 - x0) : 0.0f;
    calib->off_y = y0;
    calib->gain_y = (fabsf(y1 - y0) > 1.0f) ? span_y / (y1 - y0) : 0.0f;
    calib->inset = (float)inset;
    calib->valid = (calib->gain_x != 0.0f && calib->gain_y != 0.0f);
    ESP_LOGI(TAG, "solve ax=%u ay=%u gx=%.4f gy=%.4f", calib->axis_x, calib->axis_y,
             calib->gain_x, calib->gain_y);
    return calib->valid;
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
