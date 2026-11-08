#include "calib.h"

#include <math.h>
#include <string.h>

#include "esp_log.h"

static const char *TAG = "wui_calib";

static const wui_storage_ops_t *s_storage;

void wui_storage_set_ops(const wui_storage_ops_t *ops) {
    s_storage = ops;
}

void wui_calib_defaults(wui_calib_t *out) {
    if (out == NULL) {
        return;
    }
    out->valid = true;
    out->axis_x = 1;  // raw Y drives screen X on the CYD panel (swap_xy in HW)
    out->axis_y = 0;
    out->off_x = 240.0f;
    out->gain_x = (320.0f - 1.0f - 2.0f * WUI_CALIB_INSET) / (3750.0f - 240.0f);
    out->off_y = 200.0f;
    out->gain_y = (240.0f - 1.0f - 2.0f * WUI_CALIB_INSET) / (3700.0f - 200.0f);
    out->inset = (float)WUI_CALIB_INSET;
}

bool wui_calib_load(wui_calib_t *out) {
    if (out == NULL) {
        return false;
    }
    wui_calib_t tmp;
    if (s_storage == NULL || s_storage->load == NULL || !s_storage->load(&tmp, sizeof(tmp)) ||
        !tmp.valid) {
        return false;
    }
    *out = tmp;
    ESP_LOGI(TAG, "loaded calibration: ax=%u ay=%u", tmp.axis_x, tmp.axis_y);
    return true;
}

void wui_calib_save(const wui_calib_t *calib) {
    if (calib == NULL) {
        return;
    }
    wui_calib_t tmp = *calib;
    tmp.valid = true;
    if (s_storage != NULL && s_storage->save != NULL && s_storage->save(&tmp, sizeof(tmp))) {
        ESP_LOGW(TAG, "calibration saved ax=%u ay=%u gx=%.4f gy=%.4f", tmp.axis_x, tmp.axis_y, tmp.gain_x, tmp.gain_y);
    } else {
        ESP_LOGW(TAG, "calibration save failed");
    }
}

void wui_calib_clear(void) {
    if (s_storage != NULL && s_storage->clear != NULL) {
        s_storage->clear();
    }
}

static float edge_mean(const int16_t raw[4][2], int axis, int a, int b) {
    return ((float)raw[a][axis] + (float)raw[b][axis]) * 0.5f;
}

void wui_calib_solve(const int16_t raw[4][2], int16_t width, int16_t height, int16_t inset,
                     wui_calib_t *out) {
    if (raw == NULL || out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));

    // Which raw axis moves along the screen's X direction (top edge: 0 -> 1)?
    const float dx_x = fabsf((float)raw[1][0] - (float)raw[0][0]);
    const float dx_y = fabsf((float)raw[1][1] - (float)raw[0][1]);
    out->axis_x = (dx_y > dx_x) ? 1 : 0;
    out->axis_y = out->axis_x ? 0 : 1;

    const float x0 = edge_mean(raw, out->axis_x, 0, 3);  // left edge
    const float x1 = edge_mean(raw, out->axis_x, 1, 2);  // right edge
    const float y0 = edge_mean(raw, out->axis_y, 0, 1);  // top edge
    const float y1 = edge_mean(raw, out->axis_y, 3, 2);  // bottom edge

    const float span_x = (float)(width - 1 - 2 * inset);
    const float span_y = (float)(height - 1 - 2 * inset);
    out->off_x = x0;
    out->gain_x = (fabsf(x1 - x0) > 1.0f) ? span_x / (x1 - x0) : 0.0f;
    out->off_y = y0;
    out->gain_y = (fabsf(y1 - y0) > 1.0f) ? span_y / (y1 - y0) : 0.0f;
    out->inset = (float)inset;
    out->valid = (out->gain_x != 0.0f && out->gain_y != 0.0f);
    ESP_LOGW(TAG, "solved: ax=%u ay=%u gx=%.4f gy=%.4f", out->axis_x, out->axis_y, out->gain_x, out->gain_y);
}

static int clamp_int(int value, int limit) {
    if (value < 0) return 0;
    if (value > limit) return limit;
    return value;
}

void wui_calib_apply(const wui_calib_t *calib, int raw_x, int raw_y, int width, int height,
                     int *screen_x, int *screen_y) {
    if (calib == NULL || !calib->valid) {
        wui_calib_t fallback;
        wui_calib_defaults(&fallback);
        calib = &fallback;
    }
    const float a = (calib->axis_x == 1) ? (float)raw_y : (float)raw_x;
    const float b = (calib->axis_y == 1) ? (float)raw_y : (float)raw_x;
    const float inset = calib->inset > 0.0f ? calib->inset : (float)WUI_CALIB_INSET;
    const int sx = (int)lroundf(inset + (a - calib->off_x) * calib->gain_x);
    const int sy = (int)lroundf(inset + (b - calib->off_y) * calib->gain_y);
    if (screen_x) *screen_x = clamp_int(sx, width - 1);
    if (screen_y) *screen_y = clamp_int(sy, height - 1);
}
