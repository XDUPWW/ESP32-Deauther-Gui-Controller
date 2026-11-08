#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Touch taps are taken this far inside the screen edges during calibration.
#define WUI_CALIB_INSET 20

// Touch calibration: an axis-aligned linear mapping from the XPT2046 raw values
// to screen pixels, solved from four corner taps and persisted in NVS.

typedef struct {
    bool valid;
    uint8_t axis_x;  // 0 = raw X drives screen X, 1 = raw Y drives screen X
    uint8_t axis_y;
    float off_x;
    float gain_x;
    float off_y;
    float gain_y;
    float inset;
} wui_calib_t;

// Persistence hooks, injected by the application.
typedef struct {
    bool (*load)(void *out, size_t len);
    bool (*save)(const void *in, size_t len);
    void (*clear)(void);
} wui_storage_ops_t;

void wui_storage_set_ops(const wui_storage_ops_t *ops);

// Fallback mapping used when the board has never been calibrated.
void wui_calib_defaults(wui_calib_t *out);

bool wui_calib_load(wui_calib_t *out);
void wui_calib_save(const wui_calib_t *calib);
void wui_calib_clear(void);

// raw[i] holds the raw X/Y captured at corner i, in display order:
// 0 = top-left, 1 = top-right, 2 = bottom-right, 3 = bottom-left.
void wui_calib_solve(const int16_t raw[4][2], int16_t width, int16_t height, int16_t inset,
                     wui_calib_t *out);

void wui_calib_apply(const wui_calib_t *calib, int raw_x, int raw_y, int width, int height,
                     int *screen_x, int *screen_y);
