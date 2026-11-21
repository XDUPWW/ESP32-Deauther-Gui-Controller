// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "wireless_ui/wireless_ui.h"

bool wireless_ui_start(void) {
    return false;
}

bool wireless_ui_ready(void) {
    return false;
}

bool wireless_ui_selftest(int count) {
    (void)count;
    return false;
}

void wireless_ui_status(char *buf, size_t cap) {
    if (buf != NULL && cap > 0) {
        buf[0] = '\0';
    }
}

void wireless_ui_calib_reset(void) {
}

bool wireless_ui_touch_calib(bool reset) {
    (void)reset;
    return false;
}

void wireless_ui_touch_report(char *buf, size_t cap) {
    if (buf != NULL && cap > 0) {
        buf[0] = '\0';
    }
}

bool wireless_ui_tap(int x, int y) {
    (void)x;
    (void)y;
    return false;
}

void wireless_ui_dump(void) {
}
