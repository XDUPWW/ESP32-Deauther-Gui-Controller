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
