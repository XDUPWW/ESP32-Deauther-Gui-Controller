// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "ble_frame/addr.h"

#include <stdio.h>

void bf_addr_random_static(uint8_t out[6], uint64_t entropy) {
    if (out == NULL) {
        return;
    }
    for (int i = 0; i < 6; i++) {
        out[5 - i] = (uint8_t)(entropy >> (8 * i));
    }
    // 最高两位必须 11，否则控制器会当成私有地址，广播行为不一样
    out[0] = (uint8_t)(out[0] | 0xC0);
}

bool bf_addr_is_random_static(const uint8_t addr[6]) {
    return addr != NULL && (addr[0] & 0xC0) == 0xC0;
}

const char *bf_addr_type_name(bf_addr_type_t type) {
    switch (type) {
        case BF_ADDR_PUBLIC:
            return "public";
        case BF_ADDR_RANDOM_STATIC:
            return "static";
        case BF_ADDR_RANDOM_RPA:
            return "rpa";
        case BF_ADDR_RANDOM_NRPA:
            return "nrpa";
        default:
            return "?";
    }
}

void bf_addr_format(char out[18], const uint8_t addr[6]) {
    if (out == NULL || addr == NULL) {
        return;
    }
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4],
             addr[5]);
}

bool bf_addr_parse(const char *text, uint8_t out[6]) {
    if (text == NULL || out == NULL) {
        return false;
    }
    unsigned int b[6];
    if (sscanf(text, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (b[i] > 0xFF) {
            return false;
        }
        out[i] = (uint8_t)b[i];
    }
    return true;
}
