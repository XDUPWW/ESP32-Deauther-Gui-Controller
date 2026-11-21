// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "wifi_frame/mac.h"

#include <stdio.h>
#include <string.h>

bool wf_mac_parse(const char *text, uint8_t out[6]) {
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

void wf_mac_format(char out[18], const uint8_t mac[6]) {
    if (out == NULL || mac == NULL) {
        return;
    }
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4],
             mac[5]);
}

void wf_mac_randomize(uint8_t out[6], uint64_t entropy) {
    if (out == NULL) {
        return;
    }
    for (int i = 0; i < 6; i++) {
        out[5 - i] = (uint8_t)(entropy >> (8 * i));
    }
    // bit0 = 0 单播, bit1 = 1 本地管理地址，避免撞真实厂商前缀
    out[0] = (uint8_t)((out[0] | 0x02) & 0xFE);
}

bool wf_mac_is_group(const uint8_t mac[6]) {
    return mac != NULL && (mac[0] & 0x01) != 0;
}

bool wf_mac_is_broadcast(const uint8_t mac[6]) {
    if (mac == NULL) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0xFF) {
            return false;
        }
    }
    return true;
}
