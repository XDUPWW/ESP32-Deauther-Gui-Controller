// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "ble_frame/adv.h"

#include <stdio.h>
#include <string.h>

void bf_adv_init(bf_adv_t *set, uint8_t *buf, size_t cap) {
    if (set == NULL) {
        return;
    }
    set->buf = buf;
    set->cap = cap;
    set->len = 0;
    set->truncated = false;
}

static bool ad_room(const bf_adv_t *set, size_t payload) {
    if (set == NULL || set->buf == NULL || payload > BF_AD_MAX - 1) {
        return false;
    }
    if (set->len > set->cap) {
        return false;
    }
    return payload + 2 <= set->cap - set->len;
}

static bool ad_push(bf_adv_t *set, uint8_t type, const uint8_t *data, size_t n) {
    if (set == NULL || !ad_room(set, n)) {
        if (set != NULL) {
            set->truncated = true;
        }
        return false;
    }
    uint8_t *p = set->buf + set->len;
    p[0] = (uint8_t)(n + 1);
    p[1] = type;
    if (n > 0) {
        memcpy(p + 2, data, n);
    }
    set->len += n + 2;
    return true;
}

bool bf_adv_flags(bf_adv_t *set, uint8_t flags) {
    return ad_push(set, BF_AD_FLAGS, &flags, 1);
}

bool bf_adv_uuid16(bf_adv_t *set, uint16_t uuid, bool complete) {
    // 蓝牙在空口上一律小端
    const uint8_t raw[2] = {(uint8_t)(uuid & 0xFF), (uint8_t)(uuid >> 8)};
    return ad_push(set, complete ? BF_AD_UUID16_COMPLETE : BF_AD_UUID16_INCOMPLETE, raw, 2);
}

bool bf_adv_uuid128(bf_adv_t *set, const uint8_t uuid[16], bool complete) {
    if (uuid == NULL) {
        return false;
    }
    uint8_t raw[16];
    for (int i = 0; i < 16; i++) {
        raw[i] = uuid[15 - i];
    }
    return ad_push(set, complete ? BF_AD_UUID128_COMPLETE : BF_AD_UUID128_INCOMPLETE, raw, 16);
}

bool bf_adv_name(bf_adv_t *set, const char *name, bool truncate) {
    if (name == NULL) {
        return false;
    }
    const bool was_truncated = set->truncated;
    const size_t n = strlen(name);
    if (ad_push(set, BF_AD_NAME_COMPLETE, (const uint8_t *)name, n)) {
        return true;
    }
    if (!truncate) {
        return false;
    }
    // 完整名塞不下，退成短名。短名本身就是"这不是完整名"的标记，不算事故。
    set->truncated = was_truncated;
    if (set->len + 3 > set->cap) {
        set->truncated = true;
        return false;
    }
    const size_t room = set->cap - set->len - 2;
    const size_t take = (n < room) ? n : room;
    return ad_push(set, BF_AD_NAME_SHORT, (const uint8_t *)name, take);
}

bool bf_adv_tx_power(bf_adv_t *set, int8_t dbm) {
    const uint8_t raw = (uint8_t)dbm;
    return ad_push(set, BF_AD_TX_POWER, &raw, 1);
}

bool bf_adv_service_data16(bf_adv_t *set, uint16_t uuid, const uint8_t *data, size_t n) {
    if (set == NULL || (data == NULL && n > 0)) {
        return false;
    }
    if (n + 3 > BF_AD_MAX) {
        set->truncated = true;
        return false;
    }
    // 类型 0x16 后面跟 UUID(2，小端) + 数据(n)，ad_push 负责补长度字节
    uint8_t raw[BF_AD_MAX];
    raw[0] = (uint8_t)(uuid & 0xFF);
    raw[1] = (uint8_t)(uuid >> 8);
    if (n > 0) {
        memcpy(raw + 2, data, n);
    }
    return ad_push(set, BF_AD_SERVICE_DATA16, raw, n + 2);
}

bool bf_adv_mfr(bf_adv_t *set, uint16_t company_id, const uint8_t *data, size_t n) {
    if (set == NULL || (data == NULL && n > 0)) {
        return false;
    }
    // 一条 AD 装 company id(2) + 数据(n)，长度字段是 n+3
    if (n + 3 > BF_AD_MAX || !ad_room(set, n + 2)) {
        set->truncated = true;
        return false;
    }
    uint8_t *p = set->buf + set->len;
    p[0] = (uint8_t)(n + 3);
    p[1] = BF_AD_MFR;
    p[2] = (uint8_t)(company_id & 0xFF);
    p[3] = (uint8_t)(company_id >> 8);
    if (n > 0) {
        memcpy(p + 4, data, n);
    }
    set->len += n + 4;
    return true;
}

size_t bf_adv_len(const bf_adv_t *set) {
    return (set == NULL) ? 0 : set->len;
}

void bf_hex(const uint8_t *data, size_t len, char *out, size_t cap) {
    if (out == NULL || cap == 0) {
        return;
    }
    out[0] = 0;
    if (data == NULL) {
        return;
    }
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        const int wrote = snprintf(out + pos, cap - pos, "%02x", data[i]);
        if (wrote <= 0 || (size_t)wrote >= cap - pos) {
            break;
        }
        pos += (size_t)wrote;
    }
}

void bf_adv_hex(const bf_adv_t *set, char *out, size_t cap) {
    if (out == NULL || cap == 0) {
        return;
    }
    out[0] = 0;
    if (set == NULL) {
        return;
    }
    bf_hex(set->buf, set->len, out, cap);
}
