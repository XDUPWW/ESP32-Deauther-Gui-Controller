// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ble_frame/adv.h"

// 弹窗模板：把"一条厂商数据 / 服务数据"抽象成表项，渲染时只补 AD 头。
// 模板本身不含 Flags，广播串由调用方决定前面要不要加。
typedef enum {
    BF_PLAT_APPLE = 0,
    BF_PLAT_SAMSUNG,
    BF_PLAT_GOOGLE,
    BF_PLAT_MICROSOFT,
    BF_PLAT_OTHER,
} bf_platform_t;

typedef struct {
    const char *name;         // 命令行用的名字，如 "apple_airpods"
    bf_platform_t platform;   // 目标平台，列表里给人看
    uint16_t company_id;      // 厂商数据用；0 表示走 service_uuid
    uint16_t service_uuid;    // 服务数据用；0 表示走厂商数据
    const uint8_t *body;      // 已去掉 AD 头和公司 ID
    uint8_t body_len;
    bool scan_rsp;            // true = 载荷放扫描响应，广播里只留 Flags
    bool connectable;         // 模板建议的广播类型
} bf_payload_t;

size_t bf_payload_count(void);

const bf_payload_t *bf_payload_at(size_t index);

// 名字不认识返回 NULL，调用方负责报错文案。
const bf_payload_t *bf_payload_find(const char *name);

const char *bf_platform_name(bf_platform_t platform);

// 渲染成一条 AD Structure。放不下（legacy 31 字节）返回 false 并置 truncated。
// 调用方自己决定 buf 容量，弹窗模板按 legacy 上限传即可。
bool bf_payload_render(const bf_payload_t *tpl, bf_adv_t *set);
