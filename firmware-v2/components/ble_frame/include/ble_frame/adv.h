// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// 广播数据是一串 AD Structure，每条 = 长度(1) + 类型(1) + 数据(N)。
// 长度字段把类型字节也算进去，所以单条上限 255 字节。
#define BF_AD_MAX 255

// 总量上限：4.2 只能 legacy 广播，31 字节封顶；5.0 的扩展广播能到 255。
#define BF_ADV_LEGACY_MAX 31
#define BF_ADV_EXT_MAX 255

// AD Type 编号，取自 Bluetooth Assigned Numbers。
#define BF_AD_FLAGS 0x01
#define BF_AD_UUID16_INCOMPLETE 0x02
#define BF_AD_UUID16_COMPLETE 0x03
#define BF_AD_UUID128_INCOMPLETE 0x06
#define BF_AD_UUID128_COMPLETE 0x07
#define BF_AD_NAME_SHORT 0x08
#define BF_AD_NAME_COMPLETE 0x09
#define BF_AD_TX_POWER 0x0A
#define BF_AD_MFR 0xFF

// Flags 各个位，Core Spec Vol 3 Part C §11.2.3.1。
#define BF_FLAG_LIMITED_DISC 0x01
#define BF_FLAG_GENERAL_DISC 0x02
#define BF_FLAG_NO_BREDR 0x04
#define BF_FLAG_CTRL_SIMUL 0x08
#define BF_FLAG_HOST_SIMUL 0x10

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool truncated;   // 有函数因为放不下被拒了
} bf_adv_t;

void bf_adv_init(bf_adv_t *set, uint8_t *buf, size_t cap);

bool bf_adv_flags(bf_adv_t *set, uint8_t flags);

// complete=true 用 0x03/0x07，false 用 0x02/0x06。UUID 按蓝牙惯例小端写。
bool bf_adv_uuid16(bf_adv_t *set, uint16_t uuid, bool complete);
bool bf_adv_uuid128(bf_adv_t *set, const uint8_t uuid[16], bool complete);

// truncate=true 时放不下就退成 0x08 短名，能塞几个字节塞几个。
bool bf_adv_name(bf_adv_t *set, const char *name, bool truncate);

bool bf_adv_tx_power(bf_adv_t *set, int8_t dbm);

// 厂商自定义数据，company_id 是 Bluetooth SIG 分配的小端编号（Apple 0x004C）。
bool bf_adv_mfr(bf_adv_t *set, uint16_t company_id, const uint8_t *data, size_t n);

size_t bf_adv_len(const bf_adv_t *set);

// 把整串 AD 写成十六进制，给串口看。out 至少 2*len+1。
void bf_adv_hex(const bf_adv_t *set, char *out, size_t cap);

// 裸字节转十六进制，扫描结果之类的地方也要用。
void bf_hex(const uint8_t *data, size_t len, char *out, size_t cap);
