// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

// 这里的地址一律按人读顺序放：addr[0] 是最高有效字节，和 "aa:bb:cc:dd:ee:ff"
// 写出来一致。空口和 NimBLE 是反过来的（LSB 在前），转换在 hal_ble 里做一次。

// BLE 地址类型。public 是烧在芯片里的，random 分两种：
// static（最高两位 11）和 private（最高两位 00 或 01，会自己变）。
// Core Spec Vol 6 Part B §1.3。
typedef enum {
    BF_ADDR_PUBLIC = 0,
    BF_ADDR_RANDOM_STATIC = 1,
    BF_ADDR_RANDOM_RPA = 2,   // 可解析私有地址，最高两位 01
    BF_ADDR_RANDOM_NRPA = 3,  // 不可解析私有地址，最高两位 00
} bf_addr_type_t;

// 按 static random 的规矩造一个：最高两位强制 11。
// 注意和 WiFi 的本地管理地址不是一回事，WiFi 是动 bit1。
void bf_addr_random_static(uint8_t out[6], uint64_t entropy);

// 光看地址只能判它符不符合 random static 的格式，分不出 public/random，
// 那是链路层 PDU 里的标记。所以这里只回答"像不像 static"。
bool bf_addr_is_random_static(const uint8_t addr[6]);

const char *bf_addr_type_name(bf_addr_type_t type);

void bf_addr_format(char out[18], const uint8_t addr[6]);

bool bf_addr_parse(const char *text, uint8_t out[6]);
