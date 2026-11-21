// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

// 广播间隔单位 0.625ms。规范下限 100ms，上限 10.24s。
#define HAL_BLE_ITVL_MIN 160
#define HAL_BLE_ITVL_MAX 16384

// 扫描表容量
#define HAL_BLE_PEER_MAX 32

// legacy 广播 31 字节；扩展广播 255，只有 BLE 5.0 的芯片（C5/C6/S3）能发。
#define HAL_BLE_ADV_LEGACY_MAX 31
#define HAL_BLE_ADV_EXT_MAX 255

typedef struct {
    uint8_t addr[6];     // 人读顺序，和 ble_frame 一致
    uint8_t addr_type;   // 0 public / 1 random
    uint8_t evt_type;    // HCI 的 adv report 类型：0 可连可扫、1 直连、2 可扫、3 不可连、4 扫描响应
    int8_t rssi;
    uint8_t data_len;
    uint8_t data[HAL_BLE_ADV_LEGACY_MAX];
} hal_ble_peer_t;

typedef struct {
    uint32_t adv_starts;
    uint32_t adv_errors;
    uint32_t scan_reports;
    uint32_t job_timeouts;      // 投给 host 任务却没在超时内回来的次数
    uint32_t heap_after_init;   // NimBLE 起来之后剩多少堆，用来量它吃了多少
    int32_t last_rc;            // 最后一次 NimBLE 返回码
} hal_ble_stats_t;

// 拉控制器和 NimBLE host。NVS 要先初始化好，控制器校准数据存在那里。
// 重复调用是安全的，只有第一次真的做事。
esp_err_t hal_ble_init(void);

// 等 host 跟控制器同步完才算就绪。同步是异步的，init 返回不代表能用。
bool hal_ble_ready(void);

// 设成随机静态地址（最高两位会被强制置 11）。设之前最好先停广播。
esp_err_t hal_ble_addr_set(const uint8_t addr[6]);

// 拿当前在用的地址。addr_type 传 NULL 也可以。
esp_err_t hal_ble_addr_get(uint8_t out[6], uint8_t *addr_type);

// 直接给整串 AD Structure，不做二次加工。
// legacy 上限 31 字节，超了 NimBLE 会返回错误。
esp_err_t hal_ble_adv_set(const uint8_t *data, size_t len);

// 间隔单位 0.625ms，传 0 就用默认 100ms。connectable=false 走不可连接广播。
esp_err_t hal_ble_adv_start(uint16_t itvl_min, uint16_t itvl_max, bool connectable);

esp_err_t hal_ble_adv_stop(void);

bool hal_ble_adv_running(void);

// duration_ms 传 0 表示一直扫下去。扫描期间新出现的设备进 peer 表。
esp_err_t hal_ble_scan_start(uint32_t duration_ms);

esp_err_t hal_ble_scan_stop(void);

bool hal_ble_scan_running(void);

size_t hal_ble_scan_count(void);

// 表中第 index 条，越界返回 NULL。返回的指针在下一次扫描回调写表时可能变，
// 要用就当场读完。
const hal_ble_peer_t *hal_ble_scan_at(size_t index);

void hal_ble_scan_clear(void);

void hal_ble_stats(hal_ble_stats_t *out);

// ---- GATT 串口 ----
// 一对特征：手机往 RX 写命令，板子从 TX 通知回话。UUID 用 Nordic UART 那一套，
// 手机端现成的 BLE 串口 App 直接能认。
#define HAL_BLE_GATT_RX_CAP 512

typedef void (*hal_ble_gatt_conn_fn)(bool connected);

// 注册服务 + 起来广播。device_name 为空就用 "AirBench"。
// 跟 hal_ble_adv_set/start 是两条路：这个自己拼广播包，含服务 UUID 和名字。
esp_err_t hal_ble_gatt_start(const char *device_name, hal_ble_gatt_conn_fn conn_cb);

bool hal_ble_gatt_connected(void);

// 非阻塞读手机写过来的字节，返回读到的数量。拼行交给调用方。
int hal_ble_gatt_read(uint8_t *out, size_t cap);

// 发一行，按当前 MTU 自动分片。没连上或者对方没开通知就返回 ESP_ERR_INVALID_STATE。
esp_err_t hal_ble_gatt_send(const char *text);

// 协商出来的 MTU，没连接时返回 23。
uint16_t hal_ble_gatt_mtu(void);
