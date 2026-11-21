// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

// Unicast injections are paced: the 32-frame pool fills up and the next
// esp_wifi_80211_tx() returns 0x101, which kills every later WiFi call.
#define HAL_WIFI_UNICAST_GAP_MS 45

#define HAL_WIFI_CHANNEL_MAX 196
#define HAL_WIFI_OWNER_MAX 16
#define HAL_WIFI_SCAN_MAX 16

typedef enum {
    HAL_CH_PINNED = 0,   // 钉在一条信道上（多数攻击）
    HAL_CH_ROAMING = 1,  // 自己决定跳哪条（deauth 跳信道、被动扫描）
} hal_ch_mode_t;

// 注入速率。esp_wifi_config_80211_tx_rate() 是按接口全局生效的，
// 设了以后我们自己 STA 侧的管理帧也一起变。
typedef enum {
    HAL_RATE_DEFAULT = 0,
    HAL_RATE_1M,
    HAL_RATE_2M,
    HAL_RATE_5M5,
    HAL_RATE_11M,
    HAL_RATE_6M,
    HAL_RATE_9M,
    HAL_RATE_12M,
    HAL_RATE_18M,
    HAL_RATE_24M,
    HAL_RATE_36M,
    HAL_RATE_48M,
    HAL_RATE_54M,
} hal_rate_t;

typedef struct {
    uint32_t tx_ok;
    uint32_t tx_err;
    uint32_t tx_throttled;
    uint32_t rx_frames;
    uint32_t rx_dropped;
    uint32_t rx_too_long;
    uint32_t chan_granted;
    uint32_t chan_denied;
    uint32_t chan_expired;
    int32_t last_tx_err;
} hal_wifi_stats_t;

typedef struct {
    bool promiscuous;
    uint32_t filter_mask;
    uint32_t ctrl_filter_mask;
    uint8_t channel;
    char country[3];
    uint8_t country_nchan;
} hal_wifi_diag_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t channel;
    int8_t rssi;
    uint8_t authmode;
    char ssid[33];
} hal_scan_ap_t;

// len 是驱动给的 sig_len，含 4 字节 FCS（IDF 6.1 头文件明确写了），
// 需要真实帧长自己减 4。
typedef void (*hal_wifi_rx_fn)(const uint8_t *frame, uint16_t len, int8_t rssi, uint8_t channel,
                               void *ctx);

esp_err_t hal_wifi_init(void);

esp_err_t hal_wifi_set_country(const char *cc, uint8_t nchan, int8_t max_dbm, bool manual);

esp_err_t hal_wifi_set_band_auto(bool enable);

esp_err_t hal_wifi_mac(uint8_t out[6]);

esp_err_t hal_wifi_set_tx_rate(hal_rate_t rate);

hal_rate_t hal_wifi_tx_rate(void);

const char *hal_wifi_rate_name(hal_rate_t rate);

esp_err_t hal_wifi_channel_acquire(const char *owner, hal_ch_mode_t mode, uint8_t channel,
                                   uint32_t hold_ms);

esp_err_t hal_wifi_channel_select(const char *owner, uint8_t channel);

void hal_wifi_channel_release(const char *owner);

void hal_wifi_channel_tick(uint32_t now_ms);

uint8_t hal_wifi_channel(void);

const char *hal_wifi_channel_owner(void);

esp_err_t hal_wifi_tx(const uint8_t *frame, uint16_t len);

#define HAL_WIFI_RX_SUBS 4

esp_err_t hal_wifi_rx_subscribe(hal_wifi_rx_fn fn, void *ctx);

esp_err_t hal_wifi_rx_unsubscribe(hal_wifi_rx_fn fn);

esp_err_t hal_wifi_rx_set_filter(bool mgmt, bool ctrl, bool data);

esp_err_t hal_wifi_sniffer_enable(bool enable);

esp_err_t hal_wifi_scan_blocking(uint8_t dwell_ms);

uint32_t hal_wifi_scan_count(void);

const hal_scan_ap_t *hal_wifi_scan_at(uint32_t index);

esp_err_t hal_wifi_ap_start(const char *ssid, const char *password, uint8_t channel);

esp_err_t hal_wifi_ap_stop(void);

uint64_t hal_wifi_tsf(void);

void hal_wifi_stats(hal_wifi_stats_t *out);

void hal_wifi_diag(hal_wifi_diag_t *out);
