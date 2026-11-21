// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WF_FC_TYPE_MGMT 0x00
#define WF_FC_TYPE_CTRL 0x04
#define WF_FC_TYPE_DATA 0x08

#define WF_ST_ASSOC_REQ 0x00
#define WF_ST_ASSOC_RESP 0x10
#define WF_ST_PROBE_REQ 0x40
#define WF_ST_PROBE_RESP 0x50
#define WF_ST_BEACON 0x80
#define WF_ST_DISASSOC 0xA0
#define WF_ST_AUTH 0xB0
#define WF_ST_DEAUTH 0xC0
#define WF_ST_ACTION 0xD0

#define WF_ST_PSPOLL 0xA4
#define WF_ST_RTS 0xB4
#define WF_ST_BAR 0x84

#define WF_ST_QOS_DATA 0x88
#define WF_ST_QOS_NULL 0xC8

#define WF_MGMT_HDR_LEN 24
#define WF_CTRL_HDR_LEN 10
#define WF_DATA_HDR_LEN 24
#define WF_QOS_HDR_LEN 26
#define WF_LLC_SNAP_LEN 8

#define WF_IE_SSID 0
#define WF_IE_SUPPORTED_RATES 1
#define WF_IE_DS_PARAMS 3
#define WF_IE_TIM 5
#define WF_IE_CSA 37
#define WF_IE_RSN 48
#define WF_IE_EXT_CAP 127

#define WF_AKM_PSK 2
#define WF_AKM_SAE 8

#define WF_BROADCAST_ADDR_INIT \
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }

// 驱动给的注入上限就是 1500（esp_wifi_80211_tx 的注释写死 len <= 1500）。
// 这里跟驱动对齐，evil twin 克隆完整 beacon（RSN + CSA + TIM + 多个 vendor IE）
// 才装得下。之前定成 512 是自己给自己上镣铐。
#define WF_FRAME_CAP 1500

typedef struct {
    uint8_t frame[WF_FRAME_CAP];
    size_t len;
} wf_frame_t;

static inline uint16_t wf_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline void wf_put_le16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value & 0xFF);
    p[1] = (uint8_t)(value >> 8);
}

static inline bool wf_is_broadcast(const uint8_t mac[6]) {
    return mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF && mac[3] == 0xFF && mac[4] == 0xFF &&
           mac[5] == 0xFF;
}
