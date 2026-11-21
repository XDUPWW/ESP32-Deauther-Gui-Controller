// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 契约占位：除 probe request 外的帧构造在后续阶段实现，签名先固定下来。

#include "wifi_frame/frame_build.h"

#include <string.h>

static const uint8_t kRates[8] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
static const uint8_t kBroadcast[6] = WF_BROADCAST_ADDR_INIT;

static size_t put_ie(uint8_t *buf, size_t cap, size_t offset, uint8_t id, const uint8_t *body,
                     size_t len) {
    if (offset + 2 + len > cap) {
        return 0;
    }
    buf[offset++] = id;
    buf[offset++] = (uint8_t)len;
    if (len > 0 && body != NULL) {
        memcpy(buf + offset, body, len);
    }
    return offset + len;
}

int wf_build_probe_req(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                       const char *ssid, size_t ssid_len) {
    if (buf == NULL || da == NULL || sa == NULL || ssid_len > 32) {
        return -1;
    }
    if (cap < WF_MGMT_HDR_LEN + 2 + ssid_len + 2 + sizeof(kRates)) {
        return -1;
    }
    memset(buf, 0, WF_MGMT_HDR_LEN);
    buf[0] = WF_ST_PROBE_REQ;
    buf[1] = 0x00;
    memcpy(buf + 4, da, 6);
    memcpy(buf + 10, sa, 6);
    memcpy(buf + 16, kBroadcast, 6);

    size_t offset = WF_MGMT_HDR_LEN;
    offset = put_ie(buf, cap, offset, WF_IE_SSID, (const uint8_t *)ssid, ssid_len);
    if (offset == 0) {
        return -1;
    }
    offset = put_ie(buf, cap, offset, 1, kRates, sizeof(kRates));
    if (offset == 0) {
        return -1;
    }
    return (int)offset;
}

int wf_build_deauth(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                    const uint8_t bssid[6], uint16_t reason) {
    (void)buf, (void)cap, (void)da, (void)sa, (void)bssid, (void)reason;
    return -1;
}

int wf_build_disassoc(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                      const uint8_t bssid[6], uint16_t reason) {
    (void)buf, (void)cap, (void)da, (void)sa, (void)bssid, (void)reason;
    return -1;
}

int wf_build_auth(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                  const uint8_t bssid[6], uint16_t algorithm, uint16_t seq, uint16_t status) {
    (void)buf, (void)cap, (void)da, (void)sa, (void)bssid, (void)algorithm, (void)seq,
        (void)status;
    return -1;
}

int wf_build_assoc_req(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                       const uint8_t bssid[6], uint16_t capab, uint16_t listen_interval,
                       const uint8_t *ies, size_t ies_len) {
    (void)buf, (void)cap, (void)da, (void)sa, (void)bssid, (void)capab, (void)listen_interval,
        (void)ies, (void)ies_len;
    return -1;
}

int wf_build_beacon(uint8_t *buf, size_t cap, const uint8_t bssid[6], uint64_t tsf,
                    uint16_t interval, uint16_t capab, const uint8_t *ies, size_t ies_len) {
    (void)buf, (void)cap, (void)bssid, (void)tsf, (void)interval, (void)capab, (void)ies,
        (void)ies_len;
    return -1;
}

int wf_build_action(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                    const uint8_t bssid[6], uint8_t category, const uint8_t *body,
                    size_t body_len) {
    (void)buf, (void)cap, (void)da, (void)sa, (void)bssid, (void)category, (void)body,
        (void)body_len;
    return -1;
}

int wf_build_data(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                  const uint8_t bssid[6], bool tods, bool fromds, bool qos, uint8_t tid,
                  const uint8_t *payload, size_t payload_len) {
    (void)buf, (void)cap, (void)da, (void)sa, (void)bssid, (void)tods, (void)fromds, (void)qos,
        (void)tid, (void)payload, (void)payload_len;
    return -1;
}

int wf_build_null_data(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                       const uint8_t bssid[6], bool qos, bool pm_bit) {
    (void)buf, (void)cap, (void)da, (void)sa, (void)bssid, (void)qos, (void)pm_bit;
    return -1;
}

int wf_build_llc_snap(uint8_t *buf, size_t cap, uint16_t ethertype, const uint8_t *payload,
                      size_t payload_len) {
    (void)buf, (void)cap, (void)ethertype, (void)payload, (void)payload_len;
    return -1;
}

int wf_build_bar(uint8_t *buf, size_t cap, const uint8_t ra[6], const uint8_t ta[6], uint8_t tid,
                 uint16_t ssn) {
    if (buf == NULL || ra == NULL || ta == NULL || cap < 20) {
        return -1;
    }
    memset(buf, 0, 20);
    buf[0] = WF_ST_BAR;
    buf[1] = 0x00;
    memcpy(buf + 4, ra, 6);
    memcpy(buf + 10, ta, 6);
    // BAR Control: bit2 = compressed bitmap, bits12..15 = TID_INFO
    const uint16_t control = (uint16_t)(0x0004 | ((tid & 0x0F) << 12));
    wf_put_le16(buf + 16, control);
    // Starting Sequence Control: 12-bit sequence number in bits4..15
    wf_put_le16(buf + 18, (uint16_t)((ssn & 0x0FFF) << 4));
    return 20;
}

int wf_build_rts(uint8_t *buf, size_t cap, const uint8_t ra[6], const uint8_t ta[6],
                 uint16_t duration) {
    (void)buf, (void)cap, (void)ra, (void)ta, (void)duration;
    return -1;
}
