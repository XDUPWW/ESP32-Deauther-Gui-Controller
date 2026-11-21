// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

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

// 24 字节管理头，序列号留 0；duration 也留 0，反正 MAC 会重写
static size_t mgmt_header(uint8_t *buf, size_t cap, uint8_t fc0, const uint8_t a1[6],
                          const uint8_t a2[6], const uint8_t a3[6]) {
    if (buf == NULL || a1 == NULL || a2 == NULL || a3 == NULL || cap < WF_MGMT_HDR_LEN) {
        return 0;
    }
    memset(buf, 0, WF_MGMT_HDR_LEN);
    buf[0] = fc0;
    memcpy(buf + 4, a1, 6);
    memcpy(buf + 10, a2, 6);
    memcpy(buf + 16, a3, 6);
    return WF_MGMT_HDR_LEN;
}

int wf_build_deauth(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                    const uint8_t bssid[6], uint16_t reason) {
    size_t off = mgmt_header(buf, cap, WF_ST_DEAUTH, da, sa, bssid);
    if (off == 0 || off + 2 > cap) {
        return -1;
    }
    wf_put_le16(buf + off, reason);
    return (int)(off + 2);
}

int wf_build_disassoc(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                      const uint8_t bssid[6], uint16_t reason) {
    size_t off = mgmt_header(buf, cap, WF_ST_DISASSOC, da, sa, bssid);
    if (off == 0 || off + 2 > cap) {
        return -1;
    }
    wf_put_le16(buf + off, reason);
    return (int)(off + 2);
}

int wf_build_auth(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                  const uint8_t bssid[6], uint16_t algorithm, uint16_t seq, uint16_t status) {
    return wf_build_auth_ext(buf, cap, da, sa, bssid, algorithm, seq, status, NULL, 0);
}

int wf_build_auth_ext(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                      const uint8_t bssid[6], uint16_t algorithm, uint16_t seq, uint16_t status,
                      const uint8_t *extra, size_t extra_len) {
    size_t off = mgmt_header(buf, cap, WF_ST_AUTH, da, sa, bssid);
    if (off == 0 || off + 6 + extra_len > cap) {
        return -1;
    }
    wf_put_le16(buf + off, algorithm);
    wf_put_le16(buf + off + 2, seq);
    wf_put_le16(buf + off + 4, status);
    off += 6;
    if (extra_len > 0 && extra != NULL) {
        memcpy(buf + off, extra, extra_len);
    }
    return (int)(off + extra_len);
}

int wf_build_assoc_req(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                       const uint8_t bssid[6], uint16_t capab, uint16_t listen_interval,
                       const uint8_t *ies, size_t ies_len) {
    size_t off = mgmt_header(buf, cap, WF_ST_ASSOC_REQ, da, sa, bssid);
    if (off == 0 || off + 4 + ies_len > cap) {
        return -1;
    }
    wf_put_le16(buf + off, capab);
    wf_put_le16(buf + off + 2, listen_interval);
    off += 4;
    if (ies_len > 0 && ies != NULL) {
        memcpy(buf + off, ies, ies_len);
    }
    return (int)(off + ies_len);
}

int wf_build_probe_req(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                       const char *ssid, size_t ssid_len) {
    if (ssid_len > 32) {
        return -1;
    }
    size_t off = mgmt_header(buf, cap, WF_ST_PROBE_REQ, da, sa, kBroadcast);
    if (off == 0) {
        return -1;
    }
    off = put_ie(buf, cap, off, WF_IE_SSID, (const uint8_t *)ssid, ssid_len);
    if (off == 0) {
        return -1;
    }
    off = put_ie(buf, cap, off, WF_IE_SUPPORTED_RATES, kRates, sizeof(kRates));
    return (off == 0) ? -1 : (int)off;
}

int wf_build_beacon(uint8_t *buf, size_t cap, const uint8_t bssid[6], uint64_t tsf,
                    uint16_t interval, uint16_t capab, const uint8_t *ies, size_t ies_len) {
    size_t off = mgmt_header(buf, cap, WF_ST_BEACON, kBroadcast, bssid, bssid);
    if (off == 0 || off + 12 + ies_len > cap) {
        return -1;
    }
    for (int i = 0; i < 8; i++) {
        buf[off + i] = (uint8_t)(tsf >> (8 * i));
    }
    wf_put_le16(buf + off + 8, interval);
    wf_put_le16(buf + off + 10, capab);
    off += 12;
    if (ies_len > 0 && ies != NULL) {
        memcpy(buf + off, ies, ies_len);
    }
    return (int)(off + ies_len);
}

int wf_build_probe_resp(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t bssid[6],
                        uint64_t tsf, uint16_t interval, uint16_t capab, const uint8_t *ies,
                        size_t ies_len) {
    size_t off = mgmt_header(buf, cap, WF_ST_PROBE_RESP, da, bssid, bssid);
    if (off == 0 || off + 12 + ies_len > cap) {
        return -1;
    }
    for (int i = 0; i < 8; i++) {
        buf[off + i] = (uint8_t)(tsf >> (8 * i));
    }
    wf_put_le16(buf + off + 8, interval);
    wf_put_le16(buf + off + 10, capab);
    off += 12;
    if (ies_len > 0 && ies != NULL) {
        memcpy(buf + off, ies, ies_len);
    }
    return (int)(off + ies_len);
}

int wf_build_action(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                    const uint8_t bssid[6], uint8_t category, const uint8_t *body,
                    size_t body_len) {
    size_t off = mgmt_header(buf, cap, WF_ST_ACTION, da, sa, bssid);
    if (off == 0 || off + 1 + body_len > cap) {
        return -1;
    }
    buf[off++] = category;
    if (body_len > 0 && body != NULL) {
        memcpy(buf + off, body, body_len);
    }
    return (int)(off + body_len);
}

int wf_build_data(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                  const uint8_t bssid[6], bool tods, bool fromds, bool qos, uint8_t tid,
                  const uint8_t *payload, size_t payload_len) {
    if (da == NULL || sa == NULL || bssid == NULL || (tods && fromds)) {
        return -1;
    }
    const size_t header_len = WF_DATA_HDR_LEN + (qos ? 2 : 0);
    if (cap < header_len + payload_len) {
        return -1;
    }
    memset(buf, 0, header_len);
    buf[0] = qos ? WF_ST_QOS_DATA : 0x08;
    if (tods) {
        buf[1] |= 0x01;
    }
    if (fromds) {
        buf[1] |= 0x02;
    }
    if (tods) {
        memcpy(buf + 4, bssid, 6);   // RA = AP
        memcpy(buf + 10, sa, 6);     // TA = 源
        memcpy(buf + 16, da, 6);     // DA
    } else {
        memcpy(buf + 4, da, 6);
        memcpy(buf + 10, bssid, 6);
        memcpy(buf + 16, sa, 6);
    }
    if (qos) {
        wf_put_le16(buf + WF_DATA_HDR_LEN, (uint16_t)(tid & 0x0F));
    }
    if (payload_len > 0 && payload != NULL) {
        memcpy(buf + header_len, payload, payload_len);
    }
    return (int)(header_len + payload_len);
}

int wf_build_null_data(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                       const uint8_t bssid[6], bool qos, bool pm_bit) {
    const size_t header_len = WF_DATA_HDR_LEN + (qos ? 2 : 0);
    if (da == NULL || sa == NULL || bssid == NULL || cap < header_len) {
        return -1;
    }
    memset(buf, 0, header_len);
    buf[0] = qos ? WF_ST_QOS_NULL : 0x48;
    buf[1] = 0x01;  // ToDS
    if (pm_bit) {
        buf[1] |= 0x10;
    }
    memcpy(buf + 4, bssid, 6);
    memcpy(buf + 10, sa, 6);
    memcpy(buf + 16, da, 6);
    return (int)header_len;
}

int wf_build_llc_snap(uint8_t *buf, size_t cap, uint16_t ethertype, const uint8_t *payload,
                      size_t payload_len) {
    if (buf == NULL || cap < WF_LLC_SNAP_LEN + payload_len) {
        return -1;
    }
    buf[0] = 0xAA;
    buf[1] = 0xAA;
    buf[2] = 0x03;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x00;
    buf[6] = (uint8_t)(ethertype >> 8);
    buf[7] = (uint8_t)(ethertype & 0xFF);
    if (payload_len > 0 && payload != NULL) {
        memcpy(buf + WF_LLC_SNAP_LEN, payload, payload_len);
    }
    return (int)(WF_LLC_SNAP_LEN + payload_len);
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
    wf_put_le16(buf + 16, (uint16_t)(0x0004 | ((tid & 0x0F) << 12)));
    // Starting Sequence Control: 12 位序列号在 bits4..15
    wf_put_le16(buf + 18, (uint16_t)((ssn & 0x0FFF) << 4));
    return 20;
}

int wf_build_rts(uint8_t *buf, size_t cap, const uint8_t ra[6], const uint8_t ta[6],
                 uint16_t duration) {
    if (buf == NULL || ra == NULL || ta == NULL || cap < 16) {
        return -1;
    }
    memset(buf, 0, 16);
    buf[0] = WF_ST_RTS;
    buf[1] = 0x00;
    wf_put_le16(buf + 2, duration);
    memcpy(buf + 4, ra, 6);
    memcpy(buf + 10, ta, 6);
    return 16;
}
