// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 契约占位：帧构造函数的具体字节布局在后续阶段实现，签名先固定下来。

#include "wifi_frame/frame_build.h"

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

int wf_build_probe_req(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                       const char *ssid, size_t ssid_len) {
    (void)buf, (void)cap, (void)da, (void)sa, (void)ssid, (void)ssid_len;
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
    (void)buf, (void)cap, (void)ra, (void)ta, (void)tid, (void)ssn;
    return -1;
}

int wf_build_rts(uint8_t *buf, size_t cap, const uint8_t ra[6], const uint8_t ta[6],
                 uint16_t duration) {
    (void)buf, (void)cap, (void)ra, (void)ta, (void)duration;
    return -1;
}
