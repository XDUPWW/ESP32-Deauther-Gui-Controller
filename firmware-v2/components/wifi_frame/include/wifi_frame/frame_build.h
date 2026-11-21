// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wifi_frame/frames.h"

int wf_build_deauth(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                    const uint8_t bssid[6], uint16_t reason);

int wf_build_disassoc(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                      const uint8_t bssid[6], uint16_t reason);

int wf_build_auth(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                  const uint8_t bssid[6], uint16_t algorithm, uint16_t seq, uint16_t status);

int wf_build_assoc_req(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                       const uint8_t bssid[6], uint16_t capab, uint16_t listen_interval,
                       const uint8_t *ies, size_t ies_len);

int wf_build_probe_req(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                       const char *ssid, size_t ssid_len);

int wf_build_beacon(uint8_t *buf, size_t cap, const uint8_t bssid[6], uint64_t tsf,
                    uint16_t interval, uint16_t capab, const uint8_t *ies, size_t ies_len);

int wf_build_action(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                    const uint8_t bssid[6], uint8_t category, const uint8_t *body,
                    size_t body_len);

int wf_build_data(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                  const uint8_t bssid[6], bool tods, bool fromds, bool qos, uint8_t tid,
                  const uint8_t *payload, size_t payload_len);

int wf_build_null_data(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                       const uint8_t bssid[6], bool qos, bool pm_bit);

int wf_build_llc_snap(uint8_t *buf, size_t cap, uint16_t ethertype, const uint8_t *payload,
                      size_t payload_len);

int wf_build_bar(uint8_t *buf, size_t cap, const uint8_t ra[6], const uint8_t ta[6], uint8_t tid,
                 uint16_t ssn);

int wf_build_rts(uint8_t *buf, size_t cap, const uint8_t ra[6], const uint8_t ta[6],
                 uint16_t duration);
