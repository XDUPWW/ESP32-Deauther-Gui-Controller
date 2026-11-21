// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

bool wf_mac_parse(const char *text, uint8_t out[6]);

void wf_mac_format(char out[18], const uint8_t mac[6]);

// Locally administered, unicast, built from the caller's entropy.
void wf_mac_randomize(uint8_t out[6], uint64_t entropy);

bool wf_mac_is_group(const uint8_t mac[6]);

bool wf_mac_is_broadcast(const uint8_t mac[6]);
