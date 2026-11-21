// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdint.h>

#include "wbus/wbus.h"

const wb_object_t *services_system_object(void);
const wb_object_t *services_ui_object(void);
const wb_object_t *services_radio_object(void);
const wb_object_t *services_scan_object(void);

void services_scan_attach_rx(void);
void services_scan_tick(uint32_t now_ms);
