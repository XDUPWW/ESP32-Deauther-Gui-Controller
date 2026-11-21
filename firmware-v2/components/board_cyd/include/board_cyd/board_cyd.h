// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include "platform/plat_display.h"

// 板级显示口的入口，main 起来后 bind 一次。没启用这块板就返回 NULL。
const plat_display_ops_t *board_cyd_display_ops(void);
