// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "wbus/wbus.h"

// 一个攻击模块对外只有这几件事：能被 tick、能停、能报数和活跃状态。
// 命令行入口是 object 里的 wb 方法，不在这里再开一份。
typedef struct attack_driver attack_driver_t;

struct attack_driver {
    const char *name;
    const wb_object_t *object;
    void (*stop)(void);
    void (*tick)(uint32_t now_ms);
    uint32_t (*frames)(void);
    bool (*active)(void);
};

esp_err_t attack_register(const attack_driver_t *driver);

const attack_driver_t *attack_find(const char *name);

const attack_driver_t *attack_at(size_t index);

size_t attack_count(void);

void attacks_start(void);

void attacks_stop_all(void);

void attacks_tick(uint32_t now_ms);

// 各模块的驱动描述符。attacks.c 逐个登记。
const attack_driver_t *deauth_attack(void);
const attack_driver_t *probe_attack(void);
const attack_driver_t *delba_attack(void);
const attack_driver_t *ba_attack(void);
const attack_driver_t *eapol_attack(void);
const attack_driver_t *csa_attack(void);
const attack_driver_t *authflood_attack(void);
const attack_driver_t *sae_attack(void);
const attack_driver_t *btm_attack(void);
