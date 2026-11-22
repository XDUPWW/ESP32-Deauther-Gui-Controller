// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "attacks/attack.h"

#include <string.h>

#include "esp_log.h"

static const char *TAG = "attacks";

#define ATTACK_MAX 16

static const attack_driver_t *s_attacks[ATTACK_MAX];
static size_t s_attack_count;

esp_err_t attack_register(const attack_driver_t *driver) {
    if (driver == NULL || driver->name == NULL || driver->object == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_attack_count >= ATTACK_MAX) {
        ESP_LOGE(TAG, "attack table full");
        return ESP_ERR_NO_MEM;
    }
    if (attack_find(driver->name) != NULL) {
        ESP_LOGE(TAG, "duplicate attack %s", driver->name);
        return ESP_ERR_INVALID_STATE;
    }
    s_attacks[s_attack_count++] = driver;
    return wb_register(driver->object);
}

const attack_driver_t *attack_find(const char *name) {
    if (name == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < s_attack_count; i++) {
        if (strcmp(s_attacks[i]->name, name) == 0) {
            return s_attacks[i];
        }
    }
    return NULL;
}

const attack_driver_t *attack_at(size_t index) {
    return (index < s_attack_count) ? s_attacks[index] : NULL;
}

size_t attack_count(void) {
    return s_attack_count;
}

void attacks_start(void) {
    attack_register(deauth_attack());
    attack_register(probe_attack());
    attack_register(delba_attack());
    attack_register(ba_attack());
    attack_register(eapol_attack());
    attack_register(csa_attack());
    attack_register(authflood_attack());
    attack_register(sae_attack());
    attack_register(btm_attack());
}

void attacks_stop_all(void) {
    for (size_t i = 0; i < s_attack_count; i++) {
        if (s_attacks[i]->active != NULL && s_attacks[i]->active() && s_attacks[i]->stop != NULL) {
            s_attacks[i]->stop();
        }
    }
}

void attacks_tick(uint32_t now_ms) {
    for (size_t i = 0; i < s_attack_count; i++) {
        const attack_driver_t *driver = s_attacks[i];
        if (driver->tick != NULL && driver->active != NULL && driver->active()) {
            driver->tick(now_ms);
        }
    }
}
