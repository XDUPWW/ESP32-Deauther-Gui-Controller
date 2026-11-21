// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "wtarget/wtarget.h"

#include <string.h>

static wt_entry_t s_entries[WT_MAX_ENTRIES];
static uint32_t s_count;
static uint32_t s_selected;

static bool same(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

esp_err_t wt_clear(void) {
    memset(s_entries, 0, sizeof(s_entries));
    s_count = 0;
    s_selected = 0;
    return ESP_OK;
}

uint32_t wt_count(void) {
    return s_count;
}

const wt_entry_t *wt_at(uint32_t index) {
    return (index < s_count) ? &s_entries[index] : NULL;
}

esp_err_t wt_add(const wt_entry_t *entry) {
    if (entry == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint8_t *key = (entry->kind == WT_KIND_AP) ? entry->bssid : entry->mac;
    for (uint32_t i = 0; i < s_count; i++) {
        const wt_entry_t *existing = &s_entries[i];
        if (existing->kind != entry->kind) {
            continue;
        }
        const uint8_t *other = (existing->kind == WT_KIND_AP) ? existing->bssid : existing->mac;
        if (!same(other, key)) {
            continue;
        }
        s_entries[i].rssi = (entry->rssi > existing->rssi) ? entry->rssi : existing->rssi;
        if (entry->channel != 0) {
            s_entries[i].channel = entry->channel;
        }
        if (entry->ssid_len > 0) {
            memcpy(s_entries[i].ssid, entry->ssid, sizeof(s_entries[i].ssid) - 1);
            s_entries[i].ssid[sizeof(s_entries[i].ssid) - 1] = '\0';
            s_entries[i].ssid_len = entry->ssid_len;
        }
        s_entries[i].sae = entry->sae;
        s_entries[i].mfpr = entry->mfpr;
        return ESP_OK;
    }
    if (s_count >= WT_MAX_ENTRIES) {
        return ESP_ERR_NO_MEM;
    }
    s_entries[s_count] = *entry;
    s_entries[s_count].ssid[sizeof(s_entries[s_count].ssid) - 1] = '\0';
    s_count++;
    return ESP_OK;
}

const wt_entry_t *wt_find_mac(const uint8_t mac[6]) {
    if (mac == NULL) {
        return NULL;
    }
    for (uint32_t i = 0; i < s_count; i++) {
        const uint8_t *key = (s_entries[i].kind == WT_KIND_AP) ? s_entries[i].bssid
                                                               : s_entries[i].mac;
        if (same(key, mac)) {
            return &s_entries[i];
        }
    }
    return NULL;
}

esp_err_t wt_select(uint32_t index) {
    if (index >= s_count) {
        return ESP_ERR_NOT_FOUND;
    }
    s_selected = index + 1;
    return ESP_OK;
}

const wt_entry_t *wt_selected(void) {
    return (s_selected == 0) ? NULL : &s_entries[s_selected - 1];
}
