// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "platform/plat_storage.h"

#include "esp_check.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "plat_store";
static const char *NS = "wb";

esp_err_t plat_storage_init(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_RETURN_ON_ERROR(nvs_flash_erase(), TAG, "nvs erase failed");
        err = nvs_flash_init();
    }
    return err;
}

bool plat_storage_get(const char *key, void *buf, size_t len) {
    if (key == NULL || buf == NULL) {
        return false;
    }
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) {
        return false;
    }
    size_t size = len;
    const bool ok = nvs_get_blob(h, key, buf, &size) == ESP_OK && size == len;
    nvs_close(h);
    return ok;
}

esp_err_t plat_storage_set(const char *key, const void *buf, size_t len) {
    if (key == NULL || buf == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t h;
    ESP_RETURN_ON_ERROR(nvs_open(NS, NVS_READWRITE, &h), TAG, "nvs open failed");
    const esp_err_t err = nvs_set_blob(h, key, buf, len);
    if (err == ESP_OK) {
        nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

esp_err_t plat_storage_erase(const char *key) {
    if (key == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t h;
    ESP_RETURN_ON_ERROR(nvs_open(NS, NVS_READWRITE, &h), TAG, "nvs open failed");
    const esp_err_t err = nvs_erase_key(h, key);
    nvs_commit(h);
    nvs_close(h);
    return (err == ESP_ERR_NVS_NOT_FOUND) ? ESP_OK : err;
}
