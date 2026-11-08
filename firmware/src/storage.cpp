// Small NVS-backed blob store used by the LVGL UI for touch calibration.
// Kept in the application component so the UI component stays free of nvs_flash.

#include <cstddef>

#include "storage.h"

#include "nvs.h"
#include "nvs_flash.h"

namespace {

const char *kNamespace = "wui";
const char *kKey = "calib";

void ensure_nvs() {
    const esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
}

}  // namespace

bool app_storage_load(void *out, size_t len) {
    if (out == nullptr || len == 0) {
        return false;
    }
    ensure_nvs();
    nvs_handle_t handle;
    if (nvs_open(kNamespace, NVS_READONLY, &handle) != ESP_OK) {
        return false;
    }
    size_t read_len = len;
    const esp_err_t err = nvs_get_blob(handle, kKey, out, &read_len);
    nvs_close(handle);
    return err == ESP_OK && read_len == len;
}

bool app_storage_save(const void *in, size_t len) {
    if (in == nullptr || len == 0) {
        return false;
    }
    ensure_nvs();
    nvs_handle_t handle;
    if (nvs_open(kNamespace, NVS_READWRITE, &handle) != ESP_OK) {
        return false;
    }
    const esp_err_t err = nvs_set_blob(handle, kKey, in, len);
    if (err == ESP_OK) {
        nvs_commit(handle);
    }
    nvs_close(handle);
    return err == ESP_OK;
}

void app_storage_clear() {
    ensure_nvs();
    nvs_handle_t handle;
    if (nvs_open(kNamespace, NVS_READWRITE, &handle) != ESP_OK) {
        return;
    }
    nvs_erase_key(handle, kKey);
    nvs_commit(handle);
    nvs_close(handle);
}
