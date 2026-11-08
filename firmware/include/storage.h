#pragma once

#include <stdbool.h>
#include <stddef.h>

// NVS blob helpers implemented by src/storage.cpp and injected into the LVGL UI
// component (see wireless_ui_storage_ops_t).
bool app_storage_load(void *out, size_t len);
bool app_storage_save(const void *in, size_t len);
void app_storage_clear(void);
