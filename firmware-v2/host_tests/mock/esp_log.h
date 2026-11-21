// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#define ESP_LOG_AT(tag) \
    do {                \
        (void)(tag);    \
    } while (0)

#define ESP_LOGE(tag, fmt, ...) ESP_LOG_AT(tag)
#define ESP_LOGW(tag, fmt, ...) ESP_LOG_AT(tag)
#define ESP_LOGI(tag, fmt, ...) ESP_LOG_AT(tag)
#define ESP_LOGD(tag, fmt, ...) ESP_LOG_AT(tag)
