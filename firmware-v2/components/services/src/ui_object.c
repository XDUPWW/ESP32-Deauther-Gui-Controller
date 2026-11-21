// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include <stdio.h>
#include <string.h>

#include "services/services.h"
#include "wbus/wbus.h"

static services_ui_ops_t s_ui;

void services_ui_bind(const services_ui_ops_t *ops) {
    if (ops != NULL) {
        s_ui = *ops;
    }
}

static const wb_policy_t kScreenPolicy[] = {
    {.name = "count", .type = WB_T_U32, .required = false, .min = 1, .max = 4, .def = 4},
};

static esp_err_t ui_screen(wb_args_t *args, wb_reply_t *reply) {
    if (s_ui.screen == NULL) {
        wb_reply_fail(reply, "no display bound");
        return ESP_ERR_NOT_SUPPORTED;
    }
    const uint32_t count = wb_args_u32(args, "count");
    if (!s_ui.screen((int)count)) {
        wb_reply_fail(reply, "screen rejected");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "screen test armed count=%u", (unsigned)count);
    return ESP_OK;
}

static esp_err_t ui_status(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    if (s_ui.status == NULL) {
        wb_reply_fail(reply, "no display bound");
        return ESP_ERR_NOT_SUPPORTED;
    }
    char text[WB_LINE_MAX];
    text[0] = '\0';
    s_ui.status(text, sizeof(text));
    wb_reply_line(reply, "%s", text);
    return ESP_OK;
}

static const wb_method_t kUiMethods[] = {
    {"screen", ui_screen, "[count=1..4]", kScreenPolicy,
     sizeof(kScreenPolicy) / sizeof(kScreenPolicy[0])},
    {"status", ui_status, "", NULL, 0},
};

static const wb_object_t kUiObject = {
    .name = "ui",
    .methods = kUiMethods,
    .n_methods = sizeof(kUiMethods) / sizeof(kUiMethods[0]),
};

const wb_object_t *services_system_object(void);

const wb_object_t *services_ui_object(void) {
    return &kUiObject;
}

void services_start(void) {
    wb_register(services_system_object());
    wb_register(services_ui_object());
}
