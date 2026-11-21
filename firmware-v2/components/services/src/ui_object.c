// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include <stdio.h>
#include <string.h>

#include "services/services.h"
#include "services_private.h"
#include "wbus/wbus.h"

static services_ui_ops_t s_ui;

void services_ui_bind(const services_ui_ops_t *ops) {
    if (ops != NULL) {
        s_ui = *ops;
    }
}

const services_ui_ops_t *services_ui_ops(void) {
    return &s_ui;
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

static esp_err_t ui_touch(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    char text[WB_LINE_MAX];
    text[0] = '\0';
    if (s_ui.touch != NULL) {
        s_ui.touch(text, sizeof(text));
    }
    if (text[0] == '\0') {
        wb_reply_fail(reply, "no display bound");
        return ESP_ERR_NOT_SUPPORTED;
    }
    wb_reply_line(reply, "%s", text);
    return ESP_OK;
}

static const wb_policy_t kCalPolicy[] = {
    {.name = "reset", .type = WB_T_U32, .required = false, .min = 0, .max = 1, .def = 0},
};

static esp_err_t ui_touch_cal(wb_args_t *args, wb_reply_t *reply) {
    if (s_ui.touch_cal == NULL) {
        wb_reply_fail(reply, "no display bound");
        return ESP_ERR_NOT_SUPPORTED;
    }
    const bool reset = wb_args_u32(args, "reset") != 0;
    if (!s_ui.touch_cal(reset)) {
        wb_reply_fail(reply, "calibration not started");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "tap the four dots");
    return ESP_OK;
}

static const wb_policy_t kTapPolicy[] = {
    {.name = "x", .type = WB_T_U32, .required = true, .min = 0, .max = 319, .def = 0},
    {.name = "y", .type = WB_T_U32, .required = true, .min = 0, .max = 239, .def = 0},
};

static esp_err_t ui_tap(wb_args_t *args, wb_reply_t *reply) {
    if (s_ui.tap == NULL) {
        wb_reply_fail(reply, "no display bound");
        return ESP_ERR_NOT_SUPPORTED;
    }
    const uint32_t x = wb_args_u32(args, "x");
    const uint32_t y = wb_args_u32(args, "y");
    if (!s_ui.tap((int)x, (int)y)) {
        wb_reply_fail(reply, "tap rejected");
        return ESP_FAIL;
    }
    wb_reply_line(reply, "tap x=%u y=%u", (unsigned)x, (unsigned)y);
    return ESP_OK;
}

static esp_err_t ui_dump(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    if (s_ui.dump == NULL) {
        wb_reply_fail(reply, "no display bound");
        return ESP_ERR_NOT_SUPPORTED;
    }
    s_ui.dump();
    wb_reply_line(reply, "dump done");
    return ESP_OK;
}

static const wb_method_t kUiMethods[] = {
    {"screen", ui_screen, "[count=1..4]", kScreenPolicy,
     sizeof(kScreenPolicy) / sizeof(kScreenPolicy[0])},
    {"status", ui_status, "", NULL, 0},
    {"touch", ui_touch, "", NULL, 0},
    {"touch_cal", ui_touch_cal, "[reset=0|1]", kCalPolicy,
     sizeof(kCalPolicy) / sizeof(kCalPolicy[0])},
    {"tap", ui_tap, "x=0..319 y=0..239", kTapPolicy, sizeof(kTapPolicy) / sizeof(kTapPolicy[0])},
    {"dump", ui_dump, "", NULL, 0},
};

static const wb_object_t kUiObject = {
    .name = "ui",
    .methods = kUiMethods,
    .n_methods = sizeof(kUiMethods) / sizeof(kUiMethods[0]),
};

const wb_object_t *services_ui_object(void) {
    return &kUiObject;
}
