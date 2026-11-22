// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#define WB_MAX_OBJECTS 24
#define WB_MAX_METHODS 8
#define WB_MAX_ARGS 8
#define WB_MAX_SUBS 8
#define WB_LINE_MAX 256
#define WB_KEY_MAX 20
#define WB_VAL_MAX 96

typedef struct wb_args wb_args_t;
typedef struct wb_reply wb_reply_t;

typedef enum {
    WB_T_U32,
    WB_T_BOOL,
    WB_T_STR,
    WB_T_CHANNEL,
    WB_T_IDX,
    WB_T_MAC,
} wb_type_t;

typedef struct {
    const char *name;
    wb_type_t type;
    bool required;
    uint32_t min;
    uint32_t max;
    uint32_t def;
    const char *def_str;
} wb_policy_t;

typedef esp_err_t (*wb_handler_t)(wb_args_t *args, wb_reply_t *reply);

typedef struct {
    const char *name;
    wb_handler_t fn;
    const char *sig;
    const wb_policy_t *policy;
    uint8_t n_policy;
} wb_method_t;

typedef struct {
    const char *name;
    // 界面上显示的名字；NULL 表示这个对象不上界面（服务类的都不上）。
    // 触摸屏的攻击列表就是照这个字段长出来的，加一个攻击 = 这里填一行。
    const char *title;
    const wb_method_t *methods;
    uint8_t n_methods;
} wb_object_t;

typedef void (*wb_sink_fn)(void *ctx, const char *line);

esp_err_t wb_register(const wb_object_t *object);

const wb_object_t *wb_find(const char *name);

const wb_object_t *wb_at(size_t index);

size_t wb_count(void);

esp_err_t wb_call(const char *object, const char *method, int argc, char *const *argv,
                  wb_sink_fn sink, void *ctx);

esp_err_t wb_call_line(const char *line, wb_sink_fn sink, void *ctx);

void wb_reply_line(wb_reply_t *reply, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

void wb_reply_fail(wb_reply_t *reply, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

bool wb_args_has(const wb_args_t *args, const char *name);

uint32_t wb_args_u32(const wb_args_t *args, const char *name);

bool wb_args_bool(const wb_args_t *args, const char *name);

const char *wb_args_str(const wb_args_t *args, const char *name);

bool wb_args_mac(const wb_args_t *args, const char *name, uint8_t out[6]);

int wb_args_channel(const wb_args_t *args, const char *name);

typedef void (*wb_event_fn)(void *ctx, const char *line);

esp_err_t wb_subscribe(const char *object, wb_event_fn fn, void *ctx);

void wb_emit(const char *object, const char *event, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
