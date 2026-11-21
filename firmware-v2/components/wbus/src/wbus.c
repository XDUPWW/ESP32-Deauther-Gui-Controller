// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "wbus/wbus.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"

static const char *TAG = "wbus";

#define WB_TOKEN_MAX 12

typedef struct {
    char key[WB_KEY_MAX];
    char val[WB_VAL_MAX];
} wb_raw_arg_t;

struct wb_args {
    int n;
    wb_raw_arg_t raw[WB_MAX_ARGS];
};

struct wb_reply {
    wb_sink_fn sink;
    void *ctx;
    bool failed;
    char message[WB_VAL_MAX];
};

typedef struct {
    const char *object;
    wb_event_fn fn;
    void *ctx;
} wb_sub_t;

static const wb_object_t *s_objects[WB_MAX_OBJECTS];
static size_t s_object_count;
static wb_sub_t s_subs[WB_MAX_SUBS];
static size_t s_sub_count;

static void reply_out(wb_reply_t *reply, const char *line) {
    if (reply->sink != NULL) {
        reply->sink(reply->ctx, line);
    }
}

void wb_reply_line(wb_reply_t *reply, const char *fmt, ...) {
    char line[WB_LINE_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    reply_out(reply, line);
}

void wb_reply_fail(wb_reply_t *reply, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reply->message, sizeof(reply->message), fmt, ap);
    va_end(ap);
    reply->failed = true;
}

esp_err_t wb_register(const wb_object_t *object) {
    if (object == NULL || object->name == NULL || object->methods == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_object_count >= WB_MAX_OBJECTS) {
        ESP_LOGE(TAG, "object table full");
        return ESP_ERR_NO_MEM;
    }
    if (wb_find(object->name) != NULL) {
        ESP_LOGE(TAG, "duplicate object %s", object->name);
        return ESP_ERR_INVALID_STATE;
    }
    s_objects[s_object_count++] = object;
    return ESP_OK;
}

const wb_object_t *wb_find(const char *name) {
    if (name == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < s_object_count; i++) {
        if (strcmp(s_objects[i]->name, name) == 0) {
            return s_objects[i];
        }
    }
    return NULL;
}

const wb_object_t *wb_at(size_t index) {
    return (index < s_object_count) ? s_objects[index] : NULL;
}

size_t wb_count(void) {
    return s_object_count;
}

esp_err_t wb_subscribe(const char *object, wb_event_fn fn, void *ctx) {
    if (object == NULL || fn == NULL || s_sub_count >= WB_MAX_SUBS) {
        return ESP_ERR_INVALID_ARG;
    }
    s_subs[s_sub_count].object = object;
    s_subs[s_sub_count].fn = fn;
    s_subs[s_sub_count].ctx = ctx;
    s_sub_count++;
    return ESP_OK;
}

void wb_emit(const char *object, const char *event, const char *fmt, ...) {
    char payload[WB_LINE_MAX];
    payload[0] = '\0';
    if (fmt != NULL) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(payload, sizeof(payload), fmt, ap);
        va_end(ap);
    }
    char line[WB_LINE_MAX * 2];
    if (payload[0] != '\0') {
        snprintf(line, sizeof(line), "EVT %s.%s %s", object, event, payload);
    } else {
        snprintf(line, sizeof(line), "EVT %s.%s", object, event);
    }
    for (size_t i = 0; i < s_sub_count; i++) {
        if (strcmp(s_subs[i].object, object) == 0 || strcmp(s_subs[i].object, "*") == 0) {
            s_subs[i].fn(s_subs[i].ctx, line);
        }
    }
}

static wb_raw_arg_t *args_slot(wb_args_t *args, const char *key) {
    for (int i = 0; i < args->n; i++) {
        if (strcmp(args->raw[i].key, key) == 0) {
            return &args->raw[i];
        }
    }
    return NULL;
}

static const wb_raw_arg_t *args_const_slot(const wb_args_t *args, const char *key) {
    for (int i = 0; i < args->n; i++) {
        if (strcmp(args->raw[i].key, key) == 0) {
            return &args->raw[i];
        }
    }
    return NULL;
}

bool wb_args_has(const wb_args_t *args, const char *name) {
    return args != NULL && args_const_slot(args, name) != NULL;
}

bool wb_args_bool(const wb_args_t *args, const char *name) {
    const wb_raw_arg_t *slot = args_const_slot(args, name);
    if (slot == NULL) {
        return false;
    }
    return strcmp(slot->val, "1") == 0 || strcmp(slot->val, "true") == 0;
}

uint32_t wb_args_u32(const wb_args_t *args, const char *name) {
    const wb_raw_arg_t *slot = args_const_slot(args, name);
    return (slot != NULL) ? (uint32_t)strtoul(slot->val, NULL, 0) : 0;
}

const char *wb_args_str(const wb_args_t *args, const char *name) {
    const wb_raw_arg_t *slot = args_const_slot(args, name);
    return (slot != NULL) ? slot->val : "";
}

int wb_args_channel(const wb_args_t *args, const char *name) {
    const wb_raw_arg_t *slot = args_const_slot(args, name);
    if (slot == NULL || strcmp(slot->val, "auto") == 0) {
        return 0;
    }
    return (int)strtoul(slot->val, NULL, 10);
}

bool wb_args_mac(const wb_args_t *args, const char *name, uint8_t out[6]) {
    const wb_raw_arg_t *slot = args_const_slot(args, name);
    if (slot == NULL || out == NULL) {
        return false;
    }
    unsigned int b[6];
    if (sscanf(slot->val, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        out[i] = (uint8_t)b[i];
    }
    return true;
}

static bool parse_u32(const char *text, uint32_t *out) {
    if (text == NULL || *text == '\0') {
        return false;
    }
    char *end = NULL;
    const unsigned long value = strtoul(text, &end, 0);
    if (end == NULL || *end != '\0') {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static bool parse_bool(const char *text, uint32_t *out) {
    if (strcmp(text, "1") == 0 || strcmp(text, "true") == 0 || strcmp(text, "on") == 0) {
        *out = 1;
        return true;
    }
    if (strcmp(text, "0") == 0 || strcmp(text, "false") == 0 || strcmp(text, "off") == 0) {
        *out = 0;
        return true;
    }
    return false;
}

static bool parse_channel(const char *text, uint32_t *out) {
    if (strcmp(text, "auto") == 0) {
        *out = 0;
        return true;
    }
    uint32_t value = 0;
    if (!parse_u32(text, &value)) {
        return false;
    }
    *out = value;
    return true;
}

static bool parse_mac(const char *text) {
    unsigned int b[6];
    return sscanf(text, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6;
}

static bool fill_default(wb_args_t *args, const wb_policy_t *policy) {
    if (args->n >= WB_MAX_ARGS) {
        return false;
    }
    wb_raw_arg_t *slot = &args->raw[args->n];
    memset(slot, 0, sizeof(*slot));
    strncpy(slot->key, policy->name, sizeof(slot->key) - 1);
    switch (policy->type) {
        case WB_T_STR:
            if (policy->def_str == NULL) {
                return false;
            }
            strncpy(slot->val, policy->def_str, sizeof(slot->val) - 1);
            break;
        case WB_T_CHANNEL:
            if (policy->def == 0) {
                strncpy(slot->val, "auto", sizeof(slot->val) - 1);
            } else {
                snprintf(slot->val, sizeof(slot->val), "%u", (unsigned)policy->def);
            }
            break;
        case WB_T_BOOL:
            strncpy(slot->val, policy->def ? "1" : "0", sizeof(slot->val) - 1);
            break;
        default:
            snprintf(slot->val, sizeof(slot->val), "%u", (unsigned)policy->def);
            break;
    }
    args->n++;
    return true;
}

static bool validate_args(const wb_method_t *method, wb_args_t *args, char *msg, size_t cap) {
    for (uint8_t i = 0; i < method->n_policy; i++) {
        const wb_policy_t *policy = &method->policy[i];
        wb_raw_arg_t *slot = args_slot(args, policy->name);
        if (slot == NULL) {
            if (policy->required) {
                snprintf(msg, cap, "%s is required", policy->name);
                return false;
            }
            if (!fill_default(args, policy)) {
                snprintf(msg, cap, "too many arguments");
                return false;
            }
            continue;
        }
        uint32_t value = 0;
        bool ok = true;
        switch (policy->type) {
            case WB_T_STR:
                break;
            case WB_T_BOOL:
                ok = parse_bool(slot->val, &value);
                break;
            case WB_T_CHANNEL:
                ok = parse_channel(slot->val, &value);
                break;
            case WB_T_MAC:
                ok = parse_mac(slot->val);
                break;
            case WB_T_U32:
            case WB_T_IDX:
            default:
                ok = parse_u32(slot->val, &value);
                break;
        }
        if (!ok) {
            if (policy->type == WB_T_MAC) {
                snprintf(msg, cap, "%s must be aa:bb:cc:dd:ee:ff", policy->name);
            } else if (policy->type == WB_T_STR) {
                snprintf(msg, cap, "%s is invalid", policy->name);
            } else {
                snprintf(msg, cap, "%s is not a number", policy->name);
            }
            return false;
        }
        if (policy->type != WB_T_STR && policy->type != WB_T_MAC) {
            if (value < policy->min || value > policy->max) {
                snprintf(msg, cap, "%s must be %u..%u", policy->name, (unsigned)policy->min,
                         (unsigned)policy->max);
                return false;
            }
        }
    }

    for (int i = 0; i < args->n; i++) {
        bool known = false;
        for (uint8_t p = 0; p < method->n_policy; p++) {
            if (strcmp(args->raw[i].key, method->policy[p].name) == 0) {
                known = true;
                break;
            }
        }
        if (!known) {
            snprintf(msg, cap, "%s is not a parameter of %s", args->raw[i].key, method->name);
            return false;
        }
    }
    return true;
}

esp_err_t wb_call(const char *object, const char *method, int argc, char *const *argv,
                  wb_sink_fn sink, void *ctx) {
    wb_reply_t reply = {
        .sink = sink,
        .ctx = ctx,
    };
    const wb_object_t *obj = wb_find(object);
    if (obj == NULL) {
        wb_reply_fail(&reply, "unknown object");
    } else {
        const wb_method_t *target = NULL;
        for (uint8_t i = 0; i < obj->n_methods; i++) {
            if (strcmp(obj->methods[i].name, method) == 0) {
                target = &obj->methods[i];
                break;
            }
        }
        if (target == NULL) {
            wb_reply_fail(&reply, "unknown method");
        } else {
            wb_args_t args = {0};
            char problem[WB_VAL_MAX];
            problem[0] = '\0';
            const char *bad = NULL;
            for (int i = 0; i < argc && bad == NULL; i++) {
                const char *text = argv[i];
                const char *eq = strchr(text, '=');
                if (eq == NULL) {
                    bad = "expect key=value";
                    break;
                }
                if (args.n >= WB_MAX_ARGS) {
                    bad = "too many arguments";
                    break;
                }
                wb_raw_arg_t *slot = &args.raw[args.n];
                memset(slot, 0, sizeof(*slot));
                const size_t key_len = (size_t)(eq - text);
                if (key_len == 0 || key_len >= sizeof(slot->key)) {
                    bad = "bad key";
                    break;
                }
                memcpy(slot->key, text, key_len);
                strncpy(slot->val, eq + 1, sizeof(slot->val) - 1);
                args.n++;
            }
            if (bad == NULL && !validate_args(target, &args, problem, sizeof(problem))) {
                bad = problem;
            }
            if (bad != NULL) {
                wb_reply_fail(&reply, "%s", bad);
            } else {
                const esp_err_t err = target->fn(&args, &reply);
                if (err != ESP_OK && !reply.failed) {
                    wb_reply_fail(&reply, "failed (%s)", esp_err_to_name(err));
                }
            }
        }
    }

    char line[WB_LINE_MAX];
    if (reply.failed) {
        snprintf(line, sizeof(line), "ERR %s.%s: %s", object, method, reply.message);
        reply_out(&reply, line);
        return ESP_ERR_INVALID_ARG;
    }
    snprintf(line, sizeof(line), "OK %s.%s", object, method);
    reply_out(&reply, line);
    return ESP_OK;
}

static int split_tokens(char *line, char *tokens[], int max) {
    int count = 0;
    char *p = line;
    while (*p != '\0' && count < max) {
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        if (*p == '"') {
            p++;
            tokens[count++] = p;
            while (*p != '\0' && *p != '"') {
                p++;
            }
        } else {
            tokens[count++] = p;
            while (*p != '\0' && *p != ' ' && *p != '\t') {
                p++;
            }
        }
        if (*p != '\0') {
            *p = '\0';
            p++;
        }
    }
    return count;
}

esp_err_t wb_call_line(const char *line, wb_sink_fn sink, void *ctx) {
    if (line == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    char buffer[WB_LINE_MAX];
    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *tokens[WB_TOKEN_MAX];
    const int count = split_tokens(buffer, tokens, WB_TOKEN_MAX);
    if (count == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    char *dot = strchr(tokens[0], '.');
    if (dot == NULL) {
        if (sink != NULL) {
            sink(ctx, "ERR syntax: expect object.method key=value ...");
        }
        return ESP_ERR_INVALID_ARG;
    }
    *dot = '\0';
    return wb_call(tokens[0], dot + 1, count - 1, &tokens[1], sink, ctx);
}
