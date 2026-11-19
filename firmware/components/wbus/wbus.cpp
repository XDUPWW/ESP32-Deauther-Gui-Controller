#include "wbus.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

namespace {

const wb_object_t* s_objects[WB_MAX_OBJECTS];
int s_object_count;
void (*s_sink)(const char* bytes);

char s_subs[WB_MAX_SUBS][WB_SUB_LEN];
int s_sub_count;

bool str_ieq(const char* a, const char* b) {
    if (a == nullptr || b == nullptr) return false;
    while (*a != 0 && *b != 0) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

bool has_digit(const char* text) {
    for (const char* p = text; p != nullptr && *p != 0; p++) {
        if (isdigit((unsigned char)*p)) return true;
    }
    return false;
}

bool parse_mac_token(const char* token, uint8_t out[6]) {
    if (token == nullptr) return false;
    char clean[13];
    int n = 0;
    for (const char* p = token; *p != 0 && n < 13; p++) {
        if (*p == ':' || *p == '-' || *p == '.') continue;
        if (!isxdigit((unsigned char)*p)) return false;
        clean[n++] = *p;
    }
    if (n != 12) return false;
    for (int i = 0; i < 6; i++) {
        const char byte[3] = {clean[i * 2], clean[i * 2 + 1], 0};
        out[i] = (uint8_t)strtoul(byte, nullptr, 16);
    }
    return true;
}

// "a|b|c" membership. Returns a pointer into the table (the entry is only '|'
// terminated), so callers copy the spelling out before handing it to strcmp.
const char* enum_match(const char* table, const char* token) {
    if (table == nullptr || token == nullptr) return nullptr;
    const char* cursor = table;
    while (*cursor != 0) {
        const char* bar = strchr(cursor, '|');
        const size_t len = (bar == nullptr) ? strlen(cursor) : (size_t)(bar - cursor);
        if (strlen(token) == len && strncasecmp(cursor, token, len) == 0) return cursor;
        if (bar == nullptr) break;
        cursor = bar + 1;
    }
    return nullptr;
}

size_t entry_len(const char* hit) {
    const char* bar = strchr(hit, '|');
    return (bar == nullptr) ? strlen(hit) : (size_t)(bar - hit);
}

bool eval_arg(const wb_arg_spec_t& spec, const char* token, wb_value_t* out) {
    *out = wb_value_t{};
    out->present = true;

    switch (spec.type) {
        case WB_T_STR:
            out->text = token;
            return true;

        case WB_T_INT: {
            // Strict: the whole token must be a number. Anything else is refused by
            // the policy instead of being silently read as 0 (strtol's habit).
            if (token == nullptr || token[0] == 0) return false;
            char* end = nullptr;
            out->num = strtol(token, &end, 10);
            if (end == token || *end != 0) return false;
            out->text = token;
            if (spec.min < spec.max && (out->num < spec.min || out->num > spec.max)) return false;
            return true;
        }

        case WB_T_REASON:
            if (token == nullptr) return false;
            if (str_ieq(token, "random") || str_ieq(token, "rand") || str_ieq(token, "r")) {
                out->num = 0;
                out->text = "random";  // canonical, so handlers compare one spelling
                return true;
            }
            if (!has_digit(token)) return false;
            out->num = strtol(token, nullptr, 10);
            if (out->num <= 0 || out->num > 65535) return false;
            out->text = token;
            return true;

        case WB_T_MAC:
            if (!parse_mac_token(token, out->mac)) return false;
            out->text = token;
            return true;

        case WB_T_ENUM: {
            if (token == nullptr) return false;
            const bool numeric = (spec.flags & WB_F_NUMERIC_OK) != 0 && has_digit(token) &&
                                 (isdigit((unsigned char)token[0]) != 0 || token[0] == '-');
            if (numeric) {
                out->num = strtol(token, nullptr, 10);
                out->text = token;
                if (spec.min < spec.max && (out->num < spec.min || out->num > spec.max)) return false;
                return true;
            }
            if (enum_match(spec.enums, token) == nullptr) return false;
            out->num = spec.def;
            out->text = nullptr;  // filled in by canonicalize_enum()
            return true;
        }
    }
    return false;
}

// wb_args_t plus room for the canonical enum spellings, so a handler's
// wb_value_t::text survives the call without pointing into a static buffer.
struct wb_args_frame {
    wb_args_t args;
    char enums[WB_MAX_ARGS][16];
};

void canonicalize_enum(const wb_arg_spec_t& spec, const char* token, wb_args_t* args,
                       char (*store)[16], int slot) {
    if (token == nullptr) return;
    const char* hit = enum_match(spec.enums, token);
    if (hit == nullptr) return;
    const size_t len = entry_len(hit);
    const size_t copy = (len < 15) ? len : 15;
    memcpy(store[slot], hit, copy);
    store[slot][copy] = 0;
    args->value[slot].text = store[slot];
    args->value[slot].num = spec.def;
}

void reply_raw(wb_reply_t* reply, const char* bytes) {
    void (*sink)(const char*) = (reply != nullptr) ? reply->sink : nullptr;
    if (sink == nullptr) sink = s_sink;
    if (sink != nullptr) sink(bytes);
}

void reply_policy_error(wb_reply_t* reply, const char* obj, const char* method,
                        const wb_arg_spec_t& spec) {
    char buffer[128];
    // The old commands each had their own wording; carrying it in the spec keeps
    // the reply byte-identical instead of inventing a generic message.
    if (spec.err != nullptr) {
        snprintf(buffer, sizeof(buffer), "ERR %s\r\n", spec.err);
    } else {
        snprintf(buffer, sizeof(buffer), "ERR %s.%s: %s is not valid (try DESCRIBE %s)\r\n", obj,
                 method, spec.name, obj);
    }
    reply_raw(reply, buffer);
}

const wb_object_t* find_object(const char* name) {
    if (name == nullptr) return nullptr;
    for (int i = 0; i < s_object_count; i++) {
        if (str_ieq(s_objects[i]->name, name)) return s_objects[i];
    }
    return nullptr;
}

const wb_method_t* find_method(const wb_object_t* obj, const char* name) {
    if (obj == nullptr || name == nullptr) return nullptr;
    for (int i = 0; i < obj->n_methods; i++) {
        if (str_ieq(obj->methods[i].name, name)) return &obj->methods[i];
    }
    return nullptr;
}

int spec_index(const wb_method_t* method, const char* name) {
    if (method == nullptr || name == nullptr || method->args == nullptr) return -1;
    for (int i = 0; i < method->n_args; i++) {
        if (str_ieq(method->args[i].name, name)) return i;
    }
    return -1;
}

void reset_args(const wb_method_t* method, wb_args_t* args) {
    args->spec = method->args;
    args->count = method->n_args;
    args->extra_count = 0;
    for (int i = 0; i < method->n_args; i++) {
        args->value[i].present = false;
        args->value[i].num = method->args[i].def;
        args->value[i].text = nullptr;
        memset(args->value[i].mac, 0, sizeof(args->value[i].mac));
    }
}

bool topic_matches(const char* pattern, const char* topic) {
    if (pattern == nullptr || topic == nullptr) return false;
    const size_t len = strlen(pattern);
    if (len > 0 && pattern[len - 1] == '*') return strncmp(pattern, topic, len - 1) == 0;
    return strcmp(pattern, topic) == 0;
}

const wb_method_t* resolve(const char* obj_name, const char* method_name, wb_reply_t* reply,
                           wb_err_t* err) {
    const wb_object_t* obj = find_object(obj_name);
    char buffer[96];
    if (obj == nullptr) {
        snprintf(buffer, sizeof(buffer), "ERR unknown object %s (try WBUS)\r\n", obj_name);
        reply_raw(reply, buffer);
        *err = WB_ERR_NOENT;
        return nullptr;
    }
    const wb_method_t* method = find_method(obj, method_name);
    if (method == nullptr) {
        snprintf(buffer, sizeof(buffer), "ERR unknown method %s.%s (try DESCRIBE %s)\r\n", obj_name,
                 method_name, obj_name);
        reply_raw(reply, buffer);
        *err = WB_ERR_NOENT;
        return nullptr;
    }
    *err = WB_OK;
    return method;
}

}  // namespace

void wbus_set_sink(void (*sink)(const char* bytes)) { s_sink = sink; }

wb_err_t wbus_register(const wb_object_t* obj) {
    if (obj == nullptr || obj->name == nullptr) return WB_ERR_ARG;
    if (find_object(obj->name) != nullptr) return WB_ERR_ARG;  // duplicate is a bug, not a feature
    if (s_object_count >= WB_MAX_OBJECTS) return WB_ERR_FULL;
    s_objects[s_object_count++] = obj;
    return WB_OK;
}

wb_err_t wbus_call(const char* obj_name, const char* method_name, int argc, char* const* argv,
                   wb_reply_t* reply) {
    wb_err_t err = WB_OK;
    const wb_method_t* method = resolve(obj_name, method_name, reply, &err);
    if (method == nullptr) return err;

    wb_args_frame frame = {};
    wb_args_t* args = &frame.args;
    reset_args(method, args);

    for (int i = 0; i < method->n_args; i++) {
        const wb_arg_spec_t& spec = method->args[i];
        if (i >= argc || argv[i] == nullptr) continue;  // absent: defaults are already in place
        if (!eval_arg(spec, argv[i], &args->value[i])) {
            reply_policy_error(reply, obj_name, method_name, spec);
            return WB_ERR_ARG;
        }
        if (spec.type == WB_T_ENUM) canonicalize_enum(spec, argv[i], args, frame.enums, i);
    }

    for (int i = method->n_args; i < argc && args->extra_count < WB_MAX_ARGS; i++) {
        args->extra[args->extra_count++] = argv[i];
    }

    return method->handler(args, reply);
}

wb_err_t wbus_call_named(const char* obj_name, const char* method_name, int argc,
                         char* const* argv, wb_reply_t* reply) {
    wb_err_t err = WB_OK;
    const wb_method_t* method = resolve(obj_name, method_name, reply, &err);
    if (method == nullptr) return err;

    wb_args_frame frame = {};
    wb_args_t* args = &frame.args;
    reset_args(method, args);

    char buffer[96];
    for (int i = 0; i < argc; i++) {
        if (argv[i] == nullptr) continue;
        char* eq = strchr(argv[i], '=');
        if (eq == nullptr) {
            if (args->extra_count < WB_MAX_ARGS) args->extra[args->extra_count++] = argv[i];
            continue;
        }
        *eq = 0;
        const int slot = spec_index(method, argv[i]);
        if (slot < 0) {
            snprintf(buffer, sizeof(buffer), "ERR unknown arg %s (try DESCRIBE %s)\r\n", argv[i],
                     obj_name);
            reply_raw(reply, buffer);
            return WB_ERR_NOENT;
        }
        char* value_token = eq + 1;
        const wb_arg_spec_t& spec = method->args[slot];
        if (!eval_arg(spec, value_token, &args->value[slot])) {
            reply_policy_error(reply, obj_name, method_name, spec);
            return WB_ERR_ARG;
        }
        if (spec.type == WB_T_ENUM) canonicalize_enum(spec, value_token, args, frame.enums, slot);
    }

    return method->handler(args, reply);
}

void wbus_list(wb_reply_t* reply) {
    char buffer[192];
    snprintf(buffer, sizeof(buffer), "WBUS objects=%d\r\n", s_object_count);
    reply_raw(reply, buffer);
    for (int i = 0; i < s_object_count; i++) {
        const wb_object_t* obj = s_objects[i];
        char methods[96] = {0};
        for (int m = 0; m < obj->n_methods; m++) {
            if (m > 0) strncat(methods, ",", sizeof(methods) - strlen(methods) - 1);
            strncat(methods, obj->methods[m].name, sizeof(methods) - strlen(methods) - 1);
        }
        snprintf(buffer, sizeof(buffer), "WBUS %s \"%s\" methods=%s events=%s\r\n", obj->name,
                 obj->title != nullptr ? obj->title : "", methods,
                 obj->events != nullptr ? obj->events : "");
        reply_raw(reply, buffer);
    }
}

void wbus_describe(const char* name, wb_reply_t* reply) {
    char buffer[192];
    if (name == nullptr) {
        for (int i = 0; i < s_object_count; i++) wbus_describe(s_objects[i]->name, reply);
        return;
    }
    const wb_object_t* obj = find_object(name);
    if (obj == nullptr) {
        snprintf(buffer, sizeof(buffer), "ERR unknown object %s (try WBUS)\r\n", name);
        reply_raw(reply, buffer);
        return;
    }
    snprintf(buffer, sizeof(buffer), "OBJ %s \"%s\"\r\n", obj->name,
             obj->title != nullptr ? obj->title : "");
    reply_raw(reply, buffer);

    for (int m = 0; m < obj->n_methods; m++) {
        const wb_method_t& method = obj->methods[m];
        snprintf(buffer, sizeof(buffer), "METHOD %s.%s \"%s\"\r\n", obj->name, method.name,
                 method.summary != nullptr ? method.summary : "");
        reply_raw(reply, buffer);
        for (int a = 0; a < method.n_args; a++) {
            const wb_arg_spec_t& spec = method.args[a];
            const char* type = "str";
            switch (spec.type) {
                case WB_T_INT: type = "int"; break;
                case WB_T_REASON: type = "reason"; break;
                case WB_T_MAC: type = "mac"; break;
                case WB_T_ENUM: type = "enum"; break;
                default: break;
            }
            const bool has_values = (spec.enums != nullptr && spec.type == WB_T_ENUM);
            snprintf(buffer, sizeof(buffer), "ARG %s.%s %s type=%s default=%ld%s%s\r\n", obj->name,
                     method.name, spec.name, type, spec.def, has_values ? " values=" : "",
                     has_values ? spec.enums : "");
            reply_raw(reply, buffer);
        }
    }
    if (obj->events != nullptr && obj->events[0] != 0) {
        snprintf(buffer, sizeof(buffer), "EVT %s %s\r\n", obj->name, obj->events);
        reply_raw(reply, buffer);
    }
}

bool wbus_subscribe(const char* pattern) {
    if (pattern == nullptr) {
        wbus_subscribe_clear();
        return true;
    }
    if (s_sub_count >= WB_MAX_SUBS) return false;
    snprintf(s_subs[s_sub_count], WB_SUB_LEN, "%s", pattern);
    s_sub_count++;
    return true;
}

void wbus_subscribe_clear(void) { s_sub_count = 0; }

void wbus_emit(const char* topic, const char* kv) {
    if (topic == nullptr || s_sub_count == 0) return;
    bool wanted = false;
    for (int i = 0; i < s_sub_count; i++) {
        if (topic_matches(s_subs[i], topic)) {
            wanted = true;
            break;
        }
    }
    if (!wanted) return;
    char buffer[160];
    if (kv != nullptr && kv[0] != 0) {
        snprintf(buffer, sizeof(buffer), "EVT %s %s\r\n", topic, kv);
    } else {
        snprintf(buffer, sizeof(buffer), "EVT %s\r\n", topic);
    }
    if (s_sink != nullptr) s_sink(buffer);
}

const wb_value_t* wb_arg(const wb_args_t* args, const char* name) {
    if (args == nullptr || name == nullptr) return nullptr;
    for (int i = 0; i < args->count; i++) {
        if (args->spec[i].name != nullptr && str_ieq(args->spec[i].name, name)) return &args->value[i];
    }
    return nullptr;
}

long wb_arg_num(const wb_args_t* args, const char* name) {
    const wb_value_t* value = wb_arg(args, name);
    // Absent arguments already carry spec->def, so there is only one path here.
    return (value == nullptr) ? 0 : value->num;
}

bool wb_arg_mac(const wb_args_t* args, const char* name, uint8_t out[6]) {
    const wb_value_t* value = wb_arg(args, name);
    if (value == nullptr || !value->present) return false;
    memcpy(out, value->mac, 6);
    return true;
}

bool wb_parse_mac(const char* token, uint8_t out[6]) { return parse_mac_token(token, out); }

void wb_reply_line(wb_reply_t* reply, const char* text) {
    if (text == nullptr) return;
    char buffer[200];
    snprintf(buffer, sizeof(buffer), "%s\r\n", text);
    reply_raw(reply, buffer);
}

void wb_reply_printf(wb_reply_t* reply, const char* fmt, ...) {
    if (fmt == nullptr) return;
    char buffer[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);
    reply_raw(reply, buffer);
}
