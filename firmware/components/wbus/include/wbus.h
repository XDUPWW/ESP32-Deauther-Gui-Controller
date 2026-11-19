// wbus -- a miniature ubus for one board.
//
// Three pieces of ubus are enough here:
//   * an object registry          (wbus_register / wbus_list / wbus_describe)
//   * policy-checked method calls (wbus_call / wbus_call_named)
//   * a publish channel           (wbus_emit / wbus_subscribe)
//
// The point is not the names, it is that a transport never learns anything about
// an attack: it only ever says "<obj>.<method> <args>" and gets bytes back. Today
// that transport is the serial console, tomorrow it can be the LVGL screen or a
// socket, and the attack modules do not change.
//
// This component deliberately has no Arduino and no esp_* dependency: the reply
// sink is injected with wbus_set_sink(), so the same object tables can serve a
// socket later without dragging Serial along.
#ifndef WBUS_H
#define WBUS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WB_MAX_ARGS 6
#define WB_MAX_OBJECTS 16
#define WB_MAX_METHODS 8
#define WB_MAX_SUBS 4
#define WB_SUB_LEN 24

typedef enum {
    WB_OK = 0,
    WB_ERR_ARG,    // a policy check failed; the exact reply was already emitted
    WB_ERR_NOENT,  // unknown object, method or argument name
    WB_ERR_STATE,  // the handler refused (wrong channel, pool busy, ...)
    WB_ERR_FULL,   // registry or subscriber table full
} wb_err_t;

typedef enum {
    WB_T_STR = 0,  // free-form token, handed through untouched
    WB_T_INT,      // strtol with the legacy semantics: a leading number wins
    WB_T_REASON,   // 1..65535, or random/rand/r
    WB_T_MAC,      // AA:BB:CC:DD:EE:FF / AA-BB-.. / AABBCCDDEEFF
    WB_T_ENUM,     // one of spec->enums ('|' separated, case-insensitive)
} wb_type_t;

enum {
    // A WB_T_ENUM argument also accepts a number (CSA's channel is either "auto"
    // or 1..14/36..196).
    WB_F_NUMERIC_OK = 1 << 0,
    // A WB_T_INT token without a digit parses as 0 instead of failing. Legacy
    // compatibility only: `BARPUSH 0 abc` used to reach strtol() and mean step 0.
    WB_F_JUNK_ZERO = 1 << 1,
};

// One declared argument. The struct is meant to live in .rodata: `err` is the
// exact text printed after "ERR ", which is how the refactor keeps byte-identical
// replies for commands that already existed.
typedef struct wb_arg_spec {
    const char* name;
    wb_type_t type;
    unsigned flags;
    const char* enums;
    const char* label;  // DESCRIBE text
    const char* err;    // "ERR " text when this argument fails to parse
    long def;           // value used when the argument is absent
    long min;
    long max;  // a range check runs only when min < max
} wb_arg_spec_t;

typedef struct wb_value {
    bool present;
    long num;          // WB_T_INT/WB_T_REASON/numeric WB_T_ENUM
    const char* text;  // canonical enum name, or the raw token
    uint8_t mac[6];
} wb_value_t;

typedef struct wb_args {
    const wb_arg_spec_t* spec;
    int count;
    wb_value_t value[WB_MAX_ARGS];
    int extra_count;  // tokens that had no matching spec
    const char* extra[WB_MAX_ARGS];
} wb_args_t;

// Where a handler writes. Swapping the sink is the whole transport abstraction:
// serial today, an event stream or a socket later.
typedef struct wb_reply {
    void (*sink)(const char* bytes);
} wb_reply_t;

typedef wb_err_t (*wb_handler_t)(const wb_args_t*, wb_reply_t*);

typedef struct wb_method {
    const char* name;
    const wb_arg_spec_t* args;  // NULL when n_args == 0
    int n_args;
    wb_handler_t handler;
    const char* summary;  // shown by WBUS/DESCRIBE
} wb_method_t;

typedef struct wb_object {
    const char* name;
    const char* title;
    const wb_method_t* methods;
    int n_methods;
    const char* events;  // comma separated, informational
} wb_object_t;

void wbus_set_sink(void (*sink)(const char* bytes));

wb_err_t wbus_register(const wb_object_t* obj);

// Positional call: argv[i] is checked against methods->args[i]. This is what the
// legacy console commands funnel through, so their on-air behaviour cannot drift.
wb_err_t wbus_call(const char* obj, const char* method, int argc, char* const* argv,
                   wb_reply_t* reply);

// Keyword call: argv is "name=value" pairs. This is the ubus-shaped form used by
// the CALL command, and the one a future transport should prefer.
wb_err_t wbus_call_named(const char* obj, const char* method, int argc, char* const* argv,
                         wb_reply_t* reply);

void wbus_list(wb_reply_t* reply);
void wbus_describe(const char* obj, wb_reply_t* reply);

// Events. Nothing is printed unless a transport subscribed, so enabling the bus
// does not change the console's existing output.
bool wbus_subscribe(const char* pattern);  // NULL clears
void wbus_subscribe_clear(void);
void wbus_emit(const char* topic, const char* kv);

// Handler helpers.
const wb_value_t* wb_arg(const wb_args_t* args, const char* name);
long wb_arg_num(const wb_args_t* args, const char* name);
bool wb_arg_mac(const wb_args_t* args, const char* name, uint8_t out[6]);
void wb_reply_line(wb_reply_t* reply, const char* text);
void wb_reply_printf(wb_reply_t* reply, const char* fmt, ...);

#ifdef __cplusplus
}
#endif

#endif  // WBUS_H
