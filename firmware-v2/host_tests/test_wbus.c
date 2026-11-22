// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// wbus 的脱机测试：注册表、调用、参数策略、回执、事件。用系统 gcc 直接编译。

#include <stdio.h>
#include <string.h>

#include "wbus/wbus.h"

static int g_pass;
static int g_fail;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("  FAIL %s (%s:%d)\n", what, __FILE__, __LINE__);          \
        }                                                                    \
    } while (0)

#define CHECK_LINE(needle) CHECK(has_line(needle), "line contains: " needle)

static char g_lines[10][WB_LINE_MAX];
static int g_line_count;

static void sink(void *ctx, const char *line) {
    (void)ctx;
    if (g_line_count < (int)(sizeof(g_lines) / sizeof(g_lines[0]))) {
        strncpy(g_lines[g_line_count], line, WB_LINE_MAX - 1);
        g_lines[g_line_count][WB_LINE_MAX - 1] = '\0';
        g_line_count++;
    }
}

static void reset_lines(void) {
    g_line_count = 0;
    memset(g_lines, 0, sizeof(g_lines));
}

static bool has_line(const char *needle) {
    for (int i = 0; i < g_line_count; i++) {
        if (strstr(g_lines[i], needle) != NULL) {
            return true;
        }
    }
    return false;
}

static bool last_line_is(const char *expected) {
    return g_line_count > 0 && strcmp(g_lines[g_line_count - 1], expected) == 0;
}

static char g_last_seen[WB_LINE_MAX];

static esp_err_t demo_show(wb_args_t *args, wb_reply_t *reply) {
    snprintf(g_last_seen, sizeof(g_last_seen), "idx=%u cnt=%u ch=%d name=%s mac=%d",
             (unsigned)wb_args_u32(args, "idx"), (unsigned)wb_args_u32(args, "cnt"),
             wb_args_channel(args, "ch"), wb_args_str(args, "name"),
             wb_args_mac(args, "mac", (uint8_t[6]){0}) ? 1 : 0);
    wb_reply_line(reply, "%s", g_last_seen);
    return ESP_OK;
}

static esp_err_t demo_flag(wb_args_t *args, wb_reply_t *reply) {
    wb_reply_line(reply, "on=%d", wb_args_bool(args, "on") ? 1 : 0);
    return ESP_OK;
}

static esp_err_t demo_fail(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    (void)reply;
    return ESP_ERR_NOT_SUPPORTED;
}

static esp_err_t demo_two_lines(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    wb_reply_line(reply, "first");
    wb_reply_line(reply, "second");
    return ESP_OK;
}

static const wb_policy_t kShowPolicy[] = {
    {.name = "idx", .type = WB_T_U32, .required = true, .min = 1, .max = 64},
    {.name = "cnt", .type = WB_T_U32, .required = false, .min = 1, .max = 8, .def = 5},
    {.name = "ch", .type = WB_T_CHANNEL, .required = false, .min = 0, .max = 196, .def = 0},
    {.name = "name", .type = WB_T_STR, .required = false},
    {.name = "mac", .type = WB_T_MAC, .required = false},
};

static const wb_policy_t kFlagPolicy[] = {
    {.name = "on", .type = WB_T_BOOL, .required = false, .def = 0},
};

static const wb_method_t kMethods[] = {
    {"show", demo_show, "[idx=1..64]", kShowPolicy, 5},
    {"flag", demo_flag, "[on=bool]", kFlagPolicy, 1},
    {"fail", demo_fail, "", NULL, 0},
    {"two", demo_two_lines, "", NULL, 0},
};

static const wb_object_t kObject = {"demo", "Demo object", kMethods, 4};

typedef struct {
    const char *filter;
    int hits;
    char last[WB_LINE_MAX];
} sub_t;

static sub_t g_sub_a;
static sub_t g_sub_b;

static void on_event_a(void *ctx, const char *line) {
    sub_t *s = (sub_t *)ctx;
    s->hits++;
    strncpy(s->last, line, sizeof(s->last) - 1);
}

static void on_event_b(void *ctx, const char *line) {
    (void)line;
    ((sub_t *)ctx)->hits++;
}

static void test_registry(void) {
    printf("registry\n");
    CHECK(wb_register(&kObject) == ESP_OK, "register object");
    CHECK(wb_register(&kObject) == ESP_ERR_INVALID_STATE, "duplicate rejected");
    CHECK(wb_find("demo") == &kObject, "find by name");
    CHECK(wb_find("nope") == NULL, "find missing returns null");
    CHECK(wb_count() == 1, "count");
    CHECK(wb_at(0) == &kObject, "at(0)");
    CHECK(wb_at(1) == NULL, "at past end");
}

static void test_call_errors(void) {
    printf("call errors\n");
    reset_lines();
    CHECK(wb_call_line("nope.show idx=1", sink, NULL) != ESP_OK, "unknown object fails");
    CHECK_LINE("ERR nope.show: unknown object");

    reset_lines();
    CHECK(wb_call_line("demo.nope", sink, NULL) != ESP_OK, "unknown method fails");
    CHECK_LINE("ERR demo.nope: unknown method");

    reset_lines();
    CHECK(wb_call_line("demo", sink, NULL) != ESP_OK, "missing dot fails");
    CHECK_LINE("ERR syntax: expect object.method");

    reset_lines();
    CHECK(wb_call_line("demo.show", sink, NULL) != ESP_OK, "missing required fails");
    CHECK_LINE("idx is required");

    reset_lines();
    CHECK(wb_call_line("demo.show idx=1 bogus=2", sink, NULL) != ESP_OK, "unknown arg fails");
    CHECK_LINE("bogus is not a parameter of show");

    reset_lines();
    CHECK(wb_call_line("demo.show idx", sink, NULL) != ESP_OK, "bare token fails");
    CHECK_LINE("expect key=value");

    reset_lines();
    CHECK(wb_call_line("demo.show idx=0", sink, NULL) != ESP_OK, "below range fails");
    CHECK_LINE("idx must be 1..64");

    reset_lines();
    CHECK(wb_call_line("demo.show idx=65", sink, NULL) != ESP_OK, "above range fails");
    CHECK_LINE("idx must be 1..64");

    reset_lines();
    CHECK(wb_call_line("demo.show idx=abc", sink, NULL) != ESP_OK, "non-number fails");
    CHECK_LINE("idx is not a number");

    reset_lines();
    CHECK(wb_call_line("demo.show idx=1 mac=zz:11", sink, NULL) != ESP_OK, "bad mac fails");
    CHECK_LINE("mac must be aa:bb:cc:dd:ee:ff");

    reset_lines();
    CHECK(wb_call_line("demo.show idx=1 name=a name=b", sink, NULL) == ESP_OK,
          "duplicate key tolerated");
    CHECK(strstr(g_last_seen, "name=a") != NULL, "duplicate key keeps the first value");
}

static void test_args(void) {
    printf("argument handling\n");
    reset_lines();
    CHECK(wb_call_line("demo.show idx=7", sink, NULL) == ESP_OK, "call ok");
    CHECK(last_line_is("OK demo.show"), "success line");
    CHECK(strstr(g_last_seen, "idx=7") != NULL, "idx parsed");
    CHECK(strstr(g_last_seen, "cnt=5") != NULL, "default applied");
    CHECK(strstr(g_last_seen, "ch=0") != NULL, "channel default is auto(0)");
    CHECK(strstr(g_last_seen, "mac=0") != NULL, "absent mac reported false");

    reset_lines();
    CHECK(wb_call_line("demo.show idx=3 ch=11 name=hello mac=FF:00:01:02:03:04", sink, NULL) ==
              ESP_OK,
          "call with all args");
    CHECK(strstr(g_last_seen, "ch=11") != NULL, "explicit channel");
    CHECK(strstr(g_last_seen, "name=hello") != NULL, "string arg");
    CHECK(strstr(g_last_seen, "mac=1") != NULL, "mac parsed");

    reset_lines();
    CHECK(wb_call_line("demo.show count=\"a b\" idx=2", sink, NULL) != ESP_OK,
          "unknown quoted key rejected");

    reset_lines();
    CHECK(wb_call_line("demo.show idx=2 name=\"a b\"", sink, NULL) == ESP_OK,
          "quoted value with space");
    CHECK(strstr(g_last_seen, "name=a b") != NULL, "quotes stripped, space kept");

    reset_lines();
    CHECK(wb_call_line("demo.show   idx=9   cnt=8   ", sink, NULL) == ESP_OK,
          "extra whitespace tolerated");
    CHECK(strstr(g_last_seen, "idx=9") != NULL, "idx after whitespace");
    CHECK(strstr(g_last_seen, "cnt=8") != NULL, "cnt after whitespace");

    reset_lines();
    CHECK(wb_call_line("demo.flag on=true", sink, NULL) == ESP_OK, "bool true");
    CHECK_LINE("on=1");
    reset_lines();
    CHECK(wb_call_line("demo.flag on=off", sink, NULL) == ESP_OK, "bool off");
    CHECK_LINE("on=0");
    reset_lines();
    CHECK(wb_call_line("demo.flag on=maybe", sink, NULL) != ESP_OK, "bool invalid");
    CHECK_LINE("on is not a number");
}

static void test_reply(void) {
    printf("reply\n");
    reset_lines();
    CHECK(wb_call_line("demo.two", sink, NULL) == ESP_OK, "multi line ok");
    CHECK(g_line_count == 3, "two data lines plus OK");
    CHECK(strcmp(g_lines[0], "first") == 0, "first line");
    CHECK(strcmp(g_lines[1], "second") == 0, "second line");
    CHECK(last_line_is("OK demo.two"), "OK last");

    reset_lines();
    CHECK(wb_call_line("demo.fail", sink, NULL) != ESP_OK, "handler error surfaces");
    CHECK_LINE("ERR demo.fail: failed (ESP_ERR_NOT_SUPPORTED)");
}

static void test_events(void) {
    printf("events\n");
    memset(&g_sub_a, 0, sizeof(g_sub_a));
    memset(&g_sub_b, 0, sizeof(g_sub_b));
    CHECK(wb_subscribe("demo", on_event_a, &g_sub_a) == ESP_OK, "subscribe demo");
    CHECK(wb_subscribe("other", on_event_b, &g_sub_b) == ESP_OK, "subscribe other");

    wb_emit("demo", "state", "active=1 frames=%u", 12u);
    CHECK(g_sub_a.hits == 1, "matching subscriber called");
    CHECK(g_sub_b.hits == 0, "non-matching subscriber skipped");
    CHECK(strcmp(g_sub_a.last, "EVT demo.state active=1 frames=12") == 0, "event line format");

    wb_emit("demo", "idle", NULL);
    CHECK(strcmp(g_sub_a.last, "EVT demo.idle") == 0, "event without payload");
}

static void test_limits(void) {
    printf("limits\n");
    reset_lines();
    CHECK(wb_call_line("demo.show idx=1 cnt=2 ch=3 name=x", sink, NULL) == ESP_OK, "4 args fit");
    CHECK(wb_call_line("demo.show", sink, NULL) != ESP_OK, "empty call rejected");

    char long_line[WB_LINE_MAX * 3];
    memset(long_line, 'a', sizeof(long_line) - 1);
    long_line[sizeof(long_line) - 1] = '\0';
    reset_lines();
    wb_call_line(long_line, sink, NULL);
    CHECK(g_line_count >= 1, "overlong line answered, not dropped silently");
    CHECK_LINE("ERR ");

    char many[WB_LINE_MAX];
    snprintf(many, sizeof(many), "demo.show idx=1 a=1 b=2 c=3 d=4 e=5 f=6 g=7 h=8 i=9");
    reset_lines();
    CHECK(wb_call_line(many, sink, NULL) != ESP_OK, "too many args rejected");
    CHECK_LINE("too many arguments");
}

int main(void) {
    printf("wbus host tests\n");
    test_registry();
    test_call_errors();
    test_args();
    test_reply();
    test_events();
    test_limits();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
