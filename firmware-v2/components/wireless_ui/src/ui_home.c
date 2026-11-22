// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 主界面：一行状态、一个可滚动列表、两行日志、两行按键。
// 攻击列表直接从 wbus 注册表长出来：对象声明了 title 就上一个按钮，点了发 <obj>.start idx=N。
// 攻击 / 目标两副面孔共用同一个 body 容器，切换时清空重建，屏上对象数一直很小
// （CYD 空闲堆只有 ~40 KB，旧工程五个独立页面就把池子吃穿过）。

#include "ui_home.h"

#include <stdio.h>
#include <string.h>

#include "platform/plat_led.h"
#include "transport/transport.h"
#include "wbus/wbus.h"
#include "wtarget/wtarget.h"

#define LOG_LINES 2
#define LOG_COLS 44
#define LOG_TEXT_MAX (LOG_LINES * (LOG_COLS + 2) + 1)
#define RUNNING_MAX 16
#define TARGET_LIST_MAX 16
#define STATUS_MAX 48

typedef enum {
    VIEW_ATTACK = 0,
    VIEW_TARGET = 1,
} view_t;

static lv_obj_t *s_status;
static lv_obj_t *s_body;
static lv_obj_t *s_log;

static char s_log_text[LOG_TEXT_MAX];
static char s_log_lines[LOG_LINES][LOG_COLS + 1];

static view_t s_view = VIEW_ATTACK;
static bool s_body_dirty;
static uint32_t s_built_targets;   // 上一次建目标列表时表里有几条
static uint32_t s_last_target_ms;
static uint32_t s_target = 1;
static char s_running[RUNNING_MAX];
static char s_status_cache[STATUS_MAX];
static uint32_t s_uptime_s;
static uint32_t s_heap_kb;
static bool s_led_on;

static void rebuild_body(void);
static void rebuild_status(void);

static void submit_line(const char *line) {
    (void)transport_submit(line);
}

// ---- 日志 ----

static void rebuild_log(void) {
    size_t used = 0;
    s_log_text[0] = '\0';
    for (int i = 0; i < LOG_LINES; i++) {
        if (s_log_lines[i][0] == '\0') {
            continue;
        }
        const int n = snprintf(s_log_text + used, sizeof(s_log_text) - used, "%s\n",
                               s_log_lines[i]);
        if (n <= 0) {
            break;
        }
        used += (size_t)n;
        if (used >= sizeof(s_log_text) - 1) {
            break;
        }
    }
    if (s_log != NULL) {
        lv_label_set_text(s_log, s_log_text);
    }
}

void ui_home_push_line(const char *line) {
    if (line == NULL) {
        return;
    }
    for (int i = 1; i < LOG_LINES; i++) {
        memcpy(s_log_lines[i - 1], s_log_lines[i], sizeof(s_log_lines[0]));
    }
    strncpy(s_log_lines[LOG_LINES - 1], line, LOG_COLS);
    s_log_lines[LOG_LINES - 1][LOG_COLS] = 0;
    // 启动攻击失败时把"正在跑"的标记撤掉，别让界面骗人
    if (strncmp(line, "ERR ", 4) == 0 && s_running[0] != 0) {
        s_running[0] = 0;
        s_body_dirty = true;
        rebuild_status();
    }
    rebuild_log();
}

// ---- 状态行 ----

static void rebuild_status(void) {
    if (s_status == NULL) {
        return;
    }
    char text[STATUS_MAX];
    if (s_running[0] != '\0') {
        snprintf(text, sizeof(text), "up %us %uKB tgt %u > %s", (unsigned)s_uptime_s,
                 (unsigned)s_heap_kb, (unsigned)s_target, s_running);
    } else {
        snprintf(text, sizeof(text), "up %us %uKB tgt %u", (unsigned)s_uptime_s,
                 (unsigned)s_heap_kb, (unsigned)s_target);
    }
    if (strcmp(text, s_status_cache) == 0) {
        return;
    }
    strncpy(s_status_cache, text, sizeof(s_status_cache) - 1);
    s_status_cache[sizeof(s_status_cache) - 1] = '\0';
    lv_label_set_text(s_status, text);
}

void ui_home_refresh(uint32_t uptime_s, uint32_t heap_kb) {
    s_uptime_s = uptime_s;
    s_heap_kb = heap_kb;
    rebuild_status();
    // 扫描在控制台任务里跑，结束时间不确定：目标列表按"表里有几条"自己刷新
    if (s_view == VIEW_TARGET) {
        const uint32_t now = (uint32_t)(lv_tick_get());
        if (wt_count() != s_built_targets && (uint32_t)(now - s_last_target_ms) > 400) {
            s_last_target_ms = now;
            s_body_dirty = true;
        }
    }
    if (s_body_dirty) {
        s_body_dirty = false;
        rebuild_body();
    }
}

// ---- 控件 ----

static lv_obj_t *make_row_button(lv_obj_t *parent, const char *text, lv_event_cb_t cb,
                                 void *user_data) {
    lv_obj_t *btn = lv_button_create(parent);
    lv_obj_set_width(btn, lv_pct(100));
    lv_obj_set_height(btn, 28);
    lv_obj_set_style_pad_all(btn, 4, 0);
    lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, user_data);
    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_DOTS);
    lv_obj_set_width(label, lv_pct(100));
    lv_obj_align(label, LV_ALIGN_LEFT_MID, 2, 0);
    return btn;
}

static lv_obj_t *make_row(lv_obj_t *root, int32_t height) {
    lv_obj_t *row = lv_obj_create(root);
    lv_obj_set_width(row, lv_pct(100));
    lv_obj_set_height(row, height);
    lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_set_style_pad_all(row, 0, 0);
    lv_obj_set_style_pad_column(row, 6, 0);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    return row;
}

static void make_nav_button(lv_obj_t *row, const char *text, lv_event_cb_t cb,
                            const char *payload) {
    lv_obj_t *btn = lv_button_create(row);
    lv_obj_set_flex_grow(btn, 1);
    lv_obj_set_height(btn, lv_pct(100));
    lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, (void *)payload);
    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_obj_center(label);
}

// ---- 点攻击：参数里有没有 idx 决定要不要带目标号 ----

static bool method_takes_idx(const wb_object_t *object) {
    for (uint8_t i = 0; i < object->n_methods; i++) {
        const wb_method_t *method = &object->methods[i];
        if (method->name == NULL || strcmp(method->name, "start") != 0) {
            continue;
        }
        for (uint8_t j = 0; j < method->n_policy; j++) {
            if (method->policy[j].name != NULL && strcmp(method->policy[j].name, "idx") == 0) {
                return true;
            }
        }
    }
    return false;
}

static void on_attack(lv_event_t *event) {
    const wb_object_t *object = (const wb_object_t *)lv_event_get_user_data(event);
    if (object == NULL) {
        return;
    }
    char line[48];
    if (s_running[0] != 0 && strcmp(s_running, object->name) == 0) {
        // 再点一次就是停
        snprintf(line, sizeof(line), "%s.stop", object->name);
        s_running[0] = 0;
    } else {
        // 参数表里声明了 idx 的模块才带目标号；probe 这类没有 idx 的直接 start
        if (method_takes_idx(object)) {
            snprintf(line, sizeof(line), "%s.start idx=%u", object->name, (unsigned)s_target);
        } else {
            snprintf(line, sizeof(line), "%s.start", object->name);
        }
        strncpy(s_running, object->name, sizeof(s_running) - 1);
        s_running[sizeof(s_running) - 1] = 0;
    }
    submit_line(line);
    rebuild_status();
    s_body_dirty = true;
}

static void on_target(lv_event_t *event) {
    const uint32_t index = (uint32_t)(uintptr_t)lv_event_get_user_data(event);
    if (index == 0) {
        return;
    }
    s_target = index;
    (void)wt_select(index - 1);
    s_view = VIEW_ATTACK;
    rebuild_status();
    s_body_dirty = true;
}

// ---- 两个视图 ----

static void build_attack_rows(lv_obj_t *parent) {
    uint32_t shown = 0;
    for (size_t i = 0; i < wb_count(); i++) {
        const wb_object_t *object = wb_at(i);
        if (object == NULL || object->title == NULL) {
            continue;
        }
        char text[40];
        snprintf(text, sizeof(text), "%s%s", strcmp(s_running, object->name) == 0 ? "> " : "",
                 object->title);
        make_row_button(parent, text, on_attack, (void *)object);
        shown++;
    }
    if (shown == 0) {
        lv_obj_t *label = lv_label_create(parent);
        lv_label_set_text(label, "no attack registered");
    }
}

static void build_target_rows(lv_obj_t *parent) {
    const uint32_t total = wt_count();
    s_built_targets = total;
    s_last_target_ms = (uint32_t)(lv_tick_get());
    if (total == 0) {
        lv_obj_t *label = lv_label_create(parent);
        lv_label_set_text(label, "tap Scan first");
        return;
    }
    const uint32_t cap = (total < TARGET_LIST_MAX) ? total : TARGET_LIST_MAX;
    for (uint32_t i = 0; i < cap; i++) {
        const wt_entry_t *entry = wt_at(i);
        if (entry == NULL || entry->kind != WT_KIND_AP) {
            continue;
        }
        char ssid[20];
        snprintf(ssid, sizeof(ssid), "%.18s", entry->ssid[0] != 0 ? entry->ssid : "(hidden)");
        char text[48];
        snprintf(text, sizeof(text), "%s%u %s ch%u %d", (i + 1 == s_target) ? "> " : "",
                 (unsigned)(i + 1), ssid, (unsigned)entry->channel, (int)entry->rssi);
        make_row_button(parent, text, on_target, (void *)(uintptr_t)(i + 1));
    }
}

static void rebuild_body(void) {
    if (s_body == NULL) {
        return;
    }
    lv_obj_clean(s_body);
    if (s_view == VIEW_TARGET) {
        build_target_rows(s_body);
    } else {
        build_attack_rows(s_body);
    }
}

// ---- 导航 ----

static void on_nav_attack(lv_event_t *event) {
    (void)event;
    s_view = VIEW_ATTACK;
    s_body_dirty = true;
}

static void on_nav_target(lv_event_t *event) {
    (void)event;
    s_view = VIEW_TARGET;
    s_body_dirty = true;
}

static void on_nav_scan(lv_event_t *event) {
    (void)event;
    s_view = VIEW_TARGET;
    submit_line("scan.ap");
    s_body_dirty = true;
}

static void on_nav_stop(lv_event_t *event) {
    (void)event;
    if (s_running[0] == '\0') {
        ui_home_push_line("nothing running");
        return;
    }
    char line[32];
    snprintf(line, sizeof(line), "%s.stop", s_running);
    submit_line(line);
    s_running[0] = '\0';
    rebuild_status();
    s_body_dirty = true;
}

static void on_nav_info(lv_event_t *event) {
    (void)event;
    submit_line("system.info");
}

static void on_nav_touch(lv_event_t *event) {
    (void)event;
    submit_line("system.touch");
}

static void on_nav_led(lv_event_t *event) {
    (void)event;
    s_led_on = !s_led_on;
    plat_led_set(s_led_on);
    ui_home_push_line(s_led_on ? "led on" : "led off");
}

static void on_nav_cal(lv_event_t *event) {
    (void)event;
    submit_line("ui.touch_cal reset=1");
}

// ---- 搭界面 ----

void ui_home_create(void) {
    lv_obj_t *root = lv_screen_active();
    lv_obj_set_style_bg_color(root, lv_color_hex(0x0E1116), 0);
    lv_obj_set_style_bg_opa(root, LV_OPA_COVER, 0);
    lv_obj_set_style_text_color(root, lv_color_hex(0xE6EDF3), 0);
    lv_obj_set_style_pad_all(root, 6, 0);
    lv_obj_set_style_pad_row(root, 4, 0);
    lv_obj_set_flex_flow(root, LV_FLEX_FLOW_COLUMN);

    lv_obj_t *header = make_row(root, 18);
    lv_obj_t *title = lv_label_create(header);
    lv_label_set_text(title, "AirBench");
    lv_obj_set_style_text_color(title, lv_color_hex(0x58A6FF), 0);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);

    s_status = lv_label_create(header);
    lv_obj_set_style_text_color(s_status, lv_color_hex(0x8B949E), 0);
    lv_obj_align(s_status, LV_ALIGN_RIGHT_MID, 0, 0);
    rebuild_status();

    s_body = lv_obj_create(root);
    lv_obj_set_width(s_body, lv_pct(100));
    lv_obj_set_flex_grow(s_body, 1);
    lv_obj_set_style_bg_color(s_body, lv_color_hex(0x161B22), 0);
    lv_obj_set_style_border_color(s_body, lv_color_hex(0x30363D), 0);
    lv_obj_set_style_border_width(s_body, 1, 0);
    lv_obj_set_style_radius(s_body, 6, 0);
    lv_obj_set_style_pad_all(s_body, 4, 0);
    lv_obj_set_style_pad_row(s_body, 4, 0);
    lv_obj_set_flex_flow(s_body, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scroll_dir(s_body, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(s_body, LV_SCROLLBAR_MODE_AUTO);

    s_log = lv_label_create(root);
    lv_obj_set_width(s_log, lv_pct(100));
    lv_obj_set_height(s_log, 32);
    lv_label_set_long_mode(s_log, LV_LABEL_LONG_MODE_DOTS);
    lv_obj_set_style_text_color(s_log, lv_color_hex(0xC9D1D9), 0);
    lv_label_set_text(s_log, "");

    lv_obj_t *nav = make_row(root, 30);
    make_nav_button(nav, "Atk", on_nav_attack, NULL);
    make_nav_button(nav, "Tgt", on_nav_target, NULL);
    make_nav_button(nav, "Scan", on_nav_scan, NULL);
    make_nav_button(nav, "Stop", on_nav_stop, NULL);

    lv_obj_t *diag = make_row(root, 26);
    make_nav_button(diag, "Info", on_nav_info, NULL);
    make_nav_button(diag, "Touch", on_nav_touch, NULL);
    make_nav_button(diag, "LED", on_nav_led, NULL);
    make_nav_button(diag, "Cal", on_nav_cal, NULL);

    rebuild_body();
    ui_home_push_line("ui ready");
}
