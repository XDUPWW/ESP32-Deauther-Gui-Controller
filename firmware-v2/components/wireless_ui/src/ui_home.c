// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 触摸界面：一级菜单（WiFi / BLE / Touch / 诊断），二级是 WiFi 攻击格子。
// 版式沿用旧工程：标题和状态各一行，中间一屏内容，最底下两行日志；
// 按钮一行三个、行高 34，手指点得准比一屏塞下所有东西重要。
// 攻击格子从 wbus 注册表长出来：对象写了 title 就占一格，点了发 <obj>.start idx=N，
// 再点一次是停；谁在跑就给谁染色，别让人猜。
// 各页都是 body 下的容器，切页只翻 hidden 标志，屏上对象数固定。

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
#define STATUS_MAX 48
#define RUNNING_MAX 16

#define ROW_H 33
#define BTN_H 29
#define GRID_COLS 3
#define TARGET_ROWS 24
#define TARGET_ROW_H 26

typedef enum {
    SCR_MENU = 0,
    SCR_WIFI,
    SCR_TARGETS,
    SCR_BLE,
    SCR_TOUCH,
    SCR_COUNT,
} screen_t;

typedef struct {
    const wb_object_t *object;
    lv_obj_t *button;
    lv_obj_t *label;
} atk_cell_t;

static lv_obj_t *s_screens[SCR_COUNT];
static lv_obj_t *s_status;
static lv_obj_t *s_log;
static lv_obj_t *s_target_list;
static lv_obj_t *s_touch_label;

static atk_cell_t s_atk[WB_MAX_OBJECTS];
static size_t s_atk_n;

static lv_style_t s_run_style;
static screen_t s_screen = SCR_MENU;

static char s_log_text[LOG_TEXT_MAX];
static char s_log_lines[LOG_LINES][LOG_COLS + 1];

static uint32_t s_target = 1;
static uint32_t s_target_seen;
static uint32_t s_last_target_ms;
static char s_running[RUNNING_MAX];
static char s_status_cache[STATUS_MAX];
static uint32_t s_uptime_s;
static uint32_t s_heap_kb;
static bool s_led_on;

static void rebuild_status(void);
static void refresh_run_marks(void);
static void rebuild_target_rows(void);
static void show_screen(screen_t target);

static void on_open_wifi(lv_event_t *event);
static void on_open_ble(lv_event_t *event);
static void on_open_touch(lv_event_t *event);
static void on_nav_menu(lv_event_t *event);
static void on_nav_scan(lv_event_t *event);
static void on_nav_targets(lv_event_t *event);
static void on_nav_stop(lv_event_t *event);
static void on_nav_led(lv_event_t *event);
static void on_line(lv_event_t *event);
static void on_attack(lv_event_t *event);
static void on_target(lv_event_t *event);
static void on_ble_adv(lv_event_t *event);
static void on_touch_test(lv_event_t *event);

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
    // 起攻击失败时把"正在跑"撤掉，别让界面骗人
    if (strncmp(line, "ERR ", 4) == 0 && s_running[0] != 0) {
        s_running[0] = 0;
        refresh_run_marks();
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
    if (s_screen == SCR_TARGETS && wt_count() != s_target_seen) {
        const uint32_t now = (uint32_t)lv_tick_get();
        if ((uint32_t)(now - s_last_target_ms) > 400) {
            s_last_target_ms = now;
            rebuild_target_rows();
        }
    }
}

// ---- 控件 ----

static lv_obj_t *make_row(lv_obj_t *parent, int32_t height) {
    lv_obj_t *row = lv_obj_create(parent);
    lv_obj_set_width(row, lv_pct(100));
    lv_obj_set_height(row, height);
    lv_obj_set_style_pad_all(row, 0, 0);
    lv_obj_set_style_pad_column(row, 4, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    return row;
}

static lv_obj_t *make_btn(lv_obj_t *parent, const char *text, lv_event_cb_t cb, void *user,
                          int32_t height) {
    lv_obj_t *btn = lv_button_create(parent);
    lv_obj_set_flex_grow(btn, 1);
    lv_obj_set_height(btn, height);
    lv_obj_set_style_pad_all(btn, 2, 0);
    lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, user);
    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_DOTS);
    lv_obj_set_width(label, lv_pct(100));
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(label);
    return btn;
}

static lv_obj_t *make_screen(lv_obj_t *parent) {
    lv_obj_t *page = lv_obj_create(parent);
    lv_obj_set_width(page, lv_pct(100));
    lv_obj_set_flex_grow(page, 1);
    lv_obj_set_style_pad_all(page, 0, 0);
    lv_obj_set_style_pad_row(page, 2, 0);
    lv_obj_set_style_border_width(page, 0, 0);
    lv_obj_set_style_bg_opa(page, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(page, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(page, LV_FLEX_FLOW_COLUMN);
    lv_obj_add_flag(page, LV_OBJ_FLAG_HIDDEN);
    return page;
}

static void show_screen(screen_t target) {
    for (int i = 0; i < SCR_COUNT; i++) {
        if (s_screens[i] == NULL) {
            continue;
        }
        if (i == (int)target) {
            lv_obj_remove_flag(s_screens[i], LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_screens[i], LV_OBJ_FLAG_HIDDEN);
        }
    }
    s_screen = target;
    // 进目标页时重排一次；从目标行自己点回来时不走这里，别在事件里删自己
    if (target == SCR_TARGETS) {
        rebuild_target_rows();
    }
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

static void refresh_run_marks(void) {
    for (size_t i = 0; i < s_atk_n; i++) {
        atk_cell_t *cell = &s_atk[i];
        const bool running = strcmp(s_running, cell->object->name) == 0;
        char text[40];
        snprintf(text, sizeof(text), "%s%s", running ? "> " : "", cell->object->title);
        lv_label_set_text(cell->label, text);
        if (running) {
            lv_obj_add_style(cell->button, &s_run_style, 0);
        } else {
            lv_obj_remove_style(cell->button, &s_run_style, 0);
        }
    }
}

static void on_attack(lv_event_t *event) {
    const wb_object_t *object = (const wb_object_t *)lv_event_get_user_data(event);
    if (object == NULL) {
        return;
    }
    char line[48];
    if (s_running[0] != '\0' && strcmp(s_running, object->name) == 0) {
        // 再点一次就是停
        snprintf(line, sizeof(line), "%s.stop", object->name);
        submit_line(line);
        s_running[0] = '\0';
    } else {
        // 一次只跑一个：先把上一个停掉，两个模块抢信道只会互相踩
        if (s_running[0] != '\0') {
            snprintf(line, sizeof(line), "%s.stop", s_running);
            submit_line(line);
        }
        if (method_takes_idx(object)) {
            snprintf(line, sizeof(line), "%s.start idx=%u", object->name, (unsigned)s_target);
        } else {
            snprintf(line, sizeof(line), "%s.start", object->name);
        }
        submit_line(line);
        strncpy(s_running, object->name, sizeof(s_running) - 1);
        s_running[sizeof(s_running) - 1] = 0;
    }
    refresh_run_marks();
    rebuild_status();
}

static void on_target(lv_event_t *event) {
    const uint32_t index = (uint32_t)(uintptr_t)lv_event_get_user_data(event);
    if (index == 0) {
        return;
    }
    s_target = index;
    (void)wt_select(index - 1);
    rebuild_status();
    show_screen(SCR_WIFI);
}

// ---- 各页 ----

static void build_menu(lv_obj_t *page) {
    lv_obj_t *r1 = make_row(page, 42);
    make_btn(r1, "WiFi Attack", on_open_wifi, NULL, 40);
    lv_obj_t *r2 = make_row(page, 38);
    make_btn(r2, "BLE Attack", on_open_ble, NULL, 36);
    lv_obj_t *r3 = make_row(page, ROW_H);
    make_btn(r3, "Touch", on_open_touch, NULL, BTN_H);
    make_btn(r3, "Info", on_line, (void *)"system.info", BTN_H);
    make_btn(r3, "LED", on_nav_led, NULL, BTN_H);
    lv_obj_t *r4 = make_row(page, ROW_H);
    make_btn(r4, "Calibrate", on_line, (void *)"ui.touch_cal reset=1", BTN_H);
}

static void build_wifi(lv_obj_t *page) {
    s_atk_n = 0;
    lv_obj_t *row = NULL;
    for (size_t i = 0; i < wb_count() && s_atk_n < WB_MAX_OBJECTS; i++) {
        const wb_object_t *object = wb_at(i);
        if (object == NULL || object->title == NULL) {
            continue;
        }
        if ((s_atk_n % GRID_COLS) == 0) {
            row = make_row(page, ROW_H);
        }
        lv_obj_t *btn = make_btn(row, object->title, on_attack, (void *)object, BTN_H);
        s_atk[s_atk_n].object = object;
        s_atk[s_atk_n].button = btn;
        s_atk[s_atk_n].label = lv_obj_get_child(btn, 0);
        s_atk_n++;
    }
    if (s_atk_n == 0) {
        lv_obj_t *label = lv_label_create(page);
        lv_label_set_text(label, "no attack registered");
    }
    lv_obj_t *nav = make_row(page, ROW_H);
    make_btn(nav, "Scan", on_nav_scan, NULL, BTN_H);
    make_btn(nav, "Targets", on_nav_targets, NULL, BTN_H);
    make_btn(nav, "Stop", on_nav_stop, NULL, BTN_H);
    make_btn(nav, "Back", on_nav_menu, NULL, BTN_H);
}

static void build_targets_page(lv_obj_t *page) {
    s_target_list = lv_obj_create(page);
    lv_obj_set_width(s_target_list, lv_pct(100));
    lv_obj_set_flex_grow(s_target_list, 1);
    lv_obj_set_style_pad_all(s_target_list, 2, 0);
    lv_obj_set_style_pad_row(s_target_list, 3, 0);
    lv_obj_set_style_border_width(s_target_list, 1, 0);
    lv_obj_set_flex_flow(s_target_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scroll_dir(s_target_list, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(s_target_list, LV_SCROLLBAR_MODE_AUTO);

    lv_obj_t *nav = make_row(page, ROW_H);
    make_btn(nav, "Scan", on_nav_scan, NULL, BTN_H);
    make_btn(nav, "Back", on_nav_menu, NULL, BTN_H);
}

static void build_ble(lv_obj_t *page) {
    if (wb_find("ble") == NULL) {
        lv_obj_t *label = lv_label_create(page);
        lv_label_set_text(label, "BLE not in this build");
    } else {
        lv_obj_t *r1 = make_row(page, ROW_H);
        make_btn(r1, "Scan", on_line, (void *)"ble.scan action=start duration=10000", BTN_H);
        make_btn(r1, "Peers", on_line, (void *)"ble.scan action=list", BTN_H);
        make_btn(r1, "Scan Stop", on_line, (void *)"ble.scan action=stop", BTN_H);
        lv_obj_t *r2 = make_row(page, ROW_H);
        make_btn(r2, "Adv", on_ble_adv, NULL, BTN_H);
        make_btn(r2, "Adv Stop", on_line, (void *)"ble.adv action=stop", BTN_H);
        make_btn(r2, "Info", on_line, (void *)"ble.info", BTN_H);
        lv_obj_t *r3 = make_row(page, ROW_H);
        make_btn(r3, "Random Addr", on_line, (void *)"ble.addr addr=random", BTN_H);
    }
    lv_obj_t *nav = make_row(page, ROW_H);
    make_btn(nav, "Back", on_nav_menu, NULL, BTN_H);
}

static void build_touch(lv_obj_t *page) {
    lv_obj_t *pad = lv_obj_create(page);
    lv_obj_set_width(pad, lv_pct(100));
    lv_obj_set_flex_grow(pad, 1);
    lv_obj_remove_flag(pad, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(pad, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_border_width(pad, 1, 0);
    lv_obj_set_style_border_color(pad, lv_color_hex(0x30A0E0), 0);
    lv_obj_add_event_cb(pad, on_touch_test, LV_EVENT_CLICKED, NULL);

    s_touch_label = lv_label_create(pad);
    lv_label_set_text(s_touch_label, "tap anywhere");
    lv_obj_set_style_text_align(s_touch_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(s_touch_label);

    lv_obj_t *nav = make_row(page, ROW_H);
    make_btn(nav, "Back", on_nav_menu, NULL, BTN_H);
}

static void rebuild_target_rows(void) {
    if (s_target_list == NULL) {
        return;
    }
    lv_obj_clean(s_target_list);
    const uint32_t total = wt_count();
    s_target_seen = total;
    s_last_target_ms = (uint32_t)lv_tick_get();
    if (total == 0) {
        lv_obj_t *label = lv_label_create(s_target_list);
        lv_label_set_text(label, "tap Scan first");
        return;
    }
    uint32_t shown = 0;
    for (uint32_t i = 0; i < total && shown < TARGET_ROWS; i++) {
        const wt_entry_t *entry = wt_at(i);
        if (entry == NULL || entry->kind != WT_KIND_AP) {
            continue;
        }
        char ssid[18];
        snprintf(ssid, sizeof(ssid), "%.16s", entry->ssid[0] != 0 ? entry->ssid : "(hidden)");
        char text[48];
        snprintf(text, sizeof(text), "%s%u %s ch%u %d", (i + 1 == s_target) ? "> " : "",
                 (unsigned)(i + 1), ssid, (unsigned)entry->channel, (int)entry->rssi);
        lv_obj_t *btn = lv_button_create(s_target_list);
        lv_obj_set_width(btn, lv_pct(100));
        lv_obj_set_height(btn, TARGET_ROW_H);
        lv_obj_set_style_pad_all(btn, 2, 0);
        lv_obj_add_event_cb(btn, on_target, LV_EVENT_CLICKED, (void *)(uintptr_t)(i + 1));
        lv_obj_t *label = lv_label_create(btn);
        lv_label_set_text(label, text);
        lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_DOTS);
        lv_obj_set_width(label, lv_pct(100));
        lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_LEFT, 0);
        lv_obj_align(label, LV_ALIGN_LEFT_MID, 4, 0);
        shown++;
    }
    if (shown == 0) {
        lv_obj_t *label = lv_label_create(s_target_list);
        lv_label_set_text(label, "no AP yet, tap Scan");
    }
}

// ---- 导航 ----

static void on_open_wifi(lv_event_t *event) {
    (void)event;
    show_screen(SCR_WIFI);
}

static void on_open_ble(lv_event_t *event) {
    (void)event;
    show_screen(SCR_BLE);
}

static void on_open_touch(lv_event_t *event) {
    (void)event;
    show_screen(SCR_TOUCH);
}

static void on_nav_menu(lv_event_t *event) {
    (void)event;
    show_screen(SCR_MENU);
}

static void on_nav_targets(lv_event_t *event) {
    (void)event;
    show_screen(SCR_TARGETS);
}

static void on_nav_scan(lv_event_t *event) {
    (void)event;
    submit_line("scan.ap");
    show_screen(SCR_TARGETS);
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
    refresh_run_marks();
    rebuild_status();
}

static void on_nav_led(lv_event_t *event) {
    (void)event;
    s_led_on = !s_led_on;
    plat_led_set(s_led_on);
    ui_home_push_line(s_led_on ? "led on" : "led off");
}

static void on_line(lv_event_t *event) {
    const char *line = (const char *)lv_event_get_user_data(event);
    if (line != NULL) {
        submit_line(line);
    }
}

static void on_ble_adv(lv_event_t *event) {
    (void)event;
    // adv 得先设内容再开，空广播串打不出去
    submit_line("ble.adv action=set name=AirBench");
    submit_line("ble.adv action=start itvl=100");
}

static void on_touch_test(lv_event_t *event) {
    (void)event;
    lv_indev_t *indev = lv_indev_active();
    if (indev == NULL || s_touch_label == NULL) {
        return;
    }
    lv_point_t point;
    lv_indev_get_point(indev, &point);
    char text[32];
    snprintf(text, sizeof(text), "x=%d y=%d", (int)point.x, (int)point.y);
    lv_label_set_text(s_touch_label, text);
    ui_home_push_line(text);
}

// ---- 搭界面 ----

void ui_home_create(void) {
    lv_style_init(&s_run_style);
    lv_style_set_bg_color(&s_run_style, lv_color_hex(0xE07020));
    lv_style_set_text_color(&s_run_style, lv_color_hex(0xFFFFFF));

    lv_obj_t *root = lv_screen_active();
    lv_obj_clean(root);
    lv_obj_set_style_pad_all(root, 4, 0);
    lv_obj_set_style_pad_row(root, 3, 0);
    lv_obj_set_flex_flow(root, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(root, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    lv_obj_t *head = make_row(root, 18);
    lv_obj_set_flex_align(head, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    lv_obj_t *title = lv_label_create(head);
    lv_label_set_text(title, "AirBench");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);

    s_status = lv_label_create(head);
    lv_label_set_long_mode(s_status, LV_LABEL_LONG_MODE_CLIP);
    lv_obj_set_width(s_status, 200);
    lv_obj_set_style_text_align(s_status, LV_TEXT_ALIGN_RIGHT, 0);
    lv_obj_set_style_text_color(s_status, lv_color_hex(0x666666), 0);
    rebuild_status();

    lv_obj_t *body = lv_obj_create(root);
    lv_obj_set_width(body, lv_pct(100));
    lv_obj_set_flex_grow(body, 1);
    lv_obj_set_style_pad_all(body, 0, 0);
    lv_obj_set_style_border_width(body, 0, 0);
    lv_obj_set_style_bg_opa(body, LV_OPA_TRANSP, 0);
    lv_obj_remove_flag(body, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(body, LV_FLEX_FLOW_COLUMN);

    s_screens[SCR_MENU] = make_screen(body);
    s_screens[SCR_WIFI] = make_screen(body);
    s_screens[SCR_TARGETS] = make_screen(body);
    s_screens[SCR_BLE] = make_screen(body);
    s_screens[SCR_TOUCH] = make_screen(body);

    build_menu(s_screens[SCR_MENU]);
    build_wifi(s_screens[SCR_WIFI]);
    build_targets_page(s_screens[SCR_TARGETS]);
    build_ble(s_screens[SCR_BLE]);
    build_touch(s_screens[SCR_TOUCH]);

    s_log = lv_label_create(root);
    lv_obj_set_width(s_log, lv_pct(100));
    lv_obj_set_height(s_log, 33);
    lv_label_set_long_mode(s_log, LV_LABEL_LONG_MODE_DOTS);
    lv_obj_set_style_text_color(s_log, lv_color_hex(0x666666), 0);
    lv_label_set_text(s_log, "");

    show_screen(SCR_MENU);
    refresh_run_marks();
    ui_home_push_line("ui ready");
}
