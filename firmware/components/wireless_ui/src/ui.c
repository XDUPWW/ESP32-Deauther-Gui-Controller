// Minimal touch UI built on top of LVGL. It owns no attack logic: pressing a
// button just emits the same command line the serial console accepts.
//
// First boot (or after `CALIBRATE`) runs a four-corner touch calibration and
// stores the result in NVS, so every board can be calibrated without reflashing.

#include "sdkconfig.h"

#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT

#include "wireless_ui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "calib.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lvgl.h"
#include "ui_port.h"

// UI font: project subset > LVGL built-in CJK subset > default Montserrat.
#if CONFIG_WIRELESS_UI_CJK_CUSTOM
LV_FONT_DECLARE(lv_font_ui_cjk);
#define UI_FONT (&lv_font_ui_cjk)
#elif CONFIG_LV_FONT_SOURCE_HAN_SANS_SC_16_CJK
#define UI_FONT (&lv_font_source_han_sans_sc_16_cjk)
#else
#define UI_FONT NULL
#endif

#define UI_W 320
#define UI_H 240
#define MAX_ROWS 64
#define LIST_ROWS 30  // visible rows per list (heap bound, the rest is scrollable data)
#define SSID_LEN 33

static const char *TAG = "wui";

typedef struct {
    uint16_t index;
    char ssid[SSID_LEN];
    char bssid[18];
    char info[24];
} row_t;

// Target picker popup: a modal card on lv_layer_top(). Both the deauth mode
// pages and the evil twin page open it instead of embedding a scrolling list,
// so the page itself stays small and the list gets the whole popup area.
static lv_obj_t *s_popup;
static lv_obj_t *s_popup_title;
static lv_obj_t *s_popup_list;
static lv_obj_t *s_status;
static lv_obj_t *s_log;
static lv_obj_t *s_mode_label;
static lv_obj_t *s_evil_label;
// CSA page: one target AP + a new channel, picked from a popup like the reason.
static lv_obj_t *s_csa_label;
static lv_obj_t *s_delba_label;
static void reason_row_clicked(lv_event_t *event);
// Deauth reason code picker on the mode page. Cycles through the three codes
// people actually use plus "random"; the firmware keeps the authoritative value.
static uint16_t s_reason_selected = 7;
static bool s_reason_random_selected = false;
static lv_obj_t *s_reason_label;
static lv_obj_t *s_reason_popup;
static lv_obj_t *s_reason_popup_title;
static lv_obj_t *s_reason_popup_list;
static int s_reason_popup_items;
static row_t s_rows[MAX_ROWS];
static int s_row_count;
static int s_selected = -1;
static int s_mode_kind = 0;
static int s_tap_pick = 0;  // popup row tap toggles [x] instead of single select
static wireless_ui_command_cb_t s_command_cb;
static bool s_picked[64];
static bool s_picked_before[64];   // snapshot for the popup's Back button
static int s_selected_before = -1;
static uint16_t s_item_row[LIST_ROWS];    // s_rows[] slot shown by each list item
static lv_obj_t *s_item_label[LIST_ROWS]; // its label, updated in place on tap
static int s_item_count;
static void rebuild_popup_list(void);
static void refresh_item_labels(void);
static void update_mode_label(void);
static void update_popup_title(void);

// Calibration state
static volatile bool s_pending_scan_begin;
static volatile bool s_pending_scan_end;
static volatile int s_pending_scan_count;
static char s_pending_log[48];
static bool s_pending_log_valid;
static char s_pending_status[80];
static bool s_pending_status_valid;

static bool s_ui_ready;
static bool s_calib_active;
static bool s_calib_prev_down;
static int s_calib_step;
static int s_calib_stable;
static int16_t s_calib_cand[2];
static TickType_t s_calib_started;
static int16_t s_calib_raw[4][2];
static lv_obj_t *s_calib_hint;
static lv_obj_t *s_calib_dots[4];

static const char *kCalibHints[4] = {
    "Tap TOP-LEFT corner",
    "Tap TOP-RIGHT corner",
    "Tap BOTTOM-RIGHT corner",
    "Tap BOTTOM-LEFT corner",
};
static const int16_t kDotX[4] = {WUI_CALIB_INSET, UI_W - 1 - WUI_CALIB_INSET,
                                 UI_W - 1 - WUI_CALIB_INSET, WUI_CALIB_INSET};
static const int16_t kDotY[4] = {WUI_CALIB_INSET, WUI_CALIB_INSET, UI_H - 1 - WUI_CALIB_INSET,
                                 UI_H - 1 - WUI_CALIB_INSET};

static void emit(const char *command) {
    if (s_command_cb != NULL) {
        s_command_cb(command);
    }
}

static void scan_clicked(lv_event_t *event) {
    (void)event;
    emit("SCAN");
}

static void stop_clicked(lv_event_t *event) {
    (void)event;
    emit("STOP");
}

static void row_text(int slot, char *text, size_t size) {
    const row_t *row = &s_rows[s_item_row[slot]];
    const int index = (int)row->index;
    const bool picked = index >= 0 && index < 64 && s_picked[index];
    const bool selected = index == s_selected;
    const char *mark = picked ? "[x] " : (selected ? "> " : "  ");
    if (row->bssid[0] != 0) {
        snprintf(text, size, "%s%u. %s | %s %s", mark, (unsigned)row->index, row->ssid, row->bssid,
                 row->info);
    } else {
        snprintf(text, size, "%s%u. %s | %s", mark, (unsigned)row->index, row->ssid, row->info);
    }
}

// Tapping a row only rewrites that row's label: deleting the object that
// raised the event from inside its own callback is asking for trouble.
static void row_clicked(lv_event_t *event) {
    const int index = (int)(intptr_t)lv_event_get_user_data(event);
    if (index < 0 || index >= 64) {
        return;
    }
    if (s_tap_pick) {
        s_picked[index] = !s_picked[index];
    } else {
        s_selected = index;
    }
    refresh_item_labels();
    update_mode_label();
    update_popup_title();
}

static lv_obj_t *make_button_h(lv_obj_t *parent, const char *text, lv_event_cb_t cb,
                               int32_t height) {
    lv_obj_t *button = lv_button_create(parent);
    lv_obj_set_flex_grow(button, 1);
    lv_obj_set_height(button, height);
    lv_obj_add_event_cb(button, cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *label = lv_label_create(button);
    lv_label_set_text(label, text);
    lv_obj_center(label);
    return button;
}

static lv_obj_t *make_button(lv_obj_t *parent, const char *text, lv_event_cb_t cb) {
    return make_button_h(parent, text, cb, 36);
}

static void refresh_item_labels(void) {
    char text[SSID_LEN + 64];
    for (int slot = 0; slot < s_item_count; slot++) {
        if (s_item_label[slot] == NULL) {
            continue;
        }
        row_text(slot, text, sizeof(text));
        lv_label_set_text(s_item_label[slot], text);
    }
}

static void rebuild_popup_list(void) {
    if (s_popup_list == NULL) {
        return;
    }
    lv_obj_clean(s_popup_list);
    s_item_count = 0;
    for (int slot = 0; slot < LIST_ROWS; slot++) {
        s_item_label[slot] = NULL;
    }
    // Each row costs LVGL heap; bound it so a dense radio environment cannot
    // exhaust the UI heap.
    const int limit = s_row_count < LIST_ROWS ? s_row_count : LIST_ROWS;
    char text[SSID_LEN + 64];
    for (int i = 0; i < limit; i++) {
        s_item_row[i] = (uint16_t)i;
        row_text(i, text, sizeof(text));
        lv_obj_t *btn = lv_button_create(s_popup_list);
        lv_obj_set_width(btn, lv_pct(100));
        lv_obj_set_height(btn, 30);
        lv_obj_set_style_pad_all(btn, 2, 0);
        lv_obj_t *label = lv_label_create(btn);
        lv_obj_set_width(label, lv_pct(96));
        lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_CLIP);
        lv_label_set_text(label, text);
        lv_obj_align(label, LV_ALIGN_LEFT_MID, 2, 0);
#if CONFIG_WIRELESS_UI_CJK_CUSTOM || CONFIG_LV_FONT_SOURCE_HAN_SANS_SC_16_CJK
        lv_obj_set_style_text_font(label, UI_FONT, 0);
#endif
        lv_obj_add_event_cb(btn, row_clicked, LV_EVENT_CLICKED,
                            (void *)(intptr_t)s_rows[i].index);
        s_item_label[i] = label;
        s_item_count = i + 1;
    }
}

static void update_popup_title(void) {
    if (s_popup_title == NULL) {
        return;
    }
    char text[64];
    snprintf(text, sizeof(text), "pick targets (%d) - %s", s_row_count,
             s_tap_pick ? "multi" : "single");
    lv_label_set_text(s_popup_title, text);
}

typedef enum {
    SCR_MENU = 0,
    SCR_DEAUTH,
    SCR_MODE,
    SCR_PROBE,
    SCR_CSA,
    SCR_DELBA,
    SCR_EVIL,
    SCR_COUNT
} ui_screen_t;

static lv_obj_t *s_screens[SCR_COUNT];
static ui_screen_t s_screen = SCR_MENU;

static void show_screen(ui_screen_t target) {
    for (int i = 0; i < SCR_COUNT; i++) {
        if (s_screens[i] == NULL) continue;
        if (i == (int)target) {
            lv_obj_remove_flag(s_screens[i], LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_screens[i], LV_OBJ_FLAG_HIDDEN);
        }
    }
    s_screen = target;
}

static void update_mode_label(void) {
    if (s_mode_label == NULL) {
        return;
    }
    static const char *names[4] = {"One AP", "All APs", "Only picked", "Except picked"};
    const int kind = (s_mode_kind < 0 || s_mode_kind > 3) ? 0 : s_mode_kind;
    char text[96];
    int pos = snprintf(text, sizeof(text), "%s", names[kind]);
    if (kind <= 1) {
        if (s_selected >= 0) {
            snprintf(text + pos, sizeof(text) - pos, " | sel:%d", s_selected);
        } else {
            snprintf(text + pos, sizeof(text) - pos, " | tap Targets");
        }
    } else {
        pos += snprintf(text + pos, sizeof(text) - pos, " | pick:");
        bool first = true;
        for (int i = 0; i < 64; i++) {
            if (!s_picked[i]) {
                continue;
            }
            pos += snprintf(text + pos, sizeof(text) - pos, "%s%d", first ? "" : ",", i);
            first = false;
            if (pos > (int)sizeof(text) - 8) {
                break;
            }
        }
        if (first) {
            snprintf(text + pos, sizeof(text) - pos, " tap Targets");
        }
    }
    lv_label_set_text(s_mode_label, text);

    if (s_csa_label != NULL) {
        if (s_selected >= 0) {
            const char *ssid = "";
            for (int i = 0; i < s_row_count; i++) {
                if ((int)s_rows[i].index == s_selected) {
                    ssid = s_rows[i].ssid;
                    break;
                }
            }
            snprintf(text, sizeof(text), "CSA #%d %s -> auto (opposite band)", s_selected, ssid);
        } else {
            snprintf(text, sizeof(text), "CSA: pick a target (auto channel)");
        }
        lv_label_set_text(s_csa_label, text);
    }

    if (s_delba_label != NULL) {
        if (s_selected >= 0) {
            const char *ssid = "";
            for (int i = 0; i < s_row_count; i++) {
                if ((int)s_rows[i].index == s_selected) {
                    ssid = s_rows[i].ssid;
                    break;
                }
            }
            snprintf(text, sizeof(text), "DELBA #%d %s reason=37", s_selected, ssid);
        } else {
            snprintf(text, sizeof(text), "DELBA: pick a target first");
        }
        lv_label_set_text(s_delba_label, text);
    }

    if (s_evil_label != NULL) {
        if (s_selected >= 0) {
            const char *ssid = "";
            for (int i = 0; i < s_row_count; i++) {
                if ((int)s_rows[i].index == s_selected) {
                    ssid = s_rows[i].ssid;
                    break;
                }
            }
            snprintf(text, sizeof(text), "target: #%d %s", s_selected, ssid);
        } else {
            snprintf(text, sizeof(text), "target: none");
        }
        lv_label_set_text(s_evil_label, text);
    }
}

static lv_obj_t *make_screen(lv_obj_t *parent) {
    lv_obj_t *screen = lv_obj_create(parent);
    lv_obj_set_width(screen, lv_pct(100));
    lv_obj_set_flex_grow(screen, 1);
    lv_obj_set_style_pad_all(screen, 0, 0);
    lv_obj_set_style_border_width(screen, 0, 0);
    lv_obj_set_flex_flow(screen, LV_FLEX_FLOW_COLUMN);
    lv_obj_add_flag(screen, LV_OBJ_FLAG_HIDDEN);
    return screen;
}

static lv_obj_t *make_row(lv_obj_t *parent) {
    lv_obj_t *row = lv_obj_create(parent);
    lv_obj_set_width(row, lv_pct(100));
    lv_obj_set_height(row, 38);
    lv_obj_set_style_pad_all(row, 0, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(row, 4, 0);
    return row;
}

// ---- target picker popup
static void targets_back_clicked(lv_event_t *event) {
    (void)event;
    memcpy(s_picked, s_picked_before, sizeof(s_picked));
    s_selected = s_selected_before;
    if (s_popup != NULL) {
        lv_obj_add_flag(s_popup, LV_OBJ_FLAG_HIDDEN);
    }
    update_mode_label();
}

static void targets_ok_clicked(lv_event_t *event) {
    (void)event;
    if (s_popup != NULL) {
        lv_obj_add_flag(s_popup, LV_OBJ_FLAG_HIDDEN);
    }
}

static void targets_open(void) {
    if (s_popup == NULL) {
        return;
    }
    memcpy(s_picked_before, s_picked, sizeof(s_picked));
    s_selected_before = s_selected;
    update_popup_title();
    rebuild_popup_list();  // rows only exist while the popup is open
    lv_obj_remove_flag(s_popup, LV_OBJ_FLAG_HIDDEN);
    lv_obj_move_foreground(s_popup);
}

static void targets_clicked(lv_event_t *event) {
    (void)event;
    targets_open();
}


// ---- navigation
static void goto_menu(lv_event_t *event) {
    (void)event;
    show_screen(SCR_MENU);
}
static void goto_deauth(lv_event_t *event) {
    (void)event;
    show_screen(SCR_DEAUTH);
}
static void goto_probe(lv_event_t *event) {
    (void)event;
    show_screen(SCR_PROBE);
}
static void goto_csa(lv_event_t *event) {
    (void)event;
    s_tap_pick = 0;  // CSA spoofs one AP
    update_mode_label();
    show_screen(SCR_CSA);
}

static void csa_start_clicked(lv_event_t *event) {
    (void)event;
    if (s_selected < 0) {
        if (s_log) lv_label_set_text(s_log, "pick an AP first");
        return;
    }
    char command[32];
    // No channel: the firmware announces a channel from the opposite band and
    // keeps cycling until Stop.
    snprintf(command, sizeof(command), "CSA %d", s_selected);
    emit(command);
}

static void csa_stop_clicked(lv_event_t *event) {
    (void)event;
    emit("CSASTOP");
}

static void goto_delba(lv_event_t *event) {
    (void)event;
    s_tap_pick = 0;  // DELBA targets one AP
    update_mode_label();
    show_screen(SCR_DELBA);
}

static void delba_start_clicked(lv_event_t *event) {
    (void)event;
    if (s_selected < 0) {
        if (s_log) lv_label_set_text(s_log, "pick an AP first");
        return;
    }
    char command[32];
    // reason 37 = "requested from peer STA as it does not want to use the
    // mechanism", the value a real AP uses when it stops aggregating.
    snprintf(command, sizeof(command), "DELBA %d 37", s_selected);
    emit(command);
}

static void delba_stop_clicked(lv_event_t *event) {
    (void)event;
    emit("DELBASTOP");
}

static void goto_evil(lv_event_t *event) {
    (void)event;
    s_tap_pick = 0;  // evil twin needs one single target
    show_screen(SCR_EVIL);
}
static void back_from_mode(lv_event_t *event) {
    (void)event;
    show_screen(SCR_DEAUTH);
}

// ---- actions
static void probe_clicked(lv_event_t *event) {
    (void)event;
    emit("PROBE_BROADCAST");
}
static void evil_clicked(lv_event_t *event) {
    (void)event;
    if (s_selected < 0) {
        if (s_log) lv_label_set_text(s_log, "pick an AP first");
        return;
    }
    char command[48];
    snprintf(command, sizeof(command), "EVILTWIN %d", s_selected);
    emit(command);
}
static void evil_stop_clicked(lv_event_t *event) {
    (void)event;
    emit("EVILTWIN_STOP");
}
static void creds_clicked(lv_event_t *event) {
    (void)event;
    emit("CREDS");
}
static void pick_all_clicked(lv_event_t *event) {
    (void)event;
    for (int i = 0; i < 64; i++) {
        s_picked[i] = true;
    }
    refresh_item_labels();
    update_mode_label();
    update_popup_title();
}
static void pick_none_clicked(lv_event_t *event) {
    (void)event;
    for (int i = 0; i < 64; i++) {
        s_picked[i] = false;
    }
    refresh_item_labels();
    update_mode_label();
    update_popup_title();
}

// ---- level 2/3: deauth mode menu + one shared mode page
static void goto_mode(int kind) {
    s_mode_kind = kind;
    // One/All use a single target, Only/Except toggle the [x] checkboxes.
    s_tap_pick = (kind >= 2) ? 1 : 0;
    update_mode_label();
    show_screen(SCR_MODE);
}

static void mode_one_clicked(lv_event_t *event) {
    (void)event;
    goto_mode(0);
}
static void mode_all_clicked(lv_event_t *event) {
    (void)event;
    goto_mode(1);
}
static void mode_only_clicked(lv_event_t *event) {
    (void)event;
    goto_mode(2);
}
static void mode_except_clicked(lv_event_t *event) {
    (void)event;
    goto_mode(3);
}

static void build_pick_command(char *command, size_t size, const char *prefix) {
    int pos = snprintf(command, size, "%s ", prefix);
    bool first = true;
    for (int i = 0; i < 64; i++) {
        if (!s_picked[i]) continue;
        pos += snprintf(command + pos, size - pos, "%s%d", first ? "" : ",", i);
        first = false;
        if (pos > (int)size - 8) break;
    }
    if (first) {
        command[0] = 0;
        return;
    }
    snprintf(command + pos, size - pos, " 1");
}

static void start_clicked(lv_event_t *event) {
    (void)event;
    char command[96];
    switch (s_mode_kind) {
        case 0:
            if (s_selected < 0) {
                if (s_log) lv_label_set_text(s_log, "pick an AP first");
                return;
            }
            snprintf(command, sizeof(command), "DEAUTH %d 1", s_selected);
            emit(command);
            break;
        case 1:
            emit("DEAUTH_ALL 1");
            break;
        case 2:
            build_pick_command(command, sizeof(command), "DEAUTH_ONLY");
            if (command[0] == 0) {
                if (s_log) lv_label_set_text(s_log, "pick at least one AP");
                return;
            }
            emit(command);
            break;
        default:
            build_pick_command(command, sizeof(command), "DEAUTH_EXCEPT");
            if (command[0] == 0) {
                if (s_log) lv_label_set_text(s_log, "pick at least one AP");
                return;
            }
            emit(command);
            break;
    }
}

// Reason codes the standard defines. All of them are pickable from the popup,
// instead of only the three that used to be in a cycle.
typedef struct {
    uint16_t code;
    const char *text;
} reason_entry_t;

static const reason_entry_t kReasonTable[] = {
    {1, "1 unspecified"},        {2, "2 prev auth invalid"},  {3, "3 leaving"},
    {4, "4 inactivity"},         {5, "5 AP busy"},            {6, "6 class-2 frame"},
    {7, "7 class-3 frame"},      {8, "8 disassoc leaving"},   {9, "9 not authenticated"},
    {10, "10 power capability"}, {11, "11 BSS transition"},   {13, "13 invalid IE"},
    {14, "14 MIC failure"},      {15, "15 4-way timeout"},    {16, "16 group-key timeout"},
    {17, "17 IE differs"},       {18, "18 invalid group cipher"},
    {19, "19 invalid pairwise cipher"}, {20, "20 invalid AKMP"},
    {21, "21 RSNE version"},     {22, "22 RSNE capability"},  {23, "23 802.1X failed"},
    {24, "24 cipher rejected"},
};
#define REASON_TABLE_LEN ((int)(sizeof(kReasonTable) / sizeof(kReasonTable[0])))
#define REASON_RANDOM_ROW (REASON_TABLE_LEN)

// Human readable name for a code, so the button says what it means instead of
// only showing the raw number.
static const char *reason_name(uint16_t code) {
    for (int i = 0; i < REASON_TABLE_LEN; i++) {
        if (kReasonTable[i].code == code) {
            const char *text = kReasonTable[i].text;
            while (*text != 0 && *text != ' ') {
                text++;  // skip the leading number
            }
            return (*text == ' ') ? text + 1 : kReasonTable[i].text;
        }
    }
    return "custom";
}

static void reason_refresh_label(void) {
    if (s_reason_label == NULL) {
        return;
    }
    char text[48];
    if (s_reason_random_selected) {
        snprintf(text, sizeof(text), "Reason: random (per burst)");
    } else {
        snprintf(text, sizeof(text), "Reason: %u %s", (unsigned)s_reason_selected,
                 reason_name(s_reason_selected));
    }
    lv_label_set_text(s_reason_label, text);
}

static void reason_close(void) {
    if (s_reason_popup != NULL) {
        lv_obj_add_flag(s_reason_popup, LV_OBJ_FLAG_HIDDEN);
        // Free the 24 rows: LVGL's pool is only 64 KB and the target list needs
        // room for up to 30 rows at the same time.
        if (s_reason_popup_list != NULL) {
            lv_obj_clean(s_reason_popup_list);
        }
    }
}

// Builds the reason rows on demand (no rows exist while the popup is closed).
static void reason_build_rows(void) {
    if (s_reason_popup_list == NULL || lv_obj_get_child_count(s_reason_popup_list) > 0) {
        return;
    }
    for (int i = 0; i <= REASON_TABLE_LEN; i++) {
        const char *text = (i == REASON_RANDOM_ROW) ? "random (per burst)" : kReasonTable[i].text;
        lv_obj_t *btn = lv_button_create(s_reason_popup_list);
        lv_obj_set_width(btn, lv_pct(100));
        lv_obj_set_height(btn, 26);
        lv_obj_set_style_pad_all(btn, 2, 0);
        lv_obj_t *label = lv_label_create(btn);
        lv_obj_set_width(label, lv_pct(96));
        lv_label_set_long_mode(label, LV_LABEL_LONG_MODE_CLIP);
        lv_label_set_text(label, text);
        lv_obj_align(label, LV_ALIGN_LEFT_MID, 2, 0);
        lv_obj_add_event_cb(btn, reason_row_clicked, LV_EVENT_CLICKED, (void *)(intptr_t)i);
    }
}

static void reason_row_clicked(lv_event_t *event) {
    const int row = (int)(intptr_t)lv_event_get_user_data(event);
    if (row == REASON_RANDOM_ROW) {
        s_reason_random_selected = true;
        emit("REASON random");
    } else if (row >= 0 && row < REASON_TABLE_LEN) {
        s_reason_selected = kReasonTable[row].code;
        s_reason_random_selected = false;
        char command[24];
        snprintf(command, sizeof(command), "REASON %u", (unsigned)s_reason_selected);
        emit(command);
    }
    reason_refresh_label();
    reason_close();
}

static void reason_back_clicked(lv_event_t *event) {
    (void)event;
    reason_close();
}

static void reason_open(void) {
    if (s_reason_popup == NULL) {
        return;
    }
    if (s_reason_popup_title != NULL) {
        if (s_reason_random_selected) {
            lv_label_set_text(s_reason_popup_title, "Reason: random per burst");
        } else {
            char title[48];
            snprintf(title, sizeof(title), "Reason: %u %s", (unsigned)s_reason_selected,
                     reason_name(s_reason_selected));
            lv_label_set_text(s_reason_popup_title, title);
        }
    }
    reason_build_rows();
    lv_obj_remove_flag(s_reason_popup, LV_OBJ_FLAG_HIDDEN);
    lv_obj_move_foreground(s_reason_popup);
}

static void reason_clicked(lv_event_t *event) {
    (void)event;
    reason_open();
}

static bool build_main_ui(void) {
    if (!wireless_ui_port_lock(0)) {
        return false;
    }

    lv_obj_t *root = lv_screen_active();
    lv_obj_clean(root);
    lv_obj_set_style_pad_all(root, 4, 0);
    lv_obj_set_flex_flow(root, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(root, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    lv_obj_t *title = lv_label_create(root);
    lv_label_set_text(title, "Wireless Attack");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);

    s_status = lv_label_create(root);
    lv_label_set_text(s_status, "idle  d=0 p=0 nets=0 e=0");
    lv_label_set_long_mode(s_status, LV_LABEL_LONG_MODE_CLIP);
    lv_obj_set_width(s_status, 312);

    // ---- level 1: function menu
    s_screens[SCR_MENU] = make_screen(root);
    lv_obj_t *m1 = make_row(s_screens[SCR_MENU]);
    make_button(m1, "Deauth", goto_deauth);
    make_button(m1, "Probe", goto_probe);
    lv_obj_t *m2 = make_row(s_screens[SCR_MENU]);
    make_button(m2, "CSA", goto_csa);
    make_button(m2, "DELBA", goto_delba);
    lv_obj_t *m3 = make_row(s_screens[SCR_MENU]);
    make_button(m3, "Evil", goto_evil);

    // ---- level 2: deauth mode menu
    s_screens[SCR_DEAUTH] = make_screen(root);
    lv_obj_t *d1 = make_row(s_screens[SCR_DEAUTH]);
    make_button(d1, "One", mode_one_clicked);
    make_button(d1, "All", mode_all_clicked);
    lv_obj_t *d2 = make_row(s_screens[SCR_DEAUTH]);
    make_button(d2, "Only", mode_only_clicked);
    make_button(d2, "Except", mode_except_clicked);
    lv_obj_t *d3 = make_row(s_screens[SCR_DEAUTH]);
    make_button(d3, "Back", goto_menu);

    // ---- level 3: one shared page for the four deauth modes.
    // Scan / Targets / Start / Stop live here; picking happens in the popup.
    s_screens[SCR_MODE] = make_screen(root);
    s_mode_label = lv_label_create(s_screens[SCR_MODE]);
    lv_label_set_text(s_mode_label, "One AP | tap Targets");
    lv_obj_set_width(s_mode_label, 312);
    lv_obj_t *k_hint = lv_label_create(s_screens[SCR_MODE]);
    lv_label_set_text(k_hint, "Scan -> Targets -> Start");
    lv_obj_set_style_text_color(k_hint, lv_color_hex(0x666666), 0);
    lv_obj_t *k1 = make_row(s_screens[SCR_MODE]);
    make_button_h(k1, "Scan", scan_clicked, 34);
    make_button_h(k1, "Targets", targets_clicked, 34);
    make_button_h(k1, "Start", start_clicked, 34);
    lv_obj_t *k2 = make_row(s_screens[SCR_MODE]);
    make_button_h(k2, "Stop", stop_clicked, 34);
    make_button_h(k2, "Back", back_from_mode, 34);

    // Full width row: the label spells out the code ("Reason: 7 class-3 frame")
    lv_obj_t *k3 = make_row(s_screens[SCR_MODE]);
    lv_obj_t *reason_btn = make_button_h(k3, "Reason", reason_clicked, 34);
    s_reason_label = lv_obj_get_child(reason_btn, 0);
    lv_obj_set_width(s_reason_label, lv_pct(96));
    lv_label_set_long_mode(s_reason_label, LV_LABEL_LONG_MODE_CLIP);
    lv_obj_center(s_reason_label);
    reason_refresh_label();

    // ---- CSA page: same shape as the deauth work page
    s_screens[SCR_CSA] = make_screen(root);
    s_csa_label = lv_label_create(s_screens[SCR_CSA]);
    lv_obj_set_width(s_csa_label, 312);
    lv_label_set_text(s_csa_label, "CSA: pick a target -> ch11");
    lv_obj_t *c_hint = lv_label_create(s_screens[SCR_CSA]);
    lv_label_set_text(c_hint, "Scan -> Targets -> Start (auto channel)");
    lv_obj_set_style_text_color(c_hint, lv_color_hex(0x666666), 0);
    lv_obj_t *c1 = make_row(s_screens[SCR_CSA]);
    make_button_h(c1, "Scan", scan_clicked, 34);
    make_button_h(c1, "Targets", targets_clicked, 34);
    make_button_h(c1, "Start", csa_start_clicked, 34);
    lv_obj_t *c2 = make_row(s_screens[SCR_CSA]);
    make_button_h(c2, "Stop", csa_stop_clicked, 34);
    make_button_h(c2, "Back", goto_menu, 34);

    // ---- level 2: DELBA (block ack teardown), same shape as the CSA page
    s_screens[SCR_DELBA] = make_screen(root);
    s_delba_label = lv_label_create(s_screens[SCR_DELBA]);
    lv_obj_set_width(s_delba_label, 312);
    lv_label_set_text(s_delba_label, "DELBA: pick a target first");
    lv_obj_t *x_hint = lv_label_create(s_screens[SCR_DELBA]);
    lv_label_set_text(x_hint, "Scan -> Targets -> Start (tear down BA)");
    lv_obj_set_style_text_color(x_hint, lv_color_hex(0x666666), 0);
    lv_obj_t *x1 = make_row(s_screens[SCR_DELBA]);
    make_button_h(x1, "Scan", scan_clicked, 34);
    make_button_h(x1, "Targets", targets_clicked, 34);
    make_button_h(x1, "Start", delba_start_clicked, 34);
    lv_obj_t *x2 = make_row(s_screens[SCR_DELBA]);
    make_button_h(x2, "Stop", delba_stop_clicked, 34);
    make_button_h(x2, "Back", goto_menu, 34);

    // ---- level 2: probe
    s_screens[SCR_PROBE] = make_screen(root);
    lv_obj_t *p_hint = lv_label_create(s_screens[SCR_PROBE]);
    lv_label_set_text(p_hint, "flood fake APs:\nbeacon + probe response");
    lv_obj_set_width(p_hint, 312);
    lv_obj_t *p1 = make_row(s_screens[SCR_PROBE]);
    make_button(p1, "Start", probe_clicked);
    make_button(p1, "Stop", stop_clicked);
    make_button(p1, "Back", goto_menu);

    // ---- level 2: evil twin (scan -> targets popup -> clone)
    s_screens[SCR_EVIL] = make_screen(root);
    s_evil_label = lv_label_create(s_screens[SCR_EVIL]);
    lv_obj_set_width(s_evil_label, 312);
    lv_label_set_text(s_evil_label, "target: none");
    lv_obj_t *e0 = lv_label_create(s_screens[SCR_EVIL]);
    lv_label_set_text(e0, "Scan -> Targets -> Clone");
    lv_obj_set_style_text_color(e0, lv_color_hex(0x666666), 0);
    lv_obj_t *e1 = make_row(s_screens[SCR_EVIL]);
    make_button_h(e1, "Scan", scan_clicked, 34);
    make_button_h(e1, "Targets", targets_clicked, 34);
    make_button_h(e1, "Clone", evil_clicked, 34);
    lv_obj_t *e2 = make_row(s_screens[SCR_EVIL]);
    make_button_h(e2, "Stop", evil_stop_clicked, 34);
    make_button_h(e2, "Creds", creds_clicked, 34);
    make_button_h(e2, "Back", goto_menu, 34);

    // ---- modal target picker on the top layer
    lv_obj_clean(lv_layer_top());
    s_popup = lv_obj_create(lv_layer_top());
    lv_obj_set_size(s_popup, UI_W - 12, UI_H - 12);
    lv_obj_center(s_popup);
    lv_obj_remove_flag(s_popup, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_style_radius(s_popup, 8, 0);
    lv_obj_set_style_border_width(s_popup, 2, 0);
    lv_obj_set_style_border_color(s_popup, lv_color_hex(0xF0A020), 0);
    lv_obj_set_style_bg_color(s_popup, lv_color_hex(0x101820), 0);
    lv_obj_set_style_bg_opa(s_popup, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(s_popup, 4, 0);
    lv_obj_set_flex_flow(s_popup, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_popup, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    s_popup_title = lv_label_create(s_popup);
    lv_label_set_text(s_popup_title, "pick targets");
    lv_obj_set_width(s_popup_title, UI_W - 28);

    s_popup_list = lv_obj_create(s_popup);
    lv_obj_set_width(s_popup_list, lv_pct(100));
    lv_obj_set_flex_grow(s_popup_list, 1);
    lv_obj_set_style_pad_all(s_popup_list, 2, 0);
    lv_obj_set_style_pad_row(s_popup_list, 2, 0);
    lv_obj_set_flex_flow(s_popup_list, LV_FLEX_FLOW_COLUMN);

    lv_obj_t *prow = make_row(s_popup);
    lv_obj_set_height(prow, 32);
    make_button_h(prow, "All", pick_all_clicked, 30);
    make_button_h(prow, "None", pick_none_clicked, 30);
    make_button_h(prow, "Back", targets_back_clicked, 30);
    make_button_h(prow, "OK", targets_ok_clicked, 30);
    lv_obj_add_flag(s_popup, LV_OBJ_FLAG_HIDDEN);

    s_log = lv_label_create(root);
    lv_label_set_text(s_log, "ready");
    lv_label_set_long_mode(s_log, LV_LABEL_LONG_MODE_CLIP);
    lv_obj_set_width(s_log, 312);
    lv_obj_set_style_text_color(s_log, lv_color_hex(0x666666), 0);

    // ---- modal reason picker: every defined code + "random per burst"
    s_reason_popup = lv_obj_create(lv_layer_top());
    lv_obj_set_size(s_reason_popup, UI_W - 12, UI_H - 12);
    lv_obj_center(s_reason_popup);
    lv_obj_remove_flag(s_reason_popup, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_style_radius(s_reason_popup, 8, 0);
    lv_obj_set_style_border_width(s_reason_popup, 2, 0);
    lv_obj_set_style_border_color(s_reason_popup, lv_color_hex(0x30A0E0), 0);
    lv_obj_set_style_bg_color(s_reason_popup, lv_color_hex(0x101820), 0);
    lv_obj_set_style_bg_opa(s_reason_popup, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(s_reason_popup, 4, 0);
    lv_obj_set_flex_flow(s_reason_popup, LV_FLEX_FLOW_COLUMN);

    s_reason_popup_title = lv_label_create(s_reason_popup);
    lv_label_set_text(s_reason_popup_title, "reason");
    lv_obj_set_width(s_reason_popup_title, UI_W - 28);

    s_reason_popup_list = lv_obj_create(s_reason_popup);
    lv_obj_set_width(s_reason_popup_list, lv_pct(100));
    lv_obj_set_flex_grow(s_reason_popup_list, 1);
    lv_obj_set_style_pad_all(s_reason_popup_list, 2, 0);
    lv_obj_set_style_pad_row(s_reason_popup_list, 2, 0);
    lv_obj_set_flex_flow(s_reason_popup_list, LV_FLEX_FLOW_COLUMN);

    s_reason_popup_items = REASON_TABLE_LEN + 1;  // rows are built on open


    lv_obj_t *rrow = make_row(s_reason_popup);
    lv_obj_set_height(rrow, 32);
    make_button_h(rrow, "Back", reason_back_clicked, 30);
    lv_obj_add_flag(s_reason_popup, LV_OBJ_FLAG_HIDDEN);

    show_screen(SCR_MENU);
    wireless_ui_port_unlock();
    return true;
}

static void calib_show_step(int step) {
    lv_label_set_text(s_calib_hint, kCalibHints[step]);
    for (int i = 0; i < 4; i++) {
        lv_obj_set_style_bg_color(s_calib_dots[i],
                                  (i == step) ? lv_color_hex(0xE03030) : lv_color_hex(0x888888), 0);
    }
}

static void calib_start(void) {
    s_calib_active = true;
    s_calib_prev_down = false;
    s_calib_step = 0;
    s_calib_stable = 0;
    s_calib_started = xTaskGetTickCount();
    memset(s_calib_raw, 0, sizeof(s_calib_raw));

    if (!wireless_ui_port_lock(0)) {
        return;
    }
    lv_obj_t *screen = lv_screen_active();
    lv_obj_clean(screen);

    for (int i = 0; i < 4; i++) {
        lv_obj_t *dot = lv_obj_create(screen);
        lv_obj_remove_flag(dot, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_size(dot, 14, 14);
        lv_obj_set_style_radius(dot, LV_RADIUS_CIRCLE, 0);
        lv_obj_set_style_border_width(dot, 0, 0);
        lv_obj_set_pos(dot, kDotX[i] - 7, kDotY[i] - 7);
        s_calib_dots[i] = dot;
    }

    s_calib_hint = lv_label_create(screen);
    lv_obj_set_width(s_calib_hint, 280);
    lv_obj_set_style_text_align(s_calib_hint, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(s_calib_hint, LV_ALIGN_CENTER, 0, 0);
    calib_show_step(0);
    wireless_ui_port_unlock();
    ESP_LOGW(TAG, "touch calibration required: tap the 4 corners");
}

static void calib_finish(void) {
    wui_calib_t calib;
    wui_calib_solve(s_calib_raw, UI_W, UI_H, WUI_CALIB_INSET, &calib);
    if (calib.valid) {
        wui_calib_save(&calib);
        wireless_ui_port_set_calib(&calib);
    } else {
        ESP_LOGW(TAG, "calibration solve failed, keeping defaults");
    }
    s_calib_active = false;
    build_main_ui();
    if (!wireless_ui_port_lock(200)) {
        return;
    }
    lv_label_set_text(s_log, "calibrated");
    wireless_ui_port_unlock();
}

void wireless_ui_set_storage(const wireless_ui_storage_ops_t *ops) {
    wui_storage_set_ops((const wui_storage_ops_t *)ops);
}

bool wireless_ui_ready(void) {
    return s_ui_ready;
}

bool wireless_ui_init(void) {
    if (wireless_ui_port_init() == NULL) {
        ESP_LOGE(TAG, "port init failed");
        return false;
    }

    wui_calib_t calib;
    if (wui_calib_load(&calib)) {
        wireless_ui_port_set_calib(&calib);
        if (!build_main_ui()) {
            return false;
        }
        s_ui_ready = true;
        ESP_LOGW(TAG, "UI ready (calibrated)");
        return true;
    }

    ESP_LOGW(TAG, "no calibration in NVS, starting calibration");
    s_ui_ready = true;
    calib_start();
    return true;
}

void wireless_ui_set_command_cb(wireless_ui_command_cb_t cb) {
    s_command_cb = cb;
}

void wireless_ui_request_calibration(void) {
    wui_calib_clear();
    esp_restart();
}

static void ui_apply_pending(void) {
    if (!s_pending_scan_begin && !s_pending_scan_end && !s_pending_status_valid &&
        !s_pending_log_valid) {
        return;
    }
    if (s_popup == NULL) {
        // Still on the calibration screen: drop the updates instead of touching
        // widgets that do not exist yet.
        s_pending_scan_begin = false;
        s_pending_scan_end = false;
        s_pending_status_valid = false;
        s_pending_log_valid = false;
        return;
    }
    if (!wireless_ui_port_lock(120)) {
        return;  // try again next tick
    }
    if (s_pending_scan_begin) {
        s_pending_scan_begin = false;
        lv_obj_clean(s_popup_list);
        s_item_count = 0;
        lv_label_set_text(s_log, "scanning...");
    }
    if (s_pending_scan_end) {
        s_pending_scan_end = false;
        // Building 30 rows into a hidden popup was what starved LVGL's 64 KB pool
        // after a scan (the UI froze right at SCAN_END). Only build on demand.
        if (s_popup != NULL && !lv_obj_has_flag(s_popup, LV_OBJ_FLAG_HIDDEN)) {
            rebuild_popup_list();
        } else if (s_popup_list != NULL) {
            lv_obj_clean(s_popup_list);
            s_item_count = 0;
        }
        update_mode_label();
        update_popup_title();
        char text[48];
        snprintf(text, sizeof(text), "scan done, %d nets", s_pending_scan_count);
        lv_label_set_text(s_log, text);
    }
    if (s_pending_status_valid) {
        s_pending_status_valid = false;
        lv_label_set_text(s_status, s_pending_status);
    }
    if (s_pending_log_valid) {
        s_pending_log_valid = false;
        lv_label_set_text(s_log, s_pending_log);
    }
    wireless_ui_port_unlock();
}

void wireless_ui_tick(void) {
    if (s_calib_active) {
        ;  // calibration drives its own polling below
    } else {
        ui_apply_pending();
        return;
    }

    int raw_x = 0;
    int raw_y = 0;
    int sx = 0;
    int sy = 0;
    bool down = false;
    wireless_ui_port_touch_read(&raw_x, &raw_y, &sx, &sy, &down);

    // Give the panel a moment to settle, then require three consistent samples
    // so a power-up transient cannot be mistaken for a corner tap.
    if ((xTaskGetTickCount() - s_calib_started) < pdMS_TO_TICKS(800)) {
        s_calib_stable = 0;
        vTaskDelay(pdMS_TO_TICKS(15));
        return;
    }

    if (!down) {
        s_calib_stable = 0;
    } else if (s_calib_stable == 4) {
        // already captured this press, wait for the finger to lift
    } else if (s_calib_stable == 0 || abs(raw_x - s_calib_cand[0]) > 80 ||
               abs(raw_y - s_calib_cand[1]) > 80) {
        s_calib_cand[0] = (int16_t)raw_x;
        s_calib_cand[1] = (int16_t)raw_y;
        s_calib_stable = 1;
    } else if (s_calib_stable < 3) {
        s_calib_stable++;
    }

    if (s_calib_stable == 3) {
        s_calib_raw[s_calib_step][0] = s_calib_cand[0];
        s_calib_raw[s_calib_step][1] = s_calib_cand[1];
        ESP_LOGW(TAG, "corner %d raw=%d,%d", s_calib_step, s_calib_cand[0], s_calib_cand[1]);
        s_calib_step++;
        s_calib_stable = 4;  // latch until release
        if (s_calib_step >= 4) {
            calib_finish();
            return;
        }
        if (wireless_ui_port_lock(200)) {
            calib_show_step(s_calib_step);
            wireless_ui_port_unlock();
        }
    }

    s_calib_prev_down = down;
    vTaskDelay(pdMS_TO_TICKS(15));
}

void wireless_ui_scan_begin(void) {
    s_row_count = 0;
    // Indexes are only valid for one scan, so a rescan invalidates every pick.
    s_selected = -1;
    memset(s_picked, 0, sizeof(s_picked));
    s_pending_scan_begin = true;
    s_pending_scan_end = false;
}

void wireless_ui_add_network(const wireless_ui_network_t *net) {
    if (net == NULL || s_row_count >= MAX_ROWS) {
        return;
    }
    row_t *row = &s_rows[s_row_count++];
    row->index = net->index;
    snprintf(row->ssid, sizeof(row->ssid), "%s", net->ssid != NULL ? net->ssid : "");
    snprintf(row->bssid, sizeof(row->bssid), "%s", net->bssid != NULL ? net->bssid : "");
    snprintf(row->info, sizeof(row->info), "ch%u %ddB", (unsigned)net->channel, (int)net->rssi);
}

void wireless_ui_scan_end(int count) {
    s_pending_scan_count = count;
    s_pending_scan_end = true;
}

void wireless_ui_status(const char *mode, int eliminated, int networks, int creds,
                        uint32_t deauth_frames, uint32_t probe_frames) {
    snprintf(s_pending_status, sizeof(s_pending_status), "%s  d=%u p=%u nets=%d e=%d",
             mode != NULL ? mode : "?", (unsigned)deauth_frames, (unsigned)probe_frames, networks,
             eliminated);
    s_pending_status_valid = true;
}

int wireless_ui_touch_irq_level(void) {
    return wireless_ui_port_touch_irq_level();
}

void wireless_ui_show_targets(void) {
    if (!wireless_ui_port_lock(200)) {
        return;
    }
    targets_open();
    wireless_ui_port_unlock();
}

bool wireless_ui_popup_visible(void) {
    bool visible = false;
    if (!wireless_ui_port_lock(50)) {
        return false;
    }
    visible = s_popup != NULL && !lv_obj_has_flag(s_popup, LV_OBJ_FLAG_HIDDEN);
    wireless_ui_port_unlock();
    return visible;
}

int wireless_ui_popup_items(void) {
    int items = 0;
    if (!wireless_ui_port_lock(50)) {
        return 0;
    }
    items = s_item_count;
    wireless_ui_port_unlock();
    return items;
}

int wireless_ui_reason_items(void) {
    int items = 0;
    if (!wireless_ui_port_lock(50)) {
        return 0;
    }
    items = s_reason_popup_items;
    wireless_ui_port_unlock();
    return items;
}

bool wireless_ui_reason_popup_visible(void) {
    bool visible = false;
    if (!wireless_ui_port_lock(50)) {
        return false;
    }
    visible = s_reason_popup != NULL && !lv_obj_has_flag(s_reason_popup, LV_OBJ_FLAG_HIDDEN);
    wireless_ui_port_unlock();
    return visible;
}

void wireless_ui_show_reasons(void) {
    if (!wireless_ui_port_lock(200)) {
        return;
    }
    reason_open();
    wireless_ui_port_unlock();
}

bool wireless_ui_show_by_name(const char *name) {
    if (name == NULL) {
        return false;
    }
    if (!wireless_ui_port_lock(200)) {
        return false;
    }
    bool ok = true;
    if (strcmp(name, "menu") == 0) {
        show_screen(SCR_MENU);
    } else if (strcmp(name, "deauth") == 0) {
        show_screen(SCR_DEAUTH);
    } else if (strcmp(name, "mode") == 0) {
        s_mode_kind = 0;
        update_mode_label();
        show_screen(SCR_MODE);
    } else if (strcmp(name, "probe") == 0) {
        show_screen(SCR_PROBE);
    } else if (strcmp(name, "csa") == 0) {
        s_tap_pick = 0;
        update_mode_label();
        show_screen(SCR_CSA);
    } else if (strcmp(name, "delba") == 0) {
        s_tap_pick = 0;  // DELBA targets a single AP, like CSA
        update_mode_label();
        show_screen(SCR_DELBA);
    } else if (strcmp(name, "evil") == 0) {
        s_tap_pick = 0;
        show_screen(SCR_EVIL);
    } else {
        ok = false;
    }
    wireless_ui_port_unlock();
    return ok;
}

const char *wireless_ui_screen_name(void) {
    switch (s_screen) {
        case SCR_DEAUTH:
            return "deauth";
        case SCR_MODE:
            return "mode";
        case SCR_PROBE:
            return "probe";
        case SCR_EVIL:
            return "evil";
        case SCR_CSA:
            return "csa";
        case SCR_DELBA:
            return "delba";
        case SCR_MENU:
        default:
            return "menu";
    }
}

bool wireless_ui_touch_readback(int *raw_x, int *raw_y, int *screen_x, int *screen_y,
                                bool *pressed) {
    return wireless_ui_port_touch_read(raw_x, raw_y, screen_x, screen_y, pressed);
}

void wireless_ui_log(const char *line) {
    if (line == NULL) {
        return;
    }
    snprintf(s_pending_log, sizeof(s_pending_log), "%s", line);
    s_pending_log_valid = true;
}

#endif  // CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
