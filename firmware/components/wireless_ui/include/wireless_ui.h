#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// LVGL-free façade: the rest of the firmware only sees this header, so nothing
// outside components/wireless_ui/ has to know that LVGL exists.

typedef struct {
    uint16_t index;
    int8_t rssi;
    uint8_t channel;
    const char *auth;
    const char *bssid;
    const char *ssid;
} wireless_ui_network_t;

// Filled in by the firmware; the UI calls it with protocol lines ("SCAN",
// "DEAUTH 3 1", "STOP"), i.e. exactly what the serial console accepts.
typedef void (*wireless_ui_command_cb_t)(const char *line);

// Persistence hooks. The application supplies them (it owns the NVS backend),
// so the UI component never links against the storage implementation.
typedef struct {
    bool (*load)(void *out, size_t len);
    bool (*save)(const void *in, size_t len);
    void (*clear)(void);
} wireless_ui_storage_ops_t;

// Must be called before wireless_ui_init().
void wireless_ui_set_storage(const wireless_ui_storage_ops_t *ops);

bool wireless_ui_init(void);

// True once the LVGL UI (or its calibration screen) is up.
bool wireless_ui_ready(void);
void wireless_ui_set_command_cb(wireless_ui_command_cb_t cb);

// Called from the main loop so the UI can drain pending work.
void wireless_ui_tick(void);

void wireless_ui_scan_begin(void);
void wireless_ui_add_network(const wireless_ui_network_t *net);
void wireless_ui_scan_end(int count);
void wireless_ui_status(const char *mode, int eliminated, int networks, int creds,
                        uint32_t deauth_frames, uint32_t probe_frames);
void wireless_ui_log(const char *line);

// Calibration hook: reads the touch panel directly (raw + mapped). Returns false
// when this build has no UI.
bool wireless_ui_touch_readback(int *raw_x, int *raw_y, int *screen_x, int *screen_y,
                                bool *pressed);

// Drops the stored touch calibration and restarts the board, so the next boot
// asks for the four corner taps again.
void wireless_ui_request_calibration(void);

// Raw PENIRQ level (0 = pressed). Handy for wiring diagnosis.
int wireless_ui_touch_irq_level(void);

// Diagnostics: open the target-picker popup from a console command, and report
// whether it is up / how many rows it built. Used by the `UITARGETS` / `UI`
// serial commands so the UI can be checked without touching the panel.
void wireless_ui_show_targets(void);
// Switches to a named screen (menu/deauth/mode/probe/csa/delba/evil). Used by
// the serial console so the UI can be regression-tested without a finger.
bool wireless_ui_show_by_name(const char *name);
// Reason-code popup: same idea as the target picker, one row per defined code.
void wireless_ui_show_reasons(void);
bool wireless_ui_reason_popup_visible(void);
int wireless_ui_reason_items(void);
bool wireless_ui_popup_visible(void);
int wireless_ui_popup_items(void);
const char *wireless_ui_screen_name(void);

#ifdef __cplusplus
}
#endif
