#include <WiFi.h>
#include <esp_wifi.h>
#include <sdkconfig.h>
#include <string.h>

#include "deauth.h"
#include "definitions.h"
#include "evil_twin.h"
#include "serial_console.h"
#include "types.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
#include "freertos/queue.h"
#include "storage.h"
#include "wireless_ui.h"

#define UI_CMD_LEN 48
#define UI_CMD_DEPTH 6

static QueueHandle_t s_ui_cmds;

static const wireless_ui_storage_ops_t kStorageOps = {
    .load = app_storage_load,
    .save = app_storage_save,
    .clear = app_storage_clear,
};

// Runs inside the LVGL task, so it must never block: a Wi-Fi scan takes seconds
// and would freeze the UI. The line is queued and executed by the main loop.
static void ui_command_enqueue(const char* line) {
  if (s_ui_cmds == nullptr || line == nullptr) {
    return;
  }
  char buffer[UI_CMD_LEN];
  strncpy(buffer, line, sizeof(buffer) - 1);
  buffer[sizeof(buffer) - 1] = '\0';
  xQueueSend(s_ui_cmds, buffer, 0);
}

static void ui_commands_drain(void) {
  char buffer[UI_CMD_LEN];
  while (xQueueReceive(s_ui_cmds, buffer, 0) == pdTRUE) {
    wireless_console_execute(buffer);
  }
}
#endif

void setup() {
#ifdef LED
  pinMode(LED, OUTPUT);
#if LED_ACTIVE_LOW
  digitalWrite(LED, HIGH);
#else
  digitalWrite(LED, LOW);
#endif
#endif

  init_serial_console();

  // No SoftAP: the board must not advertise a BSSID, so it never sends beacons.
  WiFi.mode(WIFI_MODE_STA);
  WiFi.disconnect();

  init_evil_twin();

#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  s_ui_cmds = xQueueCreate(UI_CMD_DEPTH, UI_CMD_LEN);
  if (s_ui_cmds == nullptr) {
    Serial.println("WARN UI command queue alloc failed");
  }
  wireless_ui_set_storage(&kStorageOps);
  if (wireless_ui_init()) {
    wireless_ui_set_command_cb(ui_command_enqueue);
    Serial.println("INFO LVGL UI ready");
  } else {
    Serial.println("WARN LVGL UI init failed, running headless");
  }
#endif
}

void loop() {
  handle_serial_console();

#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  ui_commands_drain();
  wireless_ui_tick();
#endif

  // Drives multi-AP channel hopping, probe pacing and station discovery.
  attack_step();
  delay(2);

  if (evil_twin_mode == EVIL_TWIN_CAPTURING) {
    handle_evil_twin();
  }
}
