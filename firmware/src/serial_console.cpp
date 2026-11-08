#include "serial_console.h"

#include <Arduino.h>
#include <WiFi.h>
#include <ctype.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <sdkconfig.h>
#include <stdlib.h>
#include <string.h>

#include "deauth.h"
#include "definitions.h"
#include "evil_twin.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
#include "wireless_ui.h"
#endif

namespace {

char g_line[112];
size_t g_len = 0;
int g_scan_count = 0;

TaskHandle_t s_scan_task = nullptr;
volatile bool s_scan_busy = false;

const char* auth_name(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN:
      return "OPEN";
    case WIFI_AUTH_WEP:
      return "WEP";
    case WIFI_AUTH_WPA_PSK:
      return "WPA";
    case WIFI_AUTH_WPA2_PSK:
      return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:
      return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE:
      return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK:
      return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK:
      return "WPA2/WPA3";
    case WIFI_AUTH_WAPI_PSK:
      return "WAPI";
    default:
      return "UNKNOWN";
  }
}

const char* attack_mode_label() {
  if (evil_twin_mode == EVIL_TWIN_CAPTURING) return "eviltwin";
  if (evil_twin_mode == EVIL_TWIN_DEAUTHING) return "eviltwin-deauth";
  return attack_mode_name();
}

const char* capabilities() {
#if CONFIG_SOC_WIFI_SUPPORT_5G
  return "deauth,eviltwin,probe,5g";
#else
  return "deauth,eviltwin,probe";
#endif
}

void ui_log(const char* text) {
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  wireless_ui_log(text);
#else
  (void)text;
#endif
}

void mac_to_str(const uint8_t* mac, char* out) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4],
           mac[5]);
}

void print_help() {
  Serial.println("INFO Wireless-Attack serial console");
  Serial.println("INFO HELP                          this text");
  Serial.println("INFO PING / STATUS / STATS         liveness, counters, per-AP counters");
  Serial.println("INFO SCAN                          scan APs (async)");
  Serial.println("INFO DEAUTH <idx> [reason]         deauth one AP");
  Serial.println("INFO DEAUTH_ALL [reason]           deauth every scanned AP");
  Serial.println("INFO DEAUTH_ONLY <i,j,..> [reason] deauth only these APs");
  Serial.println("INFO DEAUTH_EXCEPT <i,j,..>        deauth every AP except these");
  Serial.println("INFO STATIONS [sec]                discover client STAs (default 6s)");
  Serial.println("INFO PROBE_BROADCAST               flood fake APs (beacon + probe response)");
  Serial.println("INFO STOP                          stop the current attack");
  Serial.println("INFO EVILTWIN <idx> / EVILTWIN_STOP / CREDS");
  Serial.println("INFO TOUCH / CALIBRATE             LVGL touch readback / recalibrate");
  Serial.println("INFO UITARGETS / UI                LVGL target popup: open / report state");
  Serial.println("INFO RXMIX                         received frame mix (beacon/probe/deauth/ctrl/data)");
}

// ------------------------------------------------------------------ parsing

int parse_index(char* token) {
  if (token == nullptr) return -1;
  char* end = nullptr;
  const long value = strtol(token, &end, 10);
  if (end == token) return -1;
  return (int)value;
}

uint16_t parse_reason(char* token) {
  if (token == nullptr) return 1;
  char* end = nullptr;
  const long value = strtol(token, &end, 10);
  if (end == token || value <= 0 || value > 65535) return 1;
  return (uint16_t)value;
}

int parse_index_list(char* text, int* out, int max) {
  if (text == nullptr) return 0;
  int count = 0;
  char* cursor = text;
  while (cursor != nullptr && *cursor != 0 && count < max) {
    char* next = strchr(cursor, ',');
    if (next != nullptr) {
      *next = 0;
    }
    const int value = parse_index(cursor);
    if (value >= 0) {
      out[count++] = value;
    }
    cursor = (next == nullptr) ? nullptr : next + 1;
  }
  return count;
}

// ------------------------------------------------------------------ commands

void do_scan() {
  prepare_radio_for_scan();
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  wireless_ui_scan_begin();
#endif
  g_scan_count = WiFi.scanNetworks();
  Serial.println("SCAN_BEGIN");
  for (int i = 0; i < g_scan_count; i++) {
    Serial.printf("NET %d %d %d %s %s %s\n", i, (int)WiFi.RSSI(i), (int)WiFi.channel(i),
                  auth_name(WiFi.encryptionType(i)), WiFi.BSSIDstr(i).c_str(), WiFi.SSID(i).c_str());
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
    // Keep the String objects alive until the UI has copied the text: taking
    // c_str() straight into the struct leaves dangling pointers.
    const String ui_ssid = WiFi.SSID(i);
    const String ui_bssid = WiFi.BSSIDstr(i);
    const wireless_ui_network_t net = {
        .index = (uint16_t)i,
        .rssi = (int8_t)WiFi.RSSI(i),
        .channel = (uint8_t)WiFi.channel(i),
        .auth = auth_name(WiFi.encryptionType(i)),
        .bssid = ui_bssid.c_str(),
        .ssid = ui_ssid.c_str(),
    };
    wireless_ui_add_network(&net);
#endif
  }
  Serial.printf("SCAN_END %d\n", g_scan_count);
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  wireless_ui_scan_end(g_scan_count);
#endif
}

static void scan_task(void* arg) {
  (void)arg;
  for (;;) {
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    do_scan();
    s_scan_busy = false;
  }
}

void start_scan() {
  if (s_scan_task == nullptr) {
    Serial.println("ERR scanner task not ready");
    return;
  }
  if (s_scan_busy) {
    Serial.println("ERR scan already running");
    return;
  }
  s_scan_busy = true;
  xTaskNotifyGive(s_scan_task);
}

void do_status() {
  int ui = 0;
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  ui = wireless_ui_ready() ? 1 : 0;
#endif
  Serial.print("STATUS mode=");
  Serial.print(attack_mode_label());
  Serial.print(" eliminated=");
  Serial.print(eliminated_stations);
  Serial.print(" deauth_frames=");
  Serial.print((unsigned)attack_deauth_frames());
  Serial.print(" probe_frames=");
  Serial.print((unsigned)attack_probe_frames());
  {
    uint8_t prim = 0;
    wifi_second_chan_t sec = WIFI_SECOND_CHAN_NONE;
    esp_wifi_get_channel(&prim, &sec);
    Serial.print(" ch=");
    Serial.print((int)prim);
  }
  Serial.print(" rx=");
  Serial.print((unsigned)attack_rx_frames());
  Serial.print(" rxm=");
  Serial.print((unsigned)attack_rx_matches());
  Serial.print(" txok=");
  Serial.print((unsigned)attack_tx_ok());
  Serial.print(" txerr=");
  Serial.print((unsigned)attack_tx_err());
  Serial.print(" txerr_nomem=");
  Serial.print((unsigned)attack_tx_err_nomem());
  Serial.print(" txerr_inval=");
  Serial.print((unsigned)attack_tx_err_invalid());
  Serial.print(" txerr_other=");
  Serial.print((unsigned)attack_tx_err_other());
  Serial.print(" txec=");
  Serial.print(attack_tx_last_err());
  Serial.print(" txdrop=");
  Serial.print((unsigned)attack_tx_dropped());
  Serial.print(" blind=");
  Serial.print((unsigned)attack_blind_frames());
  Serial.print(" networks=");
  Serial.print(g_scan_count);
  Serial.print(" creds=");
  Serial.print(captured_count);
  Serial.print(" heap=");
  Serial.print((unsigned)esp_get_free_heap_size());
  Serial.print(" ui=");
  Serial.print(ui);
  Serial.print(" caps=");
  Serial.println(capabilities());
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  wireless_ui_status(attack_mode_label(), eliminated_stations, g_scan_count, captured_count,
                     attack_deauth_frames(), attack_probe_frames());
#endif
}

void do_stats() {
  const int aps = attack_ap_count();
  Serial.print("STATS_BEGIN mode=");
  Serial.print(attack_mode_label());
  Serial.print(" deauth_frames=");
  Serial.print((unsigned)attack_deauth_frames());
  Serial.print(" probe_frames=");
  Serial.print((unsigned)attack_probe_frames());
  Serial.print(" aps=");
  Serial.println(aps);
  for (int i = 0; i < aps; i++) {
    const uint8_t* bssid = nullptr;
    uint32_t frames = 0;
    uint8_t channel = 0;
    if (!attack_ap_info(i, &bssid, &frames, &channel)) {
      continue;
    }
    char mac[18];
    mac_to_str(bssid, mac);
    Serial.printf("AP %d %s ch%u frames=%u\n", i, mac, (unsigned)channel, (unsigned)frames);
  }
  Serial.println("STATS_END");
}

void do_deauth(int index, uint16_t reason) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  if (!attack_deauth_single(index, reason)) {
    Serial.println("ERR cannot start deauth on that network");
    return;
  }
  Serial.printf("OK DEAUTH %d %s\n", index, WiFi.SSID(index).c_str());
  ui_log("deauth started");
}

void do_deauth_all(uint16_t reason) {
  if (g_scan_count == 0) {
    Serial.println("ERR no AP list, run SCAN first");
    return;
  }
  if (!attack_deauth_all(reason)) {
    Serial.println("ERR cannot start deauth-all");
    return;
  }
  Serial.printf("OK DEAUTH_ALL aps=%d\n", attack_ap_count());
  ui_log("deauth all started");
}

void do_deauth_list(char* list, uint16_t reason, bool except) {
  int indexes[MAX_AP_TARGETS];
  const int count = parse_index_list(list, indexes, MAX_AP_TARGETS);
  if (count == 0) {
    Serial.println("ERR need an index list, e.g. DEAUTH_ONLY 1,3,5");
    return;
  }
  if (g_scan_count == 0) {
    Serial.println("ERR no AP list, run SCAN first");
    return;
  }
  const bool ok = except ? attack_deauth_except(indexes, count, reason)
                         : attack_deauth_only(indexes, count, reason);
  if (!ok) {
    Serial.println("ERR cannot start that deauth set");
    return;
  }
  Serial.printf("OK %s %d aps\n", except ? "DEAUTH_EXCEPT" : "DEAUTH_ONLY", attack_ap_count());
  ui_log(except ? "deauth except started" : "deauth only started");
}

void do_stop() {
  attack_stop();
  Serial.printf("OK STOP deauth_frames=%u probe_frames=%u\n",
                (unsigned)attack_deauth_frames(), (unsigned)attack_probe_frames());
  ui_log("stopped");
}

void do_probe_broadcast() {
  if (!attack_probe_broadcast()) {
    Serial.println("ERR cannot start probe broadcast");
    return;
  }
  Serial.println("OK PROBE_BROADCAST");
  ui_log("probe broadcast started");
}

void do_stations(char* seconds_token) {
  int seconds = parse_index(seconds_token);
  if (seconds <= 0 || seconds > 60) {
    seconds = 6;
  }
  stations_begin((uint16_t)seconds);
  Serial.printf("OK STATIONS scanning for %ds\n", seconds);
}

void print_stations() {
  Serial.println("STA_BEGIN");
  const int count = stations_count();
  for (int i = 0; i < count; i++) {
    const uint8_t* mac = nullptr;
    const uint8_t* ap = nullptr;
    uint8_t channel = 0;
    int16_t rssi = 0;
    uint32_t frames = 0;
    if (!stations_info(i, &mac, &ap, &channel, &rssi, &frames)) {
      continue;
    }
    char mac_text[18];
    char ap_text[18];
    mac_to_str(mac, mac_text);
    mac_to_str(ap, ap_text);
    Serial.printf("STA %d %s %s ch%u %ddB frames=%u\n", i, mac_text, ap_text, (unsigned)channel,
                  (int)rssi, (unsigned)frames);
  }
  Serial.printf("STA_END %d\n", count);
}

void do_rxlog() {
  const int count = attack_rx_log_count();
  Serial.print("RXLOG_BEGIN ");
  Serial.println(count);
  for (int i = 0; i < count; i++) {
    uint8_t dest[6], src[6], bssid[6], type = 0, subtype = 0;
    uint16_t len = 0;
    if (!attack_rx_log_at(i, dest, src, bssid, &type, &subtype, &len)) continue;
    char d[18], s[18], b[18];
    mac_to_str(dest, d);
    mac_to_str(src, s);
    mac_to_str(bssid, b);
    Serial.print("RX ");
    Serial.print(i);
    Serial.print(" type=");
    Serial.print((unsigned)type);
    Serial.print(" sub=");
    Serial.print((unsigned)subtype);
    Serial.print(" len=");
    Serial.print((unsigned)len);
    Serial.print(" dest=");
    Serial.print(d);
    Serial.print(" src=");
    Serial.print(s);
    Serial.print(" bssid=");
    Serial.println(b);
  }
  Serial.println("RXLOG_END");
}

void do_creds() {
  Serial.println("CREDS_BEGIN");
  for (int i = 0; i < captured_count; i++) {
    Serial.printf("CRED %d %s %s %lu\n", i, captured_creds[i].username, captured_creds[i].password,
                  captured_creds[i].timestamp);
  }
  Serial.printf("CREDS_END %d\n", captured_count);
}

void do_evil_twin(int index) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    ui_log("evil twin: index out of range");
    return;
  }
  Serial.printf("OK EVILTWIN %d %s\n", index, WiFi.SSID(index).c_str());
  ui_log("evil twin starting");
  start_evil_twin_attack(index);
}

void do_evil_twin_stop() {
  stop_evil_twin();
  Serial.println("OK EVILTWIN_STOP");
  ui_log("evil twin stopped");
}

void do_touch() {
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  int raw_x = 0;
  int raw_y = 0;
  int screen_x = 0;
  int screen_y = 0;
  bool pressed = false;
  wireless_ui_touch_readback(&raw_x, &raw_y, &screen_x, &screen_y, &pressed);
  Serial.print("TOUCH raw_x=");
  Serial.print(raw_x);
  Serial.print(" raw_y=");
  Serial.print(raw_y);
  Serial.print(" x=");
  Serial.print(screen_x);
  Serial.print(" y=");
  Serial.print(screen_y);
  Serial.print(" pressed=");
  Serial.print(pressed ? 1 : 0);
  Serial.print(" irq=");
  Serial.println(wireless_ui_touch_irq_level());
#else
  Serial.println("ERR LVGL UI is not enabled in this build");
#endif
}

void do_calibrate() {
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  Serial.println("OK CALIBRATE, restarting");
  delay(100);
  wireless_ui_request_calibration();
#else
  Serial.println("ERR LVGL UI is not enabled in this build");
#endif
}

// Opens the on-screen target picker without touching the panel, so the popup
// can be exercised from the host (same path a finger takes).
void do_ui_targets() {
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  wireless_ui_show_targets();
  Serial.println("OK UITARGETS");
#else
  Serial.println("ERR LVGL UI is not enabled in this build");
#endif
}

// Received-frame mix. Run it on a second board (or right after an attack on this
// one) to check what the radio actually hears: beacon / probe response / deauth
// counts plus control and data totals.
void do_rx_mix() {
  uint32_t mgmt[16] = {0};
  uint32_t ctrl = 0;
  uint32_t data = 0;
  attack_rx_mix(mgmt, &ctrl, &data);
  uint32_t other = 0;
  for (int i = 0; i < 16; i++) {
    if (i != 0 && i != 1 && i != 2 && i != 4 && i != 5 && i != 8 && i != 11 && i != 12) {
      other += mgmt[i];
    }
  }
  Serial.print("RXMIX beacon=");
  Serial.print((unsigned)mgmt[8]);
  Serial.print(" proberesp=");
  Serial.print((unsigned)mgmt[5]);
  Serial.print(" probereq=");
  Serial.print((unsigned)mgmt[4]);
  Serial.print(" deauth=");
  Serial.print((unsigned)mgmt[12]);
  Serial.print(" auth=");
  Serial.print((unsigned)mgmt[11]);
  Serial.print(" assoc=");
  Serial.print((unsigned)(mgmt[0] + mgmt[1] + mgmt[2]));
  Serial.print(" other_mgmt=");
  Serial.print((unsigned)other);
  Serial.print(" ctrl=");
  Serial.print((unsigned)ctrl);
  Serial.print(" data=");
  Serial.println((unsigned)data);
}

void do_ui_state() {
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  Serial.print("UI screen=");
  Serial.print(wireless_ui_screen_name());
  Serial.print(" popup=");
  Serial.print(wireless_ui_popup_visible() ? 1 : 0);
  Serial.print(" items=");
  Serial.print(wireless_ui_popup_items());
  Serial.print(" nets=");
  Serial.println(g_scan_count);
#else
  Serial.println("ERR LVGL UI is not enabled in this build");
#endif
}

// ------------------------------------------------------------------ dispatch

void dispatch(char* line) {
  char* command = strtok(line, " \t");
  if (command == nullptr) return;
  for (char* p = command; *p != 0; p++) *p = (char)toupper((unsigned char)*p);

  if (strcmp(command, "HELP") == 0) {
    print_help();
  } else if (strcmp(command, "PING") == 0) {
    Serial.println("OK PONG");
  } else if (strcmp(command, "SCAN") == 0) {
    start_scan();
  } else if (strcmp(command, "STATUS") == 0) {
    do_status();
  } else if (strcmp(command, "STATS") == 0) {
    do_stats();
  } else if (strcmp(command, "STOP") == 0) {
    do_stop();
  } else if (strcmp(command, "DEAUTH") == 0) {
    // One strtok per statement: two calls inside one argument list have
    // unspecified evaluation order and corrupt the arguments.
    char* index_token = strtok(nullptr, " \t");
    char* reason_token = strtok(nullptr, " \t");
    do_deauth(parse_index(index_token), parse_reason(reason_token));
  } else if (strcmp(command, "DEAUTH_ALL") == 0) {
    do_deauth_all(parse_reason(strtok(nullptr, " \t")));
  } else if (strcmp(command, "DEAUTH_ONLY") == 0) {
    char* list = strtok(nullptr, " \t");
    char* reason_token = strtok(nullptr, " \t");
    do_deauth_list(list, parse_reason(reason_token), false);
  } else if (strcmp(command, "DEAUTH_EXCEPT") == 0) {
    char* list = strtok(nullptr, " \t");
    char* reason_token = strtok(nullptr, " \t");
    do_deauth_list(list, parse_reason(reason_token), true);
  } else if (strcmp(command, "STATIONS") == 0) {
    do_stations(strtok(nullptr, " \t"));
    } else if (strcmp(command, "PROBE_BROADCAST") == 0) {
    do_probe_broadcast();
  } else if (strcmp(command, "EVILTWIN") == 0) {
    do_evil_twin(parse_index(strtok(nullptr, " \t")));
  } else if (strcmp(command, "EVILTWIN_STOP") == 0) {
    do_evil_twin_stop();
  } else if (strcmp(command, "CREDS") == 0) {
    do_creds();
  } else if (strcmp(command, "RXLOG") == 0) {
    do_rxlog();
  } else if (strcmp(command, "RXMIX") == 0) {
    do_rx_mix();
  } else if (strcmp(command, "TOUCH") == 0) {
    do_touch();
  } else if (strcmp(command, "UITARGETS") == 0) {
    do_ui_targets();
  } else if (strcmp(command, "UI") == 0) {
    do_ui_state();
  } else if (strcmp(command, "CALIBRATE") == 0) {
    do_calibrate();
  } else {
    Serial.printf("ERR unknown command '%s' (try HELP)\n", command);
    ui_log("unknown command");
  }
}

}  // namespace

void init_serial_console() {
  // The default UART RX ring is 256 bytes; a burst of commands (the GUI, a script,
  // or a pentest harness) overruns it and lines get dropped. Grow it *before*
  // begin() so the driver allocates the bigger ring.
  Serial.setRxBufferSize(SERIAL_RX_BUFFER_SIZE);
  Serial.begin(115200);
  xTaskCreate(scan_task, "scan", 4096, nullptr, 2, &s_scan_task);
  delay(50);
  Serial.println("INFO Wireless-Attack ready, type HELP");
}

void handle_serial_console() {
  if (stations_poll()) {
    print_stations();
  }
  while (Serial.available() > 0) {
    const char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      g_line[g_len] = 0;
      if (g_len > 0) dispatch(g_line);
      g_len = 0;
    } else if (g_len < sizeof(g_line) - 1) {
      g_line[g_len++] = c;
    } else {
      g_len = 0;
      Serial.println("ERR line too long");
    }
  }
}

void wireless_console_execute(const char* line) {
  if (line == nullptr) return;
  char buffer[112];
  size_t len = strlen(line);
  if (len >= sizeof(buffer)) len = sizeof(buffer) - 1;
  memcpy(buffer, line, len);
  buffer[len] = 0;
  dispatch(buffer);
}
