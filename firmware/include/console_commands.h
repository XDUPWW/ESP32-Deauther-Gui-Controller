// The bridge between the wbus registry and the console handlers.
//
// Why a header instead of letting bus_objects.cpp call the modules directly: a few
// of these helpers (scan count, reason application, the UI log) live in
// serial_console.cpp, and exposing them here keeps the migration one command at a
// time instead of a big-bang move of 1700 lines.
#ifndef CONSOLE_COMMANDS_H
#define CONSOLE_COMMANDS_H

#include <stdint.h>

#include "wbus.h"

// Number of APs from the last SCAN (the index space every attack command uses).
int console_scan_count(void);

// The legacy "1,3,5" index list parser, shared with DEAUTH_ONLY / DEAUTH_EXCEPT.
int console_parse_index_list(char* text, int* out, int max);

// Applies an already policy-checked reason argument ("random" or 1..65535).
// Returns false when the value was rejected (the ERR/INFO line is already printed).
bool console_apply_reason(const wb_value_t* value, uint16_t* out_value);

// Mirrors a line into the LVGL log when the UI is compiled in. Wrapper rather than
// ui_log() itself: the console's ui_log() has internal linkage, this one does not.
void console_ui_log(const char* text);

// Fills the registry. Called once from init_serial_console().
void wbus_register_all(void);

#endif  // CONSOLE_COMMANDS_H
