#pragma once

#include <stdint.h>
#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

// Minimal channel arbiter for the one radio every attack shares.
//
// The radio serves one attack at a time, but nothing enforced that: deauth hops
// while attacking, CSA parks on the announced channel, and every other module
// claims its own channel at start. When two of them run, the channel ends up
// wherever the last writer put it and the symptom is "counters move but nothing is
// on air" -- exactly the bug PS-POLL hit during a scan (see 测试报告 缺陷 39).
//
// This records the owner and reports a takeover with one WARN line. It does NOT
// deny the request: preemption would change the multi-attack timing the throughput
// measurements depend on, and the useful part right now is visibility.
esp_err_t radio_set_channel(const char* owner, uint8_t channel);

const char* radio_owner(void);   // "" when nobody claimed yet
uint8_t radio_channel(void);     // last claimed channel, 0 = unknown
uint32_t radio_takeovers(void);  // claims that displaced a different owner

#ifdef __cplusplus
}
#endif
