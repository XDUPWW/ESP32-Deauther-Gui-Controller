#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

// Injection guard shared by every module that injects raw frames.
//
// The driver hands out a fixed pool of short (management + control) frames --
// 32 in the measurements of 测试报告 §4.3. When it is exhausted
// esp_wifi_80211_tx() answers ESP_ERR_NO_MEM (0x101) and from then on the radio
// keeps refusing frames until the whole WiFi stack is re-initialised; the pool
// probe never saw it recover by waiting.
//
// Measured ceiling (ESP32 + ESP-IDF 6.1, 华为 AP 信道 12, lab/pool_limit.py +
// lab/cap_frames.py).
//
// NOMEM happens on OUR side: 0x101 is our driver refusing to hand out another TX
// buffer, not the AP refusing anything.
//
// Why unicast fills it and broadcast does not:
//   * a unicast frame must be acknowledged. Ours carry a forged transmitter
//     address, so the AP's ACK is addressed to a MAC this chip does not own and
//     never counts as "my frame was delivered" -- the MAC retransmits to the
//     retry limit and only then releases the buffer;
//   * the AP answers our frames too (status 13 for a WPA2 AP) and *it* retries
//     as well, because we never ACK its reply (same forged-address problem in the
//     other direction). Measured: 12.7 AP retransmissions per injected commit;
//   * measured channel load at a mere 20 frames/s of injection was ~220
//     frames/s, so the radio spends most of its time on retransmissions and on
//     waiting for channel access. Each buffer is held for that whole time.
//   * a broadcast frame (the clone beacon) needs no ACK, gets no replies, and its
//     buffer comes back immediately -- 50 frames/s for a minute is fine.
//
// The usable pool therefore behaves like a leaky bucket: arrivals = injection
// rate, departures ~= 32 frames/s, capacity ~= 22 buffers. Pool-full time is
// P/(R-d), which matches every measurement:
//
//     R = 50 frames/s -> 63 frames  (1.26 s)  -> 0x101
//     R = 40 frames/s -> 117 frames (2.93 s)  -> 0x101
//     R = 30 frames/s -> 1350 frames / 45 s   -> clean
//     R = 20 frames/s -> 900 frames / 45 s    -> clean
//     broadcast beacons, 50 frames/s -> 3000 frames / 60 s -> clean
//
// (Solving P/(50-d)=1.26 and P/(40-d)=2.93 gives d=32.5 frames/s, P=22. The
// exact per-frame hold time is NOT directly observable: the driver never calls
// esp_wifi_register_80211_tx_cb() for injected frames, and the capture pipe drops
// frames, so the curve above is the evidence, not a stopwatch.)
//
// The pool diagnostics that exist to measure that limit on purpose (BARSEQ, the
// NAV-era NAVSEQ) deliberately stay outside this guard: restarting there would
// destroy the very measurement they exist for.
//
// ---- pacing and 0x101 are now policy, not per-module folklore ----------------
//
// Every injection path calls tx_guard_send_as() with a policy, so there is exactly
// one place that decides "too fast, drop this tick" and exactly one place that
// decides what a full pool means. The modules differ only in the data below, and
// the difference is real: a burst of two unicast deauth frames plus one broadcast
// cannot be paced at 33 ms, and the BA sequence (DELBA -> ADDBA -> BAR) is
// deliberately back to back.

typedef enum {
    // Count the refusal and let the caller retry on its next tick. Used where the
    // module owns a natural retry cadence and a reboot would throw away its state
    // (deauth's scan table, BA's sequence numbers).
    TX_ON_NOMEM_BACKOFF = 0,
    // Print FATAL and esp_restart(): the frame-level flood modules, whose whole
    // run is disposable and whose pool is a hard wall.
    TX_ON_NOMEM_RESTART,
} tx_nomem_action_t;

typedef struct {
    const char* name;        // shown by RADIO / DESCRIBE
    uint16_t min_gap_ms;     // 0 = the caller paces itself (burst sequences)
    tx_nomem_action_t on_nomem;
} tx_policy_t;

// 45 ms between unicast frames, restart on 0x101: the frame-level modules
// (BTM / RRM / EAPOL / QOSNULL / SAE / AUTHFLOOD) plus CSA. This is the ~20 fps
// ceiling from the measurements above.
extern const tx_policy_t kTxPolicyGuard;

// No pacing, back off on 0x101: deauth (its pacing lives in attack_step() --
// a gap here would silently drop the second frame of every unicast pair) and the
// DELBA/BA sequence (the 40 ms tick is what produced the -99% throughput result,
// and DELBA/ADDBA/BAR are sent back to back inside one tick).
extern const tx_policy_t kTxPolicyBurst;

esp_err_t tx_guard_send_as(const tx_policy_t* policy, uint8_t* frame, uint16_t len);

// Convenience wrapper for the guard policy. Callers treat any non-OK result as
// "nothing was sent this tick" and retry on their next tick, which is exactly what
// a flood loop wants; a policy that throttles returns ESP_ERR_INVALID_STATE without
// touching the driver and counts it as "throttled" (not as an error). Broadcast
// frames (group RA) are never throttled in the guard policy: they need no ACK, so
// their buffer comes back immediately and they cannot fill the pool.
esp_err_t tx_guard_send(uint8_t* frame, uint16_t len);

#define TX_GUARD_UNICAST_GAP_MS 45

// Frames refused by the governor so far (never reached the driver).
uint32_t tx_guard_throttled(void);

uint32_t tx_guard_ok(void);
uint32_t tx_guard_err(void);
int32_t tx_guard_last_err(void);

#ifdef __cplusplus
}
#endif
