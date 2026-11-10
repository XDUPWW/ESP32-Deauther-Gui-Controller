#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// CSA (Channel Switch Announcement) spoofing, 802.11-2020 / 802.11h.
//
// The AP tells clients "move to channel N in `count` beacons" through:
//   * a CSA IE (element 37) inside Beacon / Probe Response, or
//   * an Action frame (category 4 = spectrum management, action 4).
// Neither is a robust management frame, so 802.11w (PMF) does not protect them:
// this still works against WPA3 / PMF clients, unlike deauth.
//
// The spoofer mimics a real AP: it announces count N..1 on consecutive
// beacon-sized ticks (100 TU ~= 102 ms), mixes broadcast and unicast frames so
// clients that ignore one form still see the other, and after the last count it
// hops to the new channel and keeps a cloned beacon alive there, so the client
// finds "its" AP instead of falling back to the old channel immediately.

// Starts spoofing for the AP at `index` (index from the last SCAN).
// new_channel: where clients should go (validated by the caller: 1..196).
// start_count: first CSA count value (2..8 recommended, mimics a real AP).
// hold_seconds: how long to keep the cloned beacon on the new channel.
// new_channel == 0 means "auto": a 2.4 GHz AP gets a random 5 GHz channel
// (and the other way round), and the cycle repeats until csa_stop().
// hold_ms is the per-round impersonation window on the new channel (500 ms in
// auto mode): beacons + auth accepted + assoc refused, so clients keep retrying.
bool csa_start(int index, uint8_t new_channel, uint8_t start_count, uint16_t hold_ms, bool loop);

void csa_stop(void);

// Called from the main loop every iteration.
void csa_step(void);

// Called by the promiscuous sniffer for every received frame, so the spoofer can
// learn client MACs (for unicast CSA) and the target's RSN IE (for the clone).
// `frame` points at the start of the 802.11 header, `len` is the frame length.
void csa_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps the exact bytes of one action frame and one CSA-IE beacon (format check).
void csa_selftest(void);

bool csa_active(void);
uint32_t csa_frames(void);
uint32_t csa_clients(void);
uint8_t csa_new_channel(void);
// True when the announced channel is picked from the opposite band.
bool csa_auto_channel(void);
// Completed announce+hold cycles (looping mode).
uint32_t csa_cycles(void);
// HOLD phase impersonation: auth answered with success, assoc refused on purpose.
uint32_t csa_auth_replies(void);
uint32_t csa_assoc_rejects(void);
uint8_t csa_current_count(void);
bool csa_have_rsn(void);
const char* csa_phase_name(void);

#ifdef __cplusplus
}
#endif
