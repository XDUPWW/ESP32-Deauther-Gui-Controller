#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Authentication / Association Request flooding with automatic WPA3 upgrade.
//
// Every Authentication (algorithm 0, sequence 1) starts a state machine on the
// AP keyed by the transmitter address, and every (Re)Association Request tries to
// allocate a station table entry. Forging a different transmitter address for
// each exchange therefore costs the AP real memory and CPU, and once its station
// table is full *legitimate* stations are refused -- which is why the status
// codes the AP answers with are the interesting output (17 = "AP is unable to
// handle additional associated STAs" is the goal, not a failure).
//
// WPA3 throws a spanner in: an SAE AP answers a plain open-system Authentication
// with status 13 (authentication algorithm not supported) and the flood stops
// costing anything. So the module classifies the target from its beacon RSN IE
// (the same `sae_classify()` the SAE module uses) and, when the AKM list contains
// SAE, hands over to the SAE Commit flood instead of hammering a frame the AP
// rejects. That switch is what `upgraded` reports.
//
// The pairing of one Authentication with one Association Request per identity is
// deliberate: a body that never authenticated still makes the AP allocate and
// then release a table entry, and the two frames together are what a real station
// sends.

typedef enum {
    AUTHFLOOD_BOTH = 0,
    AUTHFLOOD_AUTH_ONLY = 1,
    AUTHFLOOD_ASSOC_ONLY = 2,
} authflood_mode_t;

bool authflood_start(int index, authflood_mode_t mode, bool auto_upgrade);

void authflood_stop(void);

// Called from the main loop (via attack_step).
void authflood_step(void);

// Called by the promiscuous sniffer: learns the target's SSID / RSN element and
// counts the AP's answers to our identities.
void authflood_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps one forged Authentication and one Association Request (format check).
void authflood_selftest(void);

bool authflood_active(void);
const char* authflood_mode_name(void);
uint32_t authflood_frames(void);
uint32_t authflood_auth_frames(void);
uint32_t authflood_assoc_frames(void);
uint32_t authflood_identities(void);
uint32_t authflood_auth_responses(void);
uint32_t authflood_assoc_responses(void);
// Last status code the AP answered with (13 = algorithm unsupported,
// 17 = station table full, 0 = accepted).
uint16_t authflood_last_status(void);
bool authflood_upgraded(void);

#ifdef __cplusplus
}
#endif
