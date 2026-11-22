#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 802.11k Radio Resource Measurement (RRM) spoofing: a forged Neighbor Report
// Response.
//
// The AP answers a client's Neighbor Report Request with a list of "other BSSes
// you may roam to". A forged response whose TA is the AP's BSSID makes the client
// record phantom neighbours and, depending on the stack, steer to one of them --
// the same lever as the BTM module, only through the 11k channel instead of 11v.
//
// Frame: Action (mgmt subtype 13), category 5 (Radio Measurement), action 5
// (Neighbor Report Response), then a dialog token and one Neighbor Report element
// (id 52, length 13). Addr1 = target STA, Addr2 = Addr3 = the AP BSSID.
//
// PMF boundary: category 5 is one of the robust action categories (Linux:
// _ieee80211_is_robust_mgmt_frame()), so a client that negotiated 802.11w drops an
// unprotected frame like this in its driver. The attack therefore only has a
// window on links without PMF, or on clients that skip the check. Frame-level
// verification only -- see attack-principles.md §9 for what is and is not measured.
//
// Field values that the standard does not spell out in a way we could verify
// (BSSID Information bits, Operating Class, PHY Type) are parameters with a zero
// default on purpose: fill them from a real Neighbor Report Response captured with
// lab/cap_frames.py instead of trusting a bit table from anywhere.

typedef enum {
    RRM_MODE_OFF = 0,
    RRM_MODE_NBR = 1,  // forged Neighbor Report Response
} rrm_mode_t;

// `candidate_bssid`/`candidate_channel`: the phantom neighbour announced in the
// report. `count`: how many frames this run injects in total, 0 = keep going until
// RRMSTOP. `token`: dialog token, 0..255 (0 = unanswered requests, which is what a
// real AP sends when the client did not ask). `bssid_info`, `op_class`, `phy_type`:
// see the note above about unverified field values.
bool rrm_start(int index, const uint8_t candidate_bssid[6], uint8_t candidate_channel,
               uint8_t count, uint8_t token, uint32_t bssid_info, uint8_t op_class,
               uint8_t phy_type);

// Registers a station explicitly, so a report goes out even before that station has
// shown any traffic -- needed when the victim is known by MAC (bench runs).
void rrm_add_station(const uint8_t mac[6]);

void rrm_stop(void);

// Called from the main loop (via the module table).
void rrm_step(void);

// Called by the promiscuous sniffer for every received frame.
void rrm_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps the exact bytes of the Neighbor Report Response with decoded fields.
void rrm_selftest(void);

bool rrm_active(void);
const char* rrm_mode_name(void);
uint32_t rrm_frames(void);
// Stations this module has learned (a report goes out to each of them in turn).
uint32_t rrm_clients(void);
// Frames still to inject in this run; 0 with `rrm_active()` true means "unlimited".
uint8_t rrm_remaining(void);
// Neighbor Report Requests / Responses seen on the air: the first tells whether
// the victim ever asked its AP for neighbours, the second how often the real AP
// overrides our phantom record.
uint32_t rrm_requests(void);
// 带受害者自己 dialog token 发出去的帧数（应答式投毒命中数）
uint32_t rrm_token_hits(void);
uint32_t rrm_responses(void);
uint8_t rrm_candidate_channel(void);
uint8_t rrm_token(void);
uint32_t rrm_bssid_info(void);
uint8_t rrm_op_class(void);
uint8_t rrm_phy_type(void);

#ifdef __cplusplus
}
#endif
