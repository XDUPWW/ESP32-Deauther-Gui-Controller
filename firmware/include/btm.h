#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 802.11v BSS Transition Management (BTM) Request spoofing.
//
// The AP tells a client "move to another BSS, and by the way you have N TBTTs
// before I disassociate you" with a 802.11v Action frame (category 10, action 7).
// A forged frame whose TA is the AP's BSSID is accepted and acted on like a
// deauth, only "legally" and without any obvious disconnection.
// PMF: category 10 is inside the robust set (all action categories except
// Public/HT/the unprotected one/Self-protected/VHT/vendor), so a client that
// negotiated PMF drops an unprotected BTM Request in its driver
// (net/mac80211/rx.c) before any BTM code runs. Against PMF-less networks the
// forged TA = AP BSSID is enough.
//
// What the client does with it (from wpa_supplicant's 802.11v client, which is
// the reference behaviour):
//   * Disassociation Imminent set + a *non-zero* Disassociation Timer
//     -> "Trying to find another BSS" + an immediate scan. A timer of 0 means
//        the client has no deadline and does not scan, which is why this module
//        defaults to a non-zero timer.
//   * No candidate list (this module's only shape) -> the client answers with a
//        BTM Response and then scans on its own; the timer is what forces the
//        scan. Measured on a real station: with a same-SSID, same-security BSS in
//        range it moves there within ~0.1 s.
//
// Only clients that advertise the BSS Transition bit (Extended Capabilities,
// bit 19) act on it, so the sniffer learns that bit from the client's probe /
// (re)association request and clients that say "no" are skipped.

// Default shape has no candidate list: measured on a real station, the list-less
// form makes it scan and move to any same-SSID BSS in range (firmware/测试报告
// §4.4.12), while a list pointing at a phantom BSSID only earns a BTM Response.
//
// `cand_bssid != NULL` adds one Neighbor Report element naming that BSSID, which is
// the "go exactly there" form. `cand_channel` must be its real channel (the caller
// normally looks it up in the scan results); `cand_info` is written verbatim into
// the BSSID Information word -- this module does not claim to know what its bits
// mean, 0 is the safe default.
// `disassoc_timer` is in TBTT and must be non-zero (0 is silently raised to 10).
bool btm_start(int index, uint16_t disassoc_timer, const uint8_t *cand_bssid,
               uint8_t cand_channel, uint32_t cand_info);

// Registers a station explicitly (capability unknown), so a request goes out even
// before that station has shown any 11v traffic -- needed when the victim is known
// by MAC (a bench STA, or a capture-verification run on a quiet BSS).
void btm_add_station(const uint8_t mac[6]);

void btm_stop(void);

// Called from the main loop (via attack_step).
void btm_step(void);

// Called by the promiscuous sniffer for every received frame.
void btm_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps the exact bytes of the BTM Request with decoded fields (format check).
void btm_selftest(void);

bool btm_active(void);
const char* btm_state_name(void);   // "on" / "off"
uint32_t btm_frames(void);
// Clients known to advertise 802.11v BTM / clients skipped because they do not.
uint32_t btm_capable_clients(void);
uint32_t btm_skipped_clients(void);
// BTM Responses received from the clients, and the last status code in them.
uint32_t btm_responses(void);
// BTM Queries: a client asking the "AP" for candidates, i.e. it took the bait.
uint32_t btm_queries(void);
uint16_t btm_last_status(void);
uint16_t btm_disassoc_timer(void);
// Current candidate (NULL when the list-less shape is in use).
const uint8_t *btm_candidate_bssid(void);
uint8_t btm_candidate_channel(void);
uint32_t btm_candidate_info(void);

#ifdef __cplusplus
}
#endif
