#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 802.11v BSS Transition Management (BTM) Request spoofing.
//
// The AP tells a client "move to another BSS, and by the way you have N TBTTs
// before I disassociate you" with a WNM Action frame (category 10, action 7).
// A forged frame whose TA is the AP's BSSID is accepted and acted on like a
// deauth, only "legally" and without any obvious disconnection.
// PMF: category 10 is inside the robust set (all action categories except
// Public/HT/Unprotected-WNM/Self-protected/VHT/vendor), so a client that
// negotiated PMF drops an unprotected BTM Request in its driver
// (net/mac80211/rx.c) before any WNM code runs. Against PMF-less networks the
// forged TA = AP BSSID is enough.
//
// What the client does with it (from wpa_supplicant's wnm_sta.c, which is the
// reference behaviour):
//   * Disassociation Imminent set + a *non-zero* Disassociation Timer
//     -> "Trying to find another BSS" + an immediate scan. A timer of 0 means
//        the client has no deadline and does not scan, which is why this module
//        defaults to a non-zero timer.
//   * Preferred Candidate List Included set -> the client scans for the listed
//        candidates only (wpa_supplicant narrows the scan to that single BSSID
//        when the list has one entry), then either roams or answers with a
//        reject status. Either way it leaves the channel.
//   * No candidate list -> the client answers BTM Response with status 1
//        (reject, unspecified) but still scans because of the timer.
//
// Only clients that advertise the BSS Transition bit (Extended Capabilities,
// bit 19) act on it, so the sniffer learns that bit from the client's probe /
// (re)association request and clients that say "no" are skipped.

typedef enum {
    WNM_MODE_OFF = 0,
    WNM_MODE_CAND = 1,  // preferred candidate list included (one phantom BSS)
    WNM_MODE_BARE = 2,  // no candidate list, disassociation timer only
} wnm_mode_t;

// `candidate_channel`: where the phantom candidate is announced. 0 = pick a
// random 2.4 GHz channel other than the AP's (same band, so any client can
// actually try to scan for it).
bool wnm_start(int index, wnm_mode_t mode, uint16_t disassoc_timer, uint8_t candidate_channel);

// Registers a station explicitly (capability unknown), so a request goes out even
// before that station has shown any 11v traffic -- needed when the victim is known
// by MAC (a bench STA, or a capture-verification run on a quiet BSS).
void wnm_add_station(const uint8_t mac[6]);

void wnm_stop(void);

// Called from the main loop (via attack_step).
void wnm_step(void);

// Called by the promiscuous sniffer for every received frame.
void wnm_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps the exact bytes of the BTM Request with decoded fields (format check).
void wnm_selftest(void);

bool wnm_active(void);
const char* wnm_mode_name(void);
uint32_t wnm_frames(void);
// Clients known to advertise 802.11v BTM / clients skipped because they do not.
uint32_t wnm_capable_clients(void);
uint32_t wnm_skipped_clients(void);
// BTM Responses received from the clients, and the last status code in them.
uint32_t wnm_responses(void);
// BTM Queries: a client asking the "AP" for candidates, i.e. it took the bait.
uint32_t wnm_queries(void);
uint16_t wnm_last_status(void);
uint8_t wnm_candidate_channel(void);
uint16_t wnm_disassoc_timer(void);

#ifdef __cplusplus
}
#endif
