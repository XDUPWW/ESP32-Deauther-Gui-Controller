#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// SAE Commit flooding (WPA3-Personal DoS).
//
// SAE runs inside Authentication frames: algorithm 3, transaction sequence 1
// (Commit) or 2 (Confirm). A Commit carries a finite cyclic group, a scalar and
// a commit element; the authenticator has to parse and validate them against its
// elliptic curve, which is by far the most expensive thing it does per frame of
// any kind. Nothing about the frame is authenticated until the Confirm exchange,
// so a garbage Commit is indistinguishable from a real one until the work is
// already done.
//
// The standard's only defence is anti-clogging: the AP answers the first Commit
// with status 76 (ANTI_CLOGGING_TOKEN_REQUIRED) plus a token, and refuses to do
// the expensive work until the same station echoes that token back. That is a
// reflection test, not a defence against a flood -- so this module echoes it:
//   * a Commit is sent for a fresh identity (random MAC),
//   * a status 76 answer for that identity is parsed and its token stored,
//   * the next Commit for that identity carries the token in the same container
//     shape the AP used (raw after the group for non-H2E, extended element 93 for
//     H2E), which is the form that makes the AP do the work.
//
// The commit element is the NIST P-256 generator by default (a *valid* point, so
// the AP cannot short-circuit at point validation); `elem=rand` sends random
// bytes as an A/B control, and a cheaper AP answer there is the proof that point
// validation is what costs it.
//
// WPA3 is detected from the RSN IE (AKM 00-0F-AC:8/9/24) of the target's beacon;
// `sae_classify()` is also what the auth-flood module uses to decide whether to
// upgrade itself.

typedef enum {
    SAE_SEC_UNKNOWN = 0,
    SAE_SEC_PSK = 1,         // PSK AKM only -> WPA2, nothing SAE to flood
    SAE_SEC_SAE = 2,         // SAE only -> WPA3-Personal
    SAE_SEC_TRANSITION = 3,  // both PSK and SAE -> WPA2/WPA3 mixed mode
} sae_security_t;

typedef enum {
    SAE_ELEM_BASEPOINT = 0,  // P-256 generator: a valid curve point
    SAE_ELEM_RANDOM = 1,     // random bytes: control run for point validation
} sae_element_t;

// Classifies a beacon / probe response by its RSN element.
sae_security_t sae_classify(const uint8_t* frame, uint16_t len);
const char* sae_security_name(sae_security_t sec);

// `gap_ms`: minimum spacing between two injected Commits. 0 selects 50 ms, i.e. 20
// frames/s -- the rate measured to run for minutes without exhausting the driver's
// management pool (50 frames/s fills it after ~63 frames and the chip restarts).
bool sae_start(int index, sae_element_t element, uint32_t gap_ms);

void sae_stop(void);

// Called from the main loop (via attack_step).
void sae_step(void);

// Called by the promiscuous sniffer: learns the target's security and parses
// anti-clogging tokens addressed to our identities.
void sae_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps one Commit (no token) and one with a container token (format check).
void sae_selftest(void);

bool sae_active(void);
uint32_t sae_frames(void);
uint32_t sae_identities(void);
// Authentication frames the AP sent back to our identities, the last status code
// in them (76 = token required, 1 = unspecified failure, 0 = impossible here).
uint32_t sae_responses(void);
uint16_t sae_last_status(void);
// Anti-clogging tokens received / Commits resent with a token.
uint32_t sae_tokens(void);
uint32_t sae_echoed(void);
sae_security_t sae_security(void);
sae_element_t sae_element(void);
uint32_t sae_gap_ms(void);

#ifdef __cplusplus
}
#endif
