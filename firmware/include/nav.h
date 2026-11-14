#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Virtual carrier sense (NAV) attacks. 802.11 NAV is "I heard Duration=X, so I
// keep quiet for X microseconds", and the Duration field of RTS/CTS/data frames
// is used without any authentication -- control frames are not in the 802.11w
// (PMF) protected set, so WPA3 changes nothing here.
//
// Four ways to weaponise it:
//   CTS   -- broadcast CTS-to-self with the largest legal duration (32767 us) and
//            refresh before it expires. Cheap: ~100 us of airtime every ~16 ms.
//   RTS   -- send RTS to the *AP* with a huge duration. The AP must answer with
//            a CTS that carries the same duration, and that CTS is a perfectly
//            valid control frame for every neighbour: the victim rebroadcasts our
//            NAV into areas our own signal never reaches ("reflection").
//   CFEND -- the opposite: a forged CF-End resets everyone's NAV, so nodes that
//            were politely waiting inside someone else's TXOP all transmit at
//            once. The reservation turns into a directed collision.
//   HYBRID-- pin the NAV, then periodically fire CF-End so the frozen nodes
//            unfreeze together, collide, and back off -- while we keep sending.
typedef enum {
    NAV_MODE_CTS = 0,
    NAV_MODE_RTS,     // RTS with a random RA: pure NAV pin, no reflection
    NAV_MODE_RTSAP,   // RTS addressed to the AP: its CTS rebroadcasts our NAV
    NAV_MODE_MGMT,    // NAV via the Duration field of a management frame
    NAV_MODE_CFEND,
    NAV_MODE_HYBRID,
} nav_mode_t;

// `duration_micros`: NAV value, 1..32767 (0 = default 32767 = the maximum the
// 16-bit Duration field can express without turning into an AID).
bool nav_start(int index, nav_mode_t mode, uint16_t duration_micros);
void nav_stop(void);
void nav_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);
void nav_selftest(void);
// Send one CTS / RTS / CF-End and print the driver's verdict for each (debug).
void nav_tx_probe(void);
// Frames the driver refused.
uint32_t nav_tx_errors(void);

bool nav_active(void);
const char* nav_mode_name(void);
uint32_t nav_frames(void);
uint32_t nav_cfend_frames(void);
// CTS frames heard on the channel while the attack runs: the AP's answer to our
// forged RTS, i.e. proof that the reflection path works.
uint32_t nav_cts_heard(void);
uint32_t nav_rts_heard(void);
uint16_t nav_duration(void);
uint8_t nav_channel(void);

#ifdef __cplusplus
}
#endif
