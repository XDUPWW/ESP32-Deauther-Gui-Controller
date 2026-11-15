#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// TIM poisoning through a cloned beacon.
//
// A client's power save is driven by the TIM element (id 5) of the beacon it
// hears: DTIM count/period plus a partial virtual bitmap that marks which AIDs
// have buffered traffic. Setting a victim's AID bit makes every station wake up
// and poll for frames that do not exist; clearing the bitmap makes a sleeping
// station miss the downlink it actually has queued. The beacon is unprotected
// even with PMF enabled -- the clone only has to out-pace the real AP (a 100 TU
// beacon repeated every 20 ms) to be the one the station believes.
//
// The AID of a victim is not in any beacon: it is in the Association Response
// the AP sent when the station joined, so the sniffer learns (MAC, AID) pairs
// from those frames while the attack is running. The bitmap is indexed by AID
// (bit 0 of byte 0 is AID 0, the group-addressed indication); `aid` below is the
// AID itself, 1 based.
//
// The 8 byte timestamp field of the clone is the one the MAC writes, not us: it
// is overwritten with the interface's own TSF (0 while the station interface is
// not associated), which is why a TSF-skew variant of this module was removed
// (测试报告 §4.4.3). Same class of field rewriting as Duration, see AGENTS §11.

typedef enum {
    TIM_OFF = 0,
    TIM_SET = 1,    // TIM claims buffered unicast for the victim AID(s)
    TIM_CLEAR = 2,  // TIM claims an empty buffer for everybody
} tim_mode_t;

// `aid`: 0 = every AID learned from Association Responses, 1..255 = that AID.
bool tim_start(int index, tim_mode_t mode, uint16_t aid);

void tim_stop(void);

// Called from the main loop (via attack_step): sends one clone beacon per tick.
void tim_step(void);

// Called by the promiscuous sniffer: learns the target's beacon parameters
// (SSID, RSN IE, DTIM period) and the AIDs from Association Responses.
void tim_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps the cloned beacon with the decoded TIM fields (format check).
void tim_selftest(void);

bool tim_active(void);
const char* tim_mode_name(void);
uint32_t tim_frames(void);
// Real beacons of the target seen by the sniffer; nothing is transmitted before
// the first one arrives, because a clone without them is a different network.
uint32_t tim_real_beacons(void);
// Bitmap of learned AIDs 1..32 (bit 0 = AID 1).
uint32_t tim_aid_mask(void);
uint32_t tim_clients(void);
uint16_t tim_aid(void);
uint8_t tim_dtim_period(void);
bool tim_have_target(void);

#ifdef __cplusplus
}
#endif
