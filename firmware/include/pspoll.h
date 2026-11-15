#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 802.11 power-management (PS bit) spoofing.
//
// The Power Management bit is bit 12 of the Frame Control field, i.e. 0x10 in its
// second octet. A station sets it in a Null Data frame to say "I am going to sleep,
// buffer my downlink"; the AP then stops delivering to that station and marks it in
// the TIM. Forging that frame with the victim's transmitter address puts the AP's
// idea of the station's power state under our control -- the real station never
// notices, because nothing is sent to it.
//
// Every sixth Null Data goes out with PM=0 instead: that makes the AP *release*
// whatever it has been holding, towards a station that is not there. Flapping is
// what turns "delayed" into "lost"; a steady PM=1 only delays.
//
// Why this survives 802.11w: PMF protects (robust) management frames. The PM bit of
// a data frame is outside that set, so a PMF-required WPA3 BSS -- where a forged
// deauth or BTM is dropped by the client's driver -- still acts on this frame.
//
// What it cannot do: the AP ages buffered frames out and drops them after the retry
// limit, so the damage is degraded/delayed downlink traffic, not a permanent block,
// and the association stays up. Measured against an active station the effect is
// partial: every real uplink frame from the victim carries PM=0 and puts the AP back
// into "awake", so the forged state is fought over (测试报告 §4.4.9).
//
// The PS-Poll half of this idea (forging control subtype 10 to make the AP hand a
// buffered frame to a station that is not listening) was implemented, measured and
// removed: with a unicast receiver address the MAC does not transmit the frame at
// all (0/10 on the air, while the same 16-byte frame with a broadcast RA is captured
// 10/10 with Duration/ID = 0xC000|AID intact). See 附录 A of attack-principles.md.
//
// Pacing: Null Data is unicast (the AP acknowledges it), so it is paced at 10
// frames/s -- the 20 frames/s used by the management-frame modules exhausted the
// 32-buffer short-frame pool after a few hundred frames and restarted the chip.

typedef enum {
    PSPOLL_MODE_OFF = 0,
    PSPOLL_MODE_PM = 1,  // forged PM=1 Null Data, periodic PM=0 release
} pspoll_mode_t;

bool pspoll_start(int index);

// Registers a station explicitly, so the flood starts even before that station has
// been seen sending anything (bench STA / capture-verification run).
void pspoll_add_station(const uint8_t mac[6]);

void pspoll_stop(void);

// Sends one PM=0 Null Data per known victim and stops: the AP then flushes the
// frames it has been holding back towards a station that is not listening.
void pspoll_release(void);

// Called from the main loop (via attack_step).
void pspoll_step(void);

// Called by the promiscuous sniffer for every received frame.
void pspoll_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps both frame shapes (PM=1 and PM=0) with decoded fields (format check).
void pspoll_selftest(void);

bool pspoll_active(void);
const char* pspoll_mode_name(void);
uint32_t pspoll_frames(void);
uint32_t pspoll_null_frames(void);
// Null Data frames sent with PM=0: the "release" half of the flap.
uint32_t pspoll_flush_frames(void);
uint32_t pspoll_clients(void);
// Downlink data frames seen on the air towards a known victim: the AP is still
// transmitting to it, i.e. the forged PM state did not take (or did not hold).
uint32_t pspoll_dl_frames(void);
// PS-Poll frames heard from real stations of the BSS. Reference behaviour: an
// ESP-IDF station in WIFI_PS_MIN_MODEM never sends one (it wakes per DTIM), which is
// why a forged PS-Poll would have had nothing to imitate anyway.
uint32_t pspoll_rx_polls(void);
// Null Data frames heard from stations, and how many of them had PM=1.
uint32_t pspoll_rx_nulls(void);
uint32_t pspoll_rx_pm1(void);
// esp_wifi_set_channel() verdict from pspoll_start(): non-zero means the frames go
// out on the channel the radio happened to be on (typically right after a SCAN).
int32_t pspoll_channel_err(void);

#ifdef __cplusplus
}
#endif
