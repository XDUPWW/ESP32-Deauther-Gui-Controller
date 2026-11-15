#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Power-management (PM bit) spoofing, in three interchangeable frame shapes.
//
// The Power Management bit is bit 12 of the Frame Control field, i.e. 0x10 in its
// second octet. A station sets it to say "I am going to sleep, buffer my downlink";
// the AP then stops delivering to that station and marks it in the TIM. Forging
// that frame with the victim's transmitter address puts the AP's idea of the
// station's power state under our control -- the real station never notices,
// because nothing is sent to it.
//
// Three frame shapes carry the same bit, and real stacks do not agree on which one
// they honour, so all three are selectable:
//
//   * `null`    -- Null Data (data subtype 4). The canonical PS transition frame
//                  (mac80211: ieee80211_nullfunc_get()). No payload, no LLC/SNAP.
//   * `qosnull` -- QoS Null (data subtype 12) with a 2-byte QoS Control. This is
//                  what a QoS/WMM association uses for the same purpose; an AP that
//                  only tracks QoS stations may ignore the plain form.
//   * `action`  -- unicast Action frame (management subtype 13) with vendor-specific
//                  category 127. Management frames carry the PM bit too, and
//                  category 127 is one of the few Action categories that is NOT a
//                  robust management frame -- so this shape keeps the PMF bypass
//                  that the whole module relies on, while looking like ordinary
//                  management traffic to the AP.
//
// Each shape is sent with PM=1, and every sixth frame with PM=0 instead: PM=0 tells
// the AP "I am awake, send what you have", i.e. it releases the buffered frames
// towards a station that is not there. That flap turns "delayed" into "lost", and
// `PSPOLLREL` sends the PM=0 form once per victim as an undo.
//
// Why this survives 802.11w: PMF protects (robust) management frames. The PM bit of
// a data frame and a vendor-specific Action frame are outside that set, so a
// PMF-required WPA3 BSS -- where a forged deauth or BTM is dropped by the client's
// driver -- still acts on these frames.
//
// What it cannot do: the AP ages buffered frames out and drops them after the retry
// limit, and every real uplink frame from the victim carries PM=0 and puts the AP
// back into "awake". The effect is degraded/delayed downlink traffic, not a
// permanent block; the association stays up (测试报告 §4.4.9/§4.4.10).
//
// The PS-Poll half of this idea (forging control subtype 10 to make the AP hand a
// buffered frame to a station that is not listening) was implemented, measured and
// removed: with a unicast receiver address the MAC does not transmit the frame at
// all (0/10 on the air, while the same 16-byte frame with a broadcast RA is captured
// 10/10 with Duration/ID = 0xC000|AID intact). See 附录 A of attack-principles.md.
//
// Pacing: every shape is unicast (the AP acknowledges it), so frames are paced at
// 10 frames/s -- 20 frames/s exhausted the 32-buffer short-frame pool after a few
// hundred frames and restarted the chip.

typedef enum {
    PSPOLL_MODE_OFF = 0,
    PSPOLL_MODE_PM = 1,  // forged PM=1 frames, periodic PM=0 release
} pspoll_mode_t;

typedef enum {
    PSPOLL_FRAME_NULL = 0,     // data subtype 4  (Null Data)
    PSPOLL_FRAME_QOSNULL = 1,  // data subtype 12 (QoS Null, QoS Control 2B)
    PSPOLL_FRAME_ACTION = 2,   // mgmt subtype 13 (Action, category 127)
} pspoll_frame_t;

bool pspoll_start(int index, pspoll_frame_t frame);

// Registers a station explicitly, so the flood starts even before that station has
// been seen sending anything (bench STA / capture-verification run).
void pspoll_add_station(const uint8_t mac[6]);

void pspoll_stop(void);

// Sends one PM=0 frame (same shape as the attack) per known victim and stops: the
// AP then flushes the frames it has been holding back towards a station that is not
// listening.
void pspoll_release(void);

// Called from the main loop (via attack_step).
void pspoll_step(void);

// Called by the promiscuous sniffer for every received frame.
void pspoll_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps all three shapes (PM=1 and PM=0) with decoded fields (format check).
void pspoll_selftest(void);

bool pspoll_active(void);
const char* pspoll_mode_name(void);
const char* pspoll_frame_name(void);
uint32_t pspoll_frames(void);
uint32_t pspoll_null_frames(void);  // every PM=1 frame (any shape)
// Frames sent with PM=0: the "release" half of the flap.
uint32_t pspoll_flush_frames(void);
uint32_t pspoll_clients(void);
// Downlink data frames seen on the air towards a known victim: the AP is still
// transmitting to it, i.e. the forged PM state did not take (or did not hold).
uint32_t pspoll_dl_frames(void);
// PS-Poll frames heard from real stations of the BSS. Reference behaviour: an
// ESP-IDF station in WIFI_PS_MIN_MODEM never sends one (it wakes per DTIM).
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
