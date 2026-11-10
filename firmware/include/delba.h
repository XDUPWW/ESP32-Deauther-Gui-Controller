#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// DELBA (Block Ack session teardown) spoofing, 802.11-2020 / 802.11e.
//
// A Block Ack session is negotiated per TID with ADDBA Request/Response and torn
// down with a DELBA action frame (category 3 = Block Ack, action 2). DELBA is not
// a robust management frame, so 802.11w (PMF) does not authenticate it: a forged
// frame whose transmitter address is the AP's BSSID is accepted by any peer that
// still has a session for that TID.
//
// Losing the session removes A-MPDU aggregation, so the link falls back to
// per-frame acknowledgement: throughput collapses while the client stays
// associated. Nothing is deauthenticated, so deauth-oriented WIDS see nothing.
//
// Blind DELBA is useless (a peer without a session ignores it), so the attack is
// driven by the sniffer: every ADDBA Request/Response seen on the target BSS is
// answered with a DELBA for exactly that (client, TID). A periodic sweep over the
// TIDs the client was seen using (or 0..7 when nothing was announced yet) keeps
// the session torn down when the client retries.

// `reason`: 802.11 reason code put in the DELBA frame. Only the codes a real
// peer uses are accepted (1 / 32 / 37 / 38 / 39); 0 selects the default (37,
// "requested from peer STA as it does not want to use the mechanism").
bool delba_start(int index, uint16_t reason);

void delba_stop(void);

// Called from the main loop (via attack_step) every iteration.
void delba_step(void);

// Called by the promiscuous sniffer: learns clients/TIDs and queues a DELBA
// immediately after an ADDBA frame of the target BSS.
void delba_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps one DELBA frame as bytes and decoded fields (format check).
void delba_selftest(void);

bool delba_active(void);
bool delba_reason_is_defined(uint16_t code);
uint32_t delba_frames(void);
uint32_t delba_clients(void);
// Bitmap of TIDs the clients of the target BSS are actually using, learned from
// QoS data frames, BlockAck/BlockAckReq control frames and ADDBA frames.
uint8_t delba_tid_mask(void);
uint32_t delba_addba_seen(void);
// BlockAck / BlockAckReq control frames whose TID was decoded.
uint32_t delba_bar_seen(void);
// DELBA frames sent right after an observed ADDBA (the precise path).
uint32_t delba_triggered(void);
// Group-addressed DELBA sent while no client MAC is known yet.
uint32_t delba_blind_frames(void);
// DELBA forged in the STA -> AP direction (client "tearing down" its own session).
uint32_t delba_reverse_frames(void);
uint32_t delba_sweeps(void);
uint8_t delba_channel(void);
uint16_t delba_reason(void);

#ifdef __cplusplus
}
#endif
