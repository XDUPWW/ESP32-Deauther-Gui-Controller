#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// EAPOL-Start / EAPOL-Logoff flooding on behalf of a victim station.
//
// EAPOL lives in a ToDS data frame: LLC/SNAP (AA AA 03 00 00 00 88 8E) followed
// by version, packet type and length. EAPOL-Start (1) makes the authenticator
// restart 802.1X for that station, EAPOL-Logoff (2) puts its controlled port back
// into the unauthorised state. Both frames carry nothing that could be verified
// without the PMK, and their only "identity" is the transmitter address -- which
// a raw injection can set to any MAC it likes.
//
// Alternating the two at 100 ms per victim keeps the port flapping between
// authorised and unauthorised: the station re-authenticates, the authenticator
// tears the port down again. Under WPA2/WPA3-PSK the effect depends entirely on
// the AP implementation (some restart the 4-way handshake, some ignore EAPOL in
// PSK mode), which is exactly what the counters measure:
//   * `eaprxreq` -- EAPOL-Packet (type 0) frames the AP sends towards a victim.
//     WPA-Enterprise answers EAPOL-Start with EAP-Request/Identity; seeing them
//     means the 802.1X state machine really restarted.
//   * `eaprxsta` -- EAPOL frames the *real* station sends after our Logoff, i.e.
//     it noticed and re-authenticated.
// Frames are sent both as plain data (subtype 0) and as QoS data (subtype 8, TID
// 6 as wpa_supplicant uses for EAPOL) because drivers differ in what they accept
// from an unknown station.

bool eapol_start(int index, int8_t qos_tid);

// Registers a station explicitly, so the flood starts even before that station
// has been seen sending anything (bench STA / capture-verification run).
void eapol_add_station(const uint8_t mac[6]);

void eapol_stop(void);

// Called from the main loop (via attack_step).
void eapol_step(void);

// Called by the promiscuous sniffer for every received frame.
void eapol_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// Dumps both frame shapes (plain + QoS) with decoded fields (format check).
void eapol_selftest(void);

bool eapol_active(void);
uint32_t eapol_frames(void);
uint32_t eapol_clients(void);
uint32_t eapol_start_frames(void);
uint32_t eapol_logoff_frames(void);
// EAPOL frames received from the AP / the ones that are EAP packets (type 0).
uint32_t eapol_rx_from_ap(void);
uint32_t eapol_rx_eap_packets(void);
// EAPOL frames received from a station (the victim re-authenticating).
uint32_t eapol_rx_from_sta(void);
int8_t eapol_qos_tid(void);

#ifdef __cplusplus
}
#endif
