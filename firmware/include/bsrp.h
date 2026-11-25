#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// HE BSRP Trigger injection (control subtype 2, Trigger Type 4). This only
// proves the frame bytes; it says nothing about a station answering or about
// throughput/battery effects. BSRPTEST marks the schedule fields that still
// need a real BSRP capture.
//
// count = 0 runs until BSRPSTOP. rate_ms below 45 is raised to the unicast
// guard. With sta == NULL the RA is learned from an association response or a
// real BSRP with this AID and AP BSSID.
bool bsrp_start(int index, uint16_t aid, uint8_t channel, uint32_t rate_ms, uint32_t count,
                const uint8_t sta[6]);

void bsrp_stop(void);
void bsrp_step(void);
void bsrp_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);
void bsrp_selftest(void);

bool bsrp_active(void);
uint32_t bsrp_frames(void);
uint32_t bsrp_remaining(void);
uint32_t bsrp_tx_errors(void);
uint32_t bsrp_reference_triggers(void);
uint16_t bsrp_aid(void);
uint8_t bsrp_channel(void);
uint32_t bsrp_rate_ms(void);
uint16_t bsrp_ul_length(void);
uint8_t bsrp_gi_ltf(void);
uint8_t bsrp_ap_tx_power(void);
uint8_t bsrp_ru_allocation(void);
uint8_t bsrp_mcs(void);
uint8_t bsrp_target_rssi(void);

// Runtime override of the schedule fields, for narrowing down why a station
// refuses to answer. "ul" 0..4095, "gi" 0..3, "atp" 0..63, "ru" 0..255,
// "rssi" 0..127, "mcs" 0..15. Returns false on an unknown name or a value out
// of that field's width.
bool bsrp_set_field(const char* name, long value);

#ifdef __cplusplus
}
#endif
