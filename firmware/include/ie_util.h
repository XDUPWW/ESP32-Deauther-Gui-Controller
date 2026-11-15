#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Minimal 802.11 element helpers shared by the WNM / TIM-TSF / SAE / auth-flood
// modules. Every call takes a (start, end) pair, so a truncated frame can never
// walk off the receive buffer -- these helpers run inside the promiscuous
// callback and a bad length there means a crash, not an exception.

// First instance of element `id`, or nullptr. `out_len` receives the body length.
const uint8_t* ie_find(const uint8_t* start, const uint8_t* end, uint8_t id, uint16_t* out_len);

// RSN element (id 48) probes.
//   AKM suite 00-0F-AC:8  = SAE (WPA3-Personal)
//   AKM suite 00-0F-AC:2  = PSK, :4 = FT-PSK, :6 = PSK-SHA256
bool rsn_has_akm_sae(const uint8_t* rsn, uint16_t len);
bool rsn_has_akm_psk(const uint8_t* rsn, uint16_t len);
// RSN Capabilities bit 6 = Management Frame Protection Required.
bool rsn_mfpr_required(const uint8_t* rsn, uint16_t len);

// Extended Capabilities element (id 127), bit 19 = BSS Transition.
bool extcap_has_bss_transition(const uint8_t* extcap, uint16_t len);

#ifdef __cplusplus
}
#endif
