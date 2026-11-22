#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Bait BSS for BTM / RRM steering.
//
// A BTM Request is only a suggestion: the station roams to a BSS it already has
// credentials for, so a forged request with no reachable twin does nothing. This
// runs a SoftAP with the target's SSID and passphrase on the target's channel, so
// the "candidate" the station ends up on is actually this board.
//
// APSTA is mandatory: WIFI_IF_STA must stay alive because every injector calls
// esp_wifi_80211_tx(WIFI_IF_STA, ...). Pure AP mode would silently break them.
// While the AP is up the channel is pinned -- moving the radio kills the
// association we just earned, so SCAN and channel-hopping attacks are refused.
bool baitap_start(const char* ssid, const char* pass, uint8_t channel, uint8_t max_conn);

void baitap_stop(void);

bool baitap_running(void);
uint8_t baitap_channel(void);
const char* baitap_ssid(void);

// BSSID the AP actually answers on. This is the candidate a BTM/RRM frame has to
// name, so the console has to be able to print it.
void baitap_bssid(uint8_t out[6]);

uint8_t baitap_clients(void);   // currently associated
uint32_t baitap_joins(void);    // cumulative WIFI_EVENT_AP_STACONNECTED
uint32_t baitap_leaves(void);   // cumulative WIFI_EVENT_AP_STADISCONNECTED

// Heap used by bringing the AP up (0 when it has never run). Static netif memory
// is not returned to the heap on stop, so this is the real budget cost.
int32_t baitap_heap_cost(void);

#ifdef __cplusplus
}
#endif
