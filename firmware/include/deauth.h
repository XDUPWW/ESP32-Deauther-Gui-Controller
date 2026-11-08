#ifndef DEAUTH_H
#define DEAUTH_H

#include <Arduino.h>
#include <stdint.h>

// Attack matrix:
//   deauth  : single AP / all scanned APs / only some APs / all but some APs
//   probe   : broadcast probe-request flood / targeted probe-response flood
typedef enum {
    ATTACK_IDLE = 0,
    ATTACK_DEAUTH_SINGLE,
    ATTACK_DEAUTH_MULTI,
    ATTACK_PROBE_BROADCAST,
} attack_mode_t;

#define MAX_AP_TARGETS 64
#define MAX_STA_TARGETS 32

// Radio preset (country + band mode) used before scanning.
void prepare_radio_for_scan();
// Kept for compatibility with the 5 GHz channel sweep helper.
uint8_t sweep_next_channel();

// ---- deauth ----
bool attack_deauth_single(int index, uint16_t reason);
bool attack_deauth_all(uint16_t reason);
bool attack_deauth_only(const int* idx, int count, uint16_t reason);
bool attack_deauth_except(const int* idx, int count, uint16_t reason);

// ---- probe ----
bool attack_probe_broadcast(void);

void attack_stop(void);

// Advanced by the main loop: multi-AP channel hopping, probe pacing, station scan.
void attack_step(void);

attack_mode_t attack_get_mode(void);
const char* attack_mode_name(void);

uint32_t attack_deauth_frames(void);
uint32_t attack_rx_frames(void);
uint32_t attack_rx_matches(void);
int attack_rx_log_count(void);
bool attack_rx_log_at(int i, uint8_t dest[6], uint8_t src[6], uint8_t bssid[6],
                      uint8_t* type, uint8_t* subtype, uint16_t* len);
uint32_t attack_probe_frames(void);

int attack_ap_count(void);
int attack_ap_enabled_count(void);
bool attack_ap_info(int i, const uint8_t** bssid, uint32_t* frames, uint8_t* channel);
int attack_ap_mac_count(void);  // reuses the single-target path for legacy DEAUTH

// ---- station discovery (to pick a probe target) ----
void stations_begin(uint16_t seconds);
bool stations_poll(void);  // true when the snapshot is ready (printed already)
int stations_count(void);
bool stations_info(int i, const uint8_t** mac, const uint8_t** ap, uint8_t* channel,
                   int16_t* rssi, uint32_t* frames);

extern int eliminated_stations;
extern bool deauth_active;

#endif
