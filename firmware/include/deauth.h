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

// ---- passive monitor window (verify injections from a second board) ----
void monitor_begin(uint8_t channel, uint16_t seconds);
bool monitor_active(void);
uint32_t attack_rx_action(void);
uint32_t attack_rx_csa_action(void);
uint32_t attack_rx_csa_ie(void);
// Block Ack frames seen by this radio: ADDBA (category 3, action 0/1) and
// DELBA (category 3, action 2).
uint32_t attack_rx_addba(void);
uint32_t attack_rx_delba(void);

// ---- module driver table ----
//
// Every attack module is one row here instead of being named in three hand-written
// chains: the promiscuous fan-out, attack_step() and attack_stop(). The table order
// is the old call order, so registering in the same order changes nothing on air;
// adding a module is one row and no edit to deauth.cpp's hot paths.
//
// `step` runs from the main loop, `on_rx` runs inside the promiscuous callback (it
// must not block and must not print), `stop` is called by STOP and by every attack
// that needs the radio to itself.
typedef void (*attack_rx_sink_t)(const uint8_t* frame, uint16_t len, uint8_t type,
                                 uint8_t subtype);

typedef struct {
    const char* name;
    void (*step)(void);      // may be NULL
    void (*stop)(void);      // may be NULL
    attack_rx_sink_t on_rx;  // may be NULL
} attack_module_t;

bool attack_module_register(const attack_module_t* module);
int attack_module_count(void);
// Registers the nine frame-level modules in their historical order.
void attack_modules_register_defaults(void);

// Installs the promiscuous filter + receive callback (idempotent). Modules that
// only need to *listen* (CSA, DELBA) must call this before turning promiscuous
// mode on themselves: without the callback the radio receives nothing, which
// silently degrades them to their blind paths.
void attack_sniffer_enable(void);
// Decoded CSA action frames seen by this radio (for RXLOG).
int attack_csa_log_count(void);
bool attack_csa_log_at(int i, uint8_t src[6], uint8_t* nch, uint8_t* cnt, uint8_t* cat,
                       uint8_t* act, uint16_t* len);

// Advanced by the main loop: multi-AP channel hopping, probe pacing, station scan.
void attack_step(void);

attack_mode_t attack_get_mode(void);
const char* attack_mode_name(void);

uint32_t attack_deauth_frames(void);
uint32_t attack_rx_frames(void);
// Raw injection accounting: ESP_OK vs rejected by the driver.
uint32_t attack_tx_ok(void);
uint32_t attack_tx_err(void);
int attack_tx_last_err(void);
uint32_t attack_tx_err_nomem(void);
uint32_t attack_tx_err_invalid(void);
uint32_t attack_tx_err_other(void);
uint32_t attack_tx_dropped(void);
// Broadcast deauth frames sent without any sniffed client (blind fallback).
uint32_t attack_blind_frames(void);
// Deauth frames forged in the STA -> AP direction (client "leaving").
uint32_t attack_reverse_frames(void);

// ---- reason code ----
// Fixed code, or "random": every burst draws a fresh value from the codes the
// standard defines. 0 is reserved and is normalised to 1.
void attack_set_reason(uint16_t code);
void attack_set_reason_random(void);
bool attack_reason_is_random(void);
uint16_t attack_reason_last(void);
bool attack_reason_is_defined(uint16_t code);
// Received frame mix: management subtypes 0..15 (deauth = 12), control and data.
void attack_rx_mix(uint32_t mgmt_sub[16], uint32_t* ctrl, uint32_t* data);
// Control subtypes (BAR=8, BA=9, PS-Poll=10, RTS=11, CTS=12, ACK=13, ...).
void attack_rx_ctrl_mix(uint32_t sub[16]);
uint32_t attack_rx_matches(void);
int attack_rx_log_count(void);
bool attack_rx_log_at(int i, uint8_t dest[6], uint8_t src[6], uint8_t bssid[6],
                      uint8_t* type, uint8_t* subtype, uint16_t* len);
// Extra detail decoded for the log sample: action category/action, CSA channel/count.
void attack_rx_log_info(int i, uint8_t* cat, uint8_t* act, uint8_t* nch, uint8_t* cnt);
// Radio metadata that came up with the frame. The driver reports a different
// set on the two targets, so `fmt` decides how `rate`/`mcs` must be read.
struct rx_radio_t {
  int16_t rssi;
  uint8_t channel;
  uint16_t duration;  // Duration/ID, straight from the MAC header
  uint8_t fmt;        // 0 = 11b, 1 = 11g/a, 2 = HT, 3 = VHT, 4..7 = HE
  uint8_t rate;       // raw driver code (see rx_rate_text)
  uint8_t mcs;
  uint8_t sgi;
  uint8_t sig_mode;
  uint8_t cwb;
  uint8_t raw_fields_valid;
};
bool attack_rx_radio_last(rx_radio_t* out);
bool attack_rx_log_radio(int i, rx_radio_t* out);
// Formats the rate for a log line: "54M", "1M", "mcs7/sgi" or "-" when the
// driver value cannot be trusted. buf must hold at least 12 bytes.
const char* rx_rate_text(uint8_t fmt, uint8_t rate, uint8_t mcs, uint8_t sgi, char* buf,
                         int buf_len);
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
