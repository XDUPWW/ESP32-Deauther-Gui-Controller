#pragma once

#include <stdint.h>

#include "deauth.h"

static constexpr uint16_t kHexMax = 512;
static constexpr int kHexSlots = 8;

struct hex_sample_t {
  uint16_t len;
  uint16_t stored_len;
  uint32_t ts;
  rx_radio_t radio;
  uint8_t data[kHexMax];
};

struct hex_mix_t {
  uint32_t data;
  uint32_t tid[16];
  uint32_t htc;
  uint32_t control_id[16];
  uint32_t lengths[4];
};

void hex_capture_configure(int type, int subtype, int tid, bool tid_het, int htc,
                           const uint8_t* ta, const uint8_t* ra);
void hex_capture_stop(void);
bool hex_capture_active(void);
void hex_capture_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype,
                       const rx_radio_t* radio, uint32_t ts);
bool hex_capture_pop(hex_sample_t* out);
uint32_t hex_capture_hits(void);
uint32_t hex_capture_drops(void);
void hex_capture_mix(hex_mix_t* out);

