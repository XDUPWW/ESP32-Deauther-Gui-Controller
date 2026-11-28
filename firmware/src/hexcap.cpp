#include "hexcap.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

namespace {

struct filter_t {
  int type;
  int subtype;
  int tid;
  bool tid_het;
  int htc;
  bool have_ta;
  bool have_ra;
  uint8_t ta[6];
  uint8_t ra[6];
};

hex_sample_t s_slots[kHexSlots];
filter_t s_filter = {-1, -1, -1, false, -1, false, false, {0}, {0}};
portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
volatile bool s_active = false;
uint32_t s_hits = 0;
uint32_t s_drops = 0;
hex_mix_t s_mix = {};
int s_head = 0;
int s_count = 0;

IRAM_ATTR bool matches(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype,
                       const filter_t& filter) {
  if (filter.type >= 0 && type != filter.type) return false;
  if (filter.subtype >= 0 && subtype != filter.subtype) return false;
  if (filter.htc >= 0) {
    if (type != 2 || subtype < 8 || len < 26) return false;
    const unsigned qos_offset = (frame[1] & 3) == 3 ? 30 : 24;
    if (len < qos_offset + 2) return false;
    const bool has_htc = (frame[1] & 0x80) != 0;
    if (has_htc && len < qos_offset + 6) return false;
    if (has_htc != (filter.htc != 0)) return false;
  }
  if (filter.tid >= 0 || filter.tid_het) {
    if (type != 2 || subtype < 8 || len < 26) return false;
    const unsigned qos_offset = (frame[1] & 3) == 3 ? 30 : 24;
    if (len < qos_offset + 2) return false;
    const uint8_t tid = frame[qos_offset] & 0x0F;
    if (filter.tid_het ? tid < 8 : tid != filter.tid) return false;
  }
  if ((filter.have_ra || filter.have_ta) && len < 16) return false;
  if (filter.have_ra && memcmp(frame + 4, filter.ra, 6) != 0) return false;
  if (filter.have_ta && memcmp(frame + 10, filter.ta, 6) != 0) return false;
  return true;
}

}  // namespace

void hex_capture_configure(int type, int subtype, int tid, bool tid_het, int htc,
                           const uint8_t* ta, const uint8_t* ra) {
  portENTER_CRITICAL(&s_mux);
  s_filter.type = type;
  s_filter.subtype = subtype;
  s_filter.tid = tid;
  s_filter.tid_het = tid_het;
  s_filter.htc = htc;
  s_filter.have_ta = ta != nullptr;
  s_filter.have_ra = ra != nullptr;
  if (ta != nullptr) memcpy(s_filter.ta, ta, 6);
  if (ra != nullptr) memcpy(s_filter.ra, ra, 6);
  s_head = 0;
  s_count = 0;
  s_hits = 0;
  s_drops = 0;
  memset(&s_mix, 0, sizeof(s_mix));
  s_active = true;
  portEXIT_CRITICAL(&s_mux);
}

void hex_capture_stop(void) {
  portENTER_CRITICAL(&s_mux);
  s_active = false;
  s_head = 0;
  s_count = 0;
  portEXIT_CRITICAL(&s_mux);
}

bool hex_capture_active(void) { return s_active; }

IRAM_ATTR void hex_capture_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype,
                                 const rx_radio_t* radio, uint32_t ts) {
  if (!s_active || frame == nullptr || radio == nullptr) return;
  const uint16_t stored_len = len > kHexMax ? kHexMax : len;

  portENTER_CRITICAL(&s_mux);
  filter_t mix_filter = s_filter;
  mix_filter.tid = -1;
  mix_filter.tid_het = false;
  mix_filter.htc = -1;
  if (s_active && type == 2 && matches(frame, stored_len, type, subtype, mix_filter)) {
    s_mix.data++;
    s_mix.lengths[len < 64 ? 0 : len < 256 ? 1 : len < 512 ? 2 : 3]++;
    const unsigned qos_offset = stored_len >= 2 && (frame[1] & 3) == 3 ? 30 : 24;
    if (subtype >= 8 && stored_len >= qos_offset + 2) {
      s_mix.tid[frame[qos_offset] & 15]++;
      if ((frame[1] & 0x80) && stored_len >= qos_offset + 6) {
        s_mix.htc++;
        const uint8_t control = frame[qos_offset + 2];
        if ((control & 3) == 3) s_mix.control_id[(control >> 2) & 15]++;
      }
    }
  }
  if (!s_active || !matches(frame, stored_len, type, subtype, s_filter)) {
    portEXIT_CRITICAL(&s_mux);
    return;
  }
  s_hits++;
  if (s_count >= kHexSlots) {
    s_drops++;
    portEXIT_CRITICAL(&s_mux);
    return;
  }
  const int tail = (s_head + s_count) % kHexSlots;
  hex_sample_t* sample = &s_slots[tail];
  sample->len = len;
  sample->stored_len = stored_len;
  sample->ts = ts;
  sample->radio = *radio;
  memcpy(sample->data, frame, stored_len);
  s_count++;
  portEXIT_CRITICAL(&s_mux);
}

bool hex_capture_pop(hex_sample_t* out) {
  if (out == nullptr) return false;
  portENTER_CRITICAL(&s_mux);
  if (s_count == 0) {
    portEXIT_CRITICAL(&s_mux);
    return false;
  }
  *out = s_slots[s_head];
  s_head = (s_head + 1) % kHexSlots;
  s_count--;
  portEXIT_CRITICAL(&s_mux);
  return true;
}

uint32_t hex_capture_hits(void) {
  portENTER_CRITICAL(&s_mux);
  const uint32_t hits = s_hits;
  portEXIT_CRITICAL(&s_mux);
  return hits;
}

uint32_t hex_capture_drops(void) {
  portENTER_CRITICAL(&s_mux);
  const uint32_t drops = s_drops;
  portEXIT_CRITICAL(&s_mux);
  return drops;
}

void hex_capture_mix(hex_mix_t* out) {
  if (out == nullptr) return;
  portENTER_CRITICAL(&s_mux);
  *out = s_mix;
  portEXIT_CRITICAL(&s_mux);
}
