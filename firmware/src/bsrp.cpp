// HE BSRP Trigger injection: 16 B header + 8 B Common Info + 5 B User Info +
// 3 B padding. BSRP has no extra BSR Control element. The driver appends FCS.

#include "bsrp.h"
#include "radio.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"
#include "tx_guard.h"

namespace {

const uint8_t kTriggerTypeBsrp = 4;
const uint8_t kTriggerTypeMuBar = 2;
const size_t kBsrpFrameLen = 32;
// Longest shape this builder can produce: 24 + 5 + 4 (MU-BAR) rounded up to 36.
const size_t kBsrpFrameMax = 40;
const uint32_t kMinUnicastGapMs = 45;

// These schedule fields stay 0 until a real BSRP is captured on the target BSS.
// BSRPTEST prints them as placeholders instead of pretending they are valid.
//
// Measured on a C5 (2026-11-25, see 测试报告.md §4.4.14) what a station actually
// requires before it answers:
//   - AID must be its own. Any other AID and the MAC does not even count the
//     frame, so nothing downstream can be observed.
//   - ul_length must be big enough to carry the response: 40 octets -> abort,
//     48 -> the station sends a QoS Null. With 0 it never answers.
//   - ap_tx_power and target_rssi do NOT gate the answer. They only move the
//     station's tb_pwr_outof_range counter, which increments even on triggers
//     that are answered. Do not read it as a veto.
// Trigger type lives in the Common Info low nibble. 4 = BSRP (default), 0 = Basic,
// 2 = MU-BAR. The rest of the frame is type-agnostic apart from MU-BAR's extra
// per-user BAR fields, which are appended only for type 2.
//
// The MU-BAR additions below are UNVERIFIED: no local dissector and no captured
// reference frame, so the two 16-bit fields exist to be checked against a real
// MU-BAR (or Wireshark's mask) before anything is concluded from them.
uint8_t s_trigger_type = 4;
uint16_t s_bar_control = 0;
uint16_t s_bar_seq = 0;

uint16_t s_ul_length = 0;
uint8_t s_gi_ltf = 0;
uint8_t s_ap_tx_power = 0;
uint8_t s_ru_allocation = 0;
uint8_t s_target_rssi = 0;
uint8_t s_mcs = 7;

bool s_active;
bool s_have_sta;
bool s_unlimited;
bool s_auto_aid;      // aid=0: take the AID from the association response
bool s_aid_known;
uint8_t s_bssid[6];
uint8_t s_sta[6];
uint8_t s_channel;
uint16_t s_aid;
uint16_t s_learned_aid;
uint32_t s_rate_ms;
uint32_t s_left;
uint32_t s_frames;
uint32_t s_tx_errors;
uint32_t s_reference_triggers;
uint32_t s_last_tx_ms;

void put_le64(uint8_t* out, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(value >> (8 * i));
    }
}

void put_le40(uint8_t* out, uint64_t value) {
    for (int i = 0; i < 5; i++) {
        out[i] = (uint8_t)(value >> (8 * i));
    }
}

uint64_t get_le40(const uint8_t* in) {
    uint64_t value = 0;
    for (int i = 0; i < 5; i++) {
        value |= ((uint64_t)in[i]) << (8 * i);
    }
    return value;
}

size_t build_bsrp(uint8_t* frame, const uint8_t ra[6], const uint8_t ta[6], uint16_t aid) {
    // MU-BAR carries four extra octets per user (BAR control + starting sequence);
    // every other trigger type stops after the 5-octet User Info.
    const size_t extra = (s_trigger_type == kTriggerTypeMuBar) ? 4 : 0;
    const size_t body = 24 + 5 + extra;
    const size_t len = (body + 3) & ~(size_t)3;  // Trigger frames are 4-octet aligned
    memset(frame, 0, len);
    frame[0] = 0x24;  // control, subtype 2 = Trigger
    memcpy(frame + 4, ra, 6);
    memcpy(frame + 10, ta, 6);

    // HE Common Info bit positions. UL Spatial Reuse occupies bits 37..52;
    // Doppler is bit 53 and UL HE-SIG-A2 Reserved occupies bits 54..62.
    uint64_t common = s_trigger_type & 0x0F;
    common |= ((uint64_t)(s_ul_length & 0x0FFF)) << 4;
    common |= ((uint64_t)(s_gi_ltf & 0x03)) << 20;
    common |= ((uint64_t)(s_ap_tx_power & 0x3F)) << 28;
    put_le64(frame + 16, common);

    // AID12, RU Allocation (including its region bit), FEC, MCS, DCM,
    // SS Allocation and UL Target RSSI share one little-endian 40-bit word.
    uint64_t user = aid & 0x0FFF;
    user |= ((uint64_t)s_ru_allocation) << 12;
    user |= ((uint64_t)(s_mcs & 0x0F)) << 21;
    user |= ((uint64_t)(s_target_rssi & 0x7F)) << 32;
    put_le40(frame + 24, user);
    if (extra != 0) {
        frame[29] = (uint8_t)(s_bar_control & 0xFF);
        frame[30] = (uint8_t)(s_bar_control >> 8);
        frame[31] = (uint8_t)(s_bar_seq & 0xFF);
        frame[32] = (uint8_t)(s_bar_seq >> 8);
    }
    return len;
}

void learn_sta(const uint8_t mac[6]) {
    if ((mac[0] & 0x01) != 0 || memcmp(mac, s_bssid, 6) == 0) {
        return;
    }
    if (!s_have_sta || memcmp(s_sta, mac, 6) != 0) {
        memcpy(s_sta, mac, 6);
        s_have_sta = true;
    }
}

void print_mac(const char* label, const uint8_t mac[6]) {
    Serial.printf("%s=%02X:%02X:%02X:%02X:%02X:%02X", label, mac[0], mac[1], mac[2], mac[3],
                  mac[4], mac[5]);
}

}  // namespace

bool bsrp_start(int index, uint16_t aid, uint8_t channel, uint32_t rate_ms, uint32_t count,
                const uint8_t sta[6]) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr || aid > 2007 || channel == 0) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    // aid 0 means "learn it": the station's AID is only visible in its own
    // association response, and the touch screen has no way to type it. Until it
    // is learned the module stays started but silent.
    s_aid = aid;
    s_auto_aid = (aid == 0);
    s_aid_known = (aid != 0);
    s_learned_aid = aid;
    s_channel = channel;
    s_rate_ms = rate_ms < kMinUnicastGapMs ? kMinUnicastGapMs : rate_ms;
    s_unlimited = (count == 0);
    s_left = count;
    s_have_sta = (sta != nullptr);
    if (s_have_sta) {
        memcpy(s_sta, sta, 6);
    } else {
        memset(s_sta, 0, 6);
    }
    s_frames = 0;
    s_tx_errors = 0;
    s_reference_triggers = 0;
    s_last_tx_ms = 0;
    s_active = true;

    radio_set_channel("bsrp", s_channel);
    attack_sniffer_enable();
    return true;
}

void bsrp_stop(void) {
    s_active = false;
}

void bsrp_step(void) {
    if (!s_active || !s_have_sta || !s_aid_known) {
        return;
    }
    if (!s_unlimited && s_left == 0) {
        s_active = false;
        return;
    }
    const uint32_t now = millis();
    if (s_last_tx_ms != 0 && now - s_last_tx_ms < s_rate_ms) {
        return;
    }

    uint8_t frame[kBsrpFrameMax];
    const size_t len = build_bsrp(frame, s_sta, s_bssid, s_learned_aid);
    if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        s_last_tx_ms = now;
        if (!s_unlimited && s_left > 0 && --s_left == 0) {
            s_active = false;
        }
    } else {
        s_tx_errors++;
    }
}

void bsrp_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (!s_active || len < 16 || memcmp(frame + 10, s_bssid, 6) != 0) {
        return;
    }

    // Association and Reassociation Response: RA is the station, AID follows
    // Capability Information and Status Code in the fixed response body.
    if (type == 0 && (subtype == 1 || subtype == 3) && len >= 30) {
        const uint16_t status = frame[26] | (frame[27] << 8);
        const uint16_t aid = (frame[28] | (frame[29] << 8)) & 0x0FFF;
        if (status == 0 && (s_auto_aid || aid == s_learned_aid)) {
            if (s_auto_aid && aid >= 1 && aid <= 2007) {
                s_learned_aid = aid;
                s_aid_known = true;
                s_auto_aid = false;
            }
            learn_sta(frame + 4);
        }
        return;
    }

    // A real BSRP for this AID also identifies its intended RA. It is a reference
    // observation only; scheduling values are not silently copied into our frame.
    if (type == 1 && subtype == 2 && len >= 29 && (frame[16] & 0x0F) == kTriggerTypeBsrp) {
        const uint64_t user = get_le40(frame + 24);
        if ((user & 0x0FFF) == s_learned_aid) {
            s_reference_triggers++;
            learn_sta(frame + 4);
        }
    }
}

void bsrp_selftest(void) {
    static const uint8_t fake_ap[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    uint8_t frame[kBsrpFrameMax];
    const size_t len = build_bsrp(frame, fake_sta, fake_ap, s_aid == 0 ? 1 : s_aid);

    const uint64_t user = get_le40(frame + 24);
    Serial.printf("BSRPTEST state=%s len=%u frame_control=0x%02X%02X type=1 subtype=2 duration=%u\n",
                  s_active ? "on" : "off", (unsigned)len, frame[1], frame[0],
                  (unsigned)(frame[2] | (frame[3] << 8)));
    Serial.print("BSRPTEST addr ");
    print_mac("ra", frame + 4);
    Serial.print(" ");
    print_mac("ta", frame + 10);
    Serial.println();
    Serial.printf(
        "BSRPTEST common[16..23] trigger_type=%u ul_length=%u more_tf=0 cs_required=0 ul_bw=0 "
        "gi_ltf=%u mu_mimo_ltf=0 he_ltf=0 stbc=0 ldpc=0 ap_tx_power=%u\n",
        frame[16] & 0x0F, s_ul_length, s_gi_ltf, s_ap_tx_power);
    Serial.println("BSRPTEST common2 pre_fec=0 pe=0 spatial_reuse=0x0000 doppler=0 "
                   "he_sig_a2_reserved=0x000 reserved=0");
    Serial.printf(
        "BSRPTEST user[24..28] aid=%u ru_region=%u ru_allocation=%u fec=0 mcs=%u dcm=0 "
        "ss_start=0 ss_count=0 target_rssi=%u reserved=0\n",
        (unsigned)(user & 0x0FFF), (unsigned)((user >> 12) & 1), (unsigned)((user >> 13) & 0x7F),
        (unsigned)((user >> 21) & 0x0F), (unsigned)((user >> 32) & 0x7F));
    if (s_trigger_type == kTriggerTypeMuBar) {
        Serial.printf("BSRPTEST mubar[29..32] bar_control=0x%04X bar_seq=0x%04X "
                      "(layout UNVERIFIED: no local dissector, no reference frame)\n",
                      (unsigned)s_bar_control, (unsigned)s_bar_seq);
        Serial.printf("BSRPTEST padding[33..%u] hex=", (unsigned)(len - 1));
        for (size_t i = 33; i < len; i++) {
            Serial.printf("%02X", frame[i]);
        }
        Serial.println();
    } else {
        Serial.println("BSRPTEST padding[29..31] hex=000000 fcs=driver");
    }
    Serial.println("BSRPTEST reference=missing core_fields=placeholder (ul_length gi_ltf "
                   "ap_tx_power ru_allocation target_rssi)");
    Serial.print("BSRPTEST hex=");
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();
}

bool bsrp_active(void) {
    return s_active;
}

uint32_t bsrp_frames(void) {
    return s_frames;
}

uint32_t bsrp_remaining(void) {
    return s_unlimited ? 0 : s_left;
}

uint32_t bsrp_tx_errors(void) {
    return s_tx_errors;
}

uint32_t bsrp_reference_triggers(void) {
    return s_reference_triggers;
}

uint16_t bsrp_aid(void) {
    return s_aid;
}

uint16_t bsrp_learned_aid(void) {
    return s_learned_aid;
}

bool bsrp_aid_known(void) {
    return s_aid_known;
}

uint8_t bsrp_channel(void) {
    return s_channel;
}

uint32_t bsrp_rate_ms(void) {
    return s_rate_ms;
}

uint16_t bsrp_ul_length(void) {
    return s_ul_length;
}

uint8_t bsrp_gi_ltf(void) {
    return s_gi_ltf;
}

uint8_t bsrp_ap_tx_power(void) {
    return s_ap_tx_power;
}

uint8_t bsrp_trigger_type(void) {
    return s_trigger_type;
}

uint8_t bsrp_ru_allocation(void) {
    return s_ru_allocation;
}

uint8_t bsrp_mcs(void) {
    return s_mcs;
}

uint8_t bsrp_target_rssi(void) {
    return s_target_rssi;
}

// Runtime knobs for the schedule fields. They exist so the failure mode can be
// narrowed by measurement instead of by guessing a "correct" value: the
// station's own counters say whether a field was read (tb_pwr_outof_range
// moves) or the frame was rejected before that point (nothing moves).
bool bsrp_set_field(const char* name, long value) {
    if (name == nullptr) {
        return false;
    }
    if (strcmp(name, "ul") == 0) {
        if (value < 0 || value > 0x0FFF) {
            return false;
        }
        s_ul_length = (uint16_t)value;
        return true;
    }
    if (strcmp(name, "gi") == 0) {
        if (value < 0 || value > 3) {
            return false;
        }
        s_gi_ltf = (uint8_t)value;
        return true;
    }
    if (strcmp(name, "atp") == 0) {
        if (value < 0 || value > 0x3F) {
            return false;
        }
        s_ap_tx_power = (uint8_t)value;
        return true;
    }
    if (strcmp(name, "ru") == 0) {
        if (value < 0 || value > 0xFF) {
            return false;
        }
        s_ru_allocation = (uint8_t)value;
        return true;
    }
    if (strcmp(name, "rssi") == 0) {
        if (value < 0 || value > 0x7F) {
            return false;
        }
        s_target_rssi = (uint8_t)value;
        return true;
    }
    if (strcmp(name, "mcs") == 0) {
        if (value < 0 || value > 15) {
            return false;
        }
        s_mcs = (uint8_t)value;
        return true;
    }
    // Trigger type: 4 = BSRP (default), 0 = Basic, 2 = MU-BAR. Other values are
    // accepted because the field is 4 bits wide; what the station does with an
    // unknown type is its business.
    if (strcmp(name, "type") == 0) {
        if (value < 0 || value > 15) {
            return false;
        }
        s_trigger_type = (uint8_t)value;
        return true;
    }
    if (strcmp(name, "barctl") == 0) {
        if (value < 0 || value > 0xFFFF) {
            return false;
        }
        s_bar_control = (uint16_t)value;
        return true;
    }
    if (strcmp(name, "barseq") == 0) {
        if (value < 0 || value > 0xFFFF) {
            return false;
        }
        s_bar_seq = (uint16_t)value;
        return true;
    }
    return false;
}
