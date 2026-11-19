#include "radio.h"

#include <Arduino.h>
#include <esp_wifi.h>
#include <stdio.h>
#include <string.h>

namespace {

char s_owner[16];
uint8_t s_channel;
uint32_t s_takeovers;
uint32_t s_last_claim_ms;
uint32_t s_last_warn_ms;

// Two owners within this window means they are genuinely running together; a claim
// minutes after the previous attack stopped is just sequential use, not a conflict.
const uint32_t kConflictWindowMs = 2000;

}  // namespace

esp_err_t radio_set_channel(const char* owner, uint8_t channel) {
    const esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    const char* name = (owner != nullptr) ? owner : "?";
    const uint32_t now = millis();

    const bool displaced = s_owner[0] != 0 && strcmp(s_owner, name) != 0 &&
                           (now - s_last_claim_ms) < kConflictWindowMs;
    if (displaced) {
        s_takeovers++;
        // Rate-limited: deauth re-claims on every hop, and one WARN per 500 ms is
        // already more than the operator needs to see the conflict.
        if (now - s_last_warn_ms > 500) {
            s_last_warn_ms = now;
            Serial.printf("WARN radio: %s took ch%u from %s (chset=%d)\n", name,
                          (unsigned)channel, s_owner, (int)err);
        }
    }

    snprintf(s_owner, sizeof(s_owner), "%s", name);
    s_channel = channel;
    s_last_claim_ms = now;
    return err;
}

const char* radio_owner(void) { return s_owner; }

uint8_t radio_channel(void) { return s_channel; }

uint32_t radio_takeovers(void) { return s_takeovers; }
