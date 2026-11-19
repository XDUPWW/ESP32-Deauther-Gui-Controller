#include "tx_guard.h"

#include <Arduino.h>
#include <esp_system.h>
#include <esp_wifi.h>

#include <string.h>

const tx_policy_t kTxPolicyGuard = {
    .name = "guard",
    .min_gap_ms = TX_GUARD_UNICAST_GAP_MS,
    .on_nomem = TX_ON_NOMEM_RESTART,
};

const tx_policy_t kTxPolicyBurst = {
    .name = "burst",
    .min_gap_ms = 0,
    .on_nomem = TX_ON_NOMEM_BACKOFF,
};

namespace {

uint32_t s_ok;
uint32_t s_err;
uint32_t s_throttled;
int32_t s_last_err;

// One pacing timestamp per policy: a burst send must not push the guard policy's
// window, otherwise deauth would throttle the frame-level modules for no reason.
struct policy_state_t {
    const tx_policy_t* policy;
    uint32_t last_unicast_ms;
};

policy_state_t s_states[4];

policy_state_t* state_for(const tx_policy_t* policy) {
    for (size_t i = 0; i < sizeof(s_states) / sizeof(s_states[0]); i++) {
        if (s_states[i].policy == policy) return &s_states[i];
    }
    for (size_t i = 0; i < sizeof(s_states) / sizeof(s_states[0]); i++) {
        if (s_states[i].policy == nullptr) {
            s_states[i].policy = policy;
            return &s_states[i];
        }
    }
    return nullptr;  // more policies than slots: pace nothing, do not corrupt state
}

// Address 1 is the receiver (RA) in every frame type we inject; the group bit of
// its first octet says whether an ACK is expected.
bool ra_is_group(const uint8_t* frame) {
    return (frame[4] & 0x01) != 0;
}

}  // namespace

esp_err_t tx_guard_send_as(const tx_policy_t* policy, uint8_t* frame, uint16_t len) {
    if (policy == nullptr) policy = &kTxPolicyBurst;
    if (frame == nullptr || len < 12) {
        s_err++;
        s_last_err = (int32_t)ESP_ERR_INVALID_ARG;
        return ESP_ERR_INVALID_ARG;
    }

    if (policy->min_gap_ms > 0 && !ra_is_group(frame)) {
        policy_state_t* state = state_for(policy);
        const uint32_t now = millis();
        if (state != nullptr && state->last_unicast_ms != 0 &&
            now - state->last_unicast_ms < policy->min_gap_ms) {
            // Governed, not failed: the pool would fill (see the header) and the
            // next 0x101 would either restart the chip or waste a tick.
            s_throttled++;
            return ESP_ERR_INVALID_STATE;
        }
        if (state != nullptr) state->last_unicast_ms = now;
    }

    const esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, (int)len, false);
    if (err == ESP_OK) {
        s_ok++;
        return err;
    }

    s_err++;
    s_last_err = (int32_t)err;
    if (err == ESP_ERR_NO_MEM && policy->on_nomem == TX_ON_NOMEM_RESTART) {
        // The short-frame pool is gone. Every later injection would be refused as
        // well, so restarting is the only recovery; print the reason first and
        // flush, because esp_restart() discards the TX FIFO.
        Serial.printf("FATAL tx 0x101 (ESP_ERR_NO_MEM) policy=%s ok=%u err=%u heap=%u -> restart\n",
                      policy->name != nullptr ? policy->name : "?", (unsigned)s_ok, (unsigned)s_err,
                      (unsigned)esp_get_free_heap_size());
        Serial.flush();
        delay(20);
        esp_restart();
    }
    return err;
}

esp_err_t tx_guard_send(uint8_t* frame, uint16_t len) {
    return tx_guard_send_as(&kTxPolicyGuard, frame, len);
}

uint32_t tx_guard_throttled(void) {
    return s_throttled;
}

uint32_t tx_guard_ok(void) {
    return s_ok;
}

uint32_t tx_guard_err(void) {
    return s_err;
}

int32_t tx_guard_last_err(void) {
    return s_last_err;
}
