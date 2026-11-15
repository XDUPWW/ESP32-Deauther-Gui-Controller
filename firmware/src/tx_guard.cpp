#include "tx_guard.h"

#include <Arduino.h>
#include <esp_system.h>
#include <esp_wifi.h>

namespace {

uint32_t s_ok;
uint32_t s_err;
uint32_t s_throttled;
int32_t s_last_err;
uint32_t s_last_unicast_ms;

// Address 1 is the receiver (RA) in every frame type we inject; the group bit of
// its first octet says whether an ACK is expected.
bool ra_is_group(const uint8_t* frame) {
    return (frame[4] & 0x01) != 0;
}

}  // namespace

esp_err_t tx_guard_send(uint8_t* frame, uint16_t len) {
    if (len < 12) {
        s_err++;
        s_last_err = (int32_t)ESP_ERR_INVALID_ARG;
        return ESP_ERR_INVALID_ARG;
    }
    if (!ra_is_group(frame)) {
        const uint32_t now = millis();
        if (s_last_unicast_ms != 0 && now - s_last_unicast_ms < TX_GUARD_UNICAST_GAP_MS) {
            // Governed, not failed: the pool would fill (see the header) and the
            // next 0x101 would restart the chip.
            s_throttled++;
            return ESP_ERR_INVALID_STATE;
        }
        s_last_unicast_ms = now;
    }

    const esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, (int)len, false);
    if (err == ESP_OK) {
        s_ok++;
        return err;
    }
    s_err++;
    s_last_err = (int32_t)err;

    if (err == ESP_ERR_NO_MEM) {
        // 0x101 == the short-frame pool is gone. Every later injection would be
        // refused as well, so restarting is the only recovery; print the reason
        // first and flush, because esp_restart() discards the TX FIFO.
        Serial.printf("FATAL tx 0x101 (ESP_ERR_NO_MEM) ok=%u err=%u heap=%u -> restart\n",
                      (unsigned)s_ok, (unsigned)s_err, (unsigned)esp_get_free_heap_size());
        Serial.flush();
        delay(20);
        esp_restart();
    }
    return err;
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
