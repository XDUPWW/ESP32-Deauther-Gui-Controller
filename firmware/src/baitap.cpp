#include "baitap.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_event.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <string.h>

#include "radio.h"
#include "deauth.h"

namespace {

// One radio: the AP's channel and the injector's channel are the same physical
// setting, which is exactly why the bait AP has to sit on the victim's channel.
bool s_running = false;
bool s_handler_registered = false;
bool s_open = false;
char s_ssid[33];
uint8_t s_channel = 0;
uint8_t s_max_conn = 2;
uint8_t s_clients = 0;
uint32_t s_joins = 0;
uint32_t s_leaves = 0;
uint32_t s_free_before = 0;
uint32_t s_free_after = 0;

void mac_text(const uint8_t* mac, char out[18]) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4],
             mac[5]);
}

void on_wifi_event(void*, esp_event_base_t base, int32_t id, void* data) {
    if (base != WIFI_EVENT) {
        return;
    }
    if (id == WIFI_EVENT_AP_STACONNECTED) {
        const auto* e = static_cast<const wifi_event_ap_staconnected_t*>(data);
        s_joins++;
        s_clients = WiFi.softAPgetStationNum();
        char mac[18];
        mac_text(e->mac, mac);
        Serial.printf("EVT baitap_join mac=%s aid=%u n=%u heap=%u\n", mac, (unsigned)e->aid,
                      (unsigned)s_clients, (unsigned)esp_get_free_heap_size());
    } else if (id == WIFI_EVENT_AP_STADISCONNECTED) {
        const auto* e = static_cast<const wifi_event_ap_stadisconnected_t*>(data);
        s_leaves++;
        s_clients = WiFi.softAPgetStationNum();
        char mac[18];
        mac_text(e->mac, mac);
        Serial.printf("EVT baitap_leave mac=%s aid=%u reason=%u n=%u\n", mac, (unsigned)e->aid,
                      (unsigned)e->reason, (unsigned)s_clients);
    }
}

}  // namespace

bool baitap_start(const char* ssid, const char* pass, uint8_t channel, uint8_t max_conn) {
    if (ssid == nullptr) {
        Serial.println("ERR bait AP needs an SSID");
        return false;
    }
    const size_t ssid_len = strlen(ssid);
    if (ssid_len == 0 || ssid_len > 32) {
        Serial.println("ERR bait AP SSID must be 1..32 bytes");
        return false;
    }
    if (channel < 1 || channel > 13) {
        Serial.println("ERR bait AP channel must be 1..13");
        return false;
    }
    const bool open = (pass == nullptr || pass[0] == 0);
    if (!open) {
        const size_t pass_len = strlen(pass);
        // WPA2-PSK only takes 8..63; a shorter one silently leaves the AP down.
        if (pass_len < 8 || pass_len > 63) {
            Serial.println("ERR bait AP passphrase must be 8..63 characters (or none for open)");
            return false;
        }
    }
    if (max_conn < 1) {
        max_conn = 1;
    }
    if (max_conn > 4) {
        max_conn = 4;
    }

    if (s_running) {
        baitap_stop();
    }

    if (!s_handler_registered) {
        esp_event_handler_instance_t instance = nullptr;
        const esp_err_t err =
            esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &on_wifi_event,
                                                nullptr, &instance);
        if (err == ESP_OK) {
            s_handler_registered = true;
        }
    }

    s_free_before = esp_get_free_heap_size();

    // Channel 12/13 are outside the default "01" country, so the AP would come up
    // without a beacon anyone can hear. Set CN before configuring the AP.
    prepare_radio_for_scan();

    // APSTA, never plain AP: WIFI_IF_STA carries every esp_wifi_80211_tx() call.
    if (!WiFi.mode(WIFI_MODE_APSTA)) {
        Serial.println("ERR cannot switch the radio to APSTA");
        return false;
    }

    const IPAddress ip = WiFi.softAP(ssid, open ? nullptr : pass, channel, 0, max_conn);
    if ((uint32_t)ip == 0) {
        WiFi.mode(WIFI_MODE_STA);
        Serial.println("ERR softAP did not start (check channel and passphrase)");
        return false;
    }

    // In APSTA the AP netif sometimes comes up unaddressed (1.0.0.0), which leaves
    // the DHCP server dead: a station would associate and then fall off the network,
    // indistinguishable from "the attack did nothing". Pin the subnet explicitly.
    IPAddress ap_ip = WiFi.softAPIP();
    if ((uint32_t)ap_ip == 0 || (uint32_t)ap_ip == 0x01000000) {
        WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1),
                          IPAddress(255, 255, 255, 0));
        ap_ip = WiFi.softAPIP();
    }

    s_free_after = esp_get_free_heap_size();
    strncpy(s_ssid, ssid, sizeof(s_ssid) - 1);
    s_ssid[sizeof(s_ssid) - 1] = 0;
    s_channel = channel;
    s_max_conn = max_conn;
    s_open = open;
    s_clients = 0;
    s_running = true;

    // Claim the channel so a hopping attack reports a takeover instead of quietly
    // dragging the AP off the air.
    radio_set_channel("baitap", channel);

    uint8_t bssid[6];
    esp_wifi_get_mac(WIFI_IF_AP, bssid);
    Serial.printf(
        "INFO BAITAP up ssid=%s bssid=%02X:%02X:%02X:%02X:%02X:%02X ch=%u auth=%s max=%u ip=%s "
        "heap=%u cost=%d\n",
        s_ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], (unsigned)channel,
        open ? "OPEN" : "WPA2", (unsigned)max_conn, ap_ip.toString().c_str(),
        (unsigned)s_free_after, (int)baitap_heap_cost());
    return true;
}

void baitap_stop(void) {
    if (!s_running) {
        return;
    }
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_MODE_STA);
    s_running = false;
    s_clients = 0;
    s_channel = 0;
    // The netif and its buffers belong to the WiFi driver and are not returned to
    // the heap; heap= here shows what actually came back.
    Serial.printf("INFO BAITAP down joins=%u leaves=%u heap=%u\n", (unsigned)s_joins,
                  (unsigned)s_leaves, (unsigned)esp_get_free_heap_size());
}

bool baitap_running(void) { return s_running; }

uint8_t baitap_channel(void) { return s_channel; }

const char* baitap_ssid(void) { return s_ssid; }

void baitap_bssid(uint8_t out[6]) {
    if (out == nullptr) {
        return;
    }
    if (!s_running || esp_wifi_get_mac(WIFI_IF_AP, out) != ESP_OK) {
        memset(out, 0, 6);
    }
}

uint8_t baitap_clients(void) {
    if (!s_running) {
        return 0;
    }
    s_clients = WiFi.softAPgetStationNum();
    return s_clients;
}

uint32_t baitap_joins(void) { return s_joins; }

uint32_t baitap_leaves(void) { return s_leaves; }

int32_t baitap_heap_cost(void) {
    if (s_free_after == 0) {
        return 0;
    }
    return (int32_t)s_free_before - (int32_t)s_free_after;
}
