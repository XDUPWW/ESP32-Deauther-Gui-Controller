#include "ie_util.h"

#include <string.h>

namespace {

// Both RSN probes walk the same prefix: version, group cipher, pairwise list,
// AKM list. Returns the offset of the AKM suite count or 0 when the element is
// too short to hold one.
size_t akm_list_offset(const uint8_t* rsn, uint16_t len) {
    if (rsn == nullptr || len < 8) {
        return 0;
    }
    size_t pos = 2 + 4;  // RSN version + group data cipher suite
    const uint16_t pairwise = (uint16_t)(rsn[pos] | (rsn[pos + 1] << 8));
    pos += 2 + (size_t)pairwise * 4;
    if (len < pos + 2) {
        return 0;
    }
    return pos;
}

bool akm_list_has(const uint8_t* rsn, uint16_t len, uint8_t suite_type) {
    const size_t pos = akm_list_offset(rsn, len);
    if (pos == 0) {
        return false;
    }
    const uint16_t count = (uint16_t)(rsn[pos] | (rsn[pos + 1] << 8));
    size_t off = pos + 2;
    for (uint16_t i = 0; i < count; i++) {
        if (len < off + 4) {
            return false;
        }
        const bool oui_ok = rsn[off] == 0x00 && rsn[off + 1] == 0x0F && rsn[off + 2] == 0xAC;
        if (oui_ok && rsn[off + 3] == suite_type) {
            return true;
        }
        off += 4;
    }
    return false;
}

}  // namespace

const uint8_t* ie_find(const uint8_t* start, const uint8_t* end, uint8_t id, uint16_t* out_len) {
    if (start == nullptr || end == nullptr) {
        return nullptr;
    }
    const uint8_t* p = start;
    while (p + 2 <= end) {
        const uint8_t ie_id = p[0];
        const uint8_t ie_len = p[1];
        if (p + 2 + ie_len > end) {
            return nullptr;  // truncated element: stop instead of guessing
        }
        if (ie_id == id) {
            if (out_len != nullptr) {
                *out_len = ie_len;
            }
            return p + 2;
        }
        p += 2 + ie_len;
    }
    return nullptr;
}

bool rsn_has_akm_sae(const uint8_t* rsn, uint16_t len) {
    // 8 = SAE, 9 = FT-SAE, 24 = SAE-EXT-KEY (WPA3 R3). All three mean "this BSS
    // runs SAE", which is what the commit flood keys on.
    return akm_list_has(rsn, len, 8) || akm_list_has(rsn, len, 9) || akm_list_has(rsn, len, 24);
}

bool rsn_has_akm_psk(const uint8_t* rsn, uint16_t len) {
    return akm_list_has(rsn, len, 2) || akm_list_has(rsn, len, 4) || akm_list_has(rsn, len, 6);
}

bool rsn_mfpr_required(const uint8_t* rsn, uint16_t len) {
    const size_t pos = akm_list_offset(rsn, len);
    if (pos == 0) {
        return false;
    }
    const uint16_t count = (uint16_t)(rsn[pos] | (rsn[pos + 1] << 8));
    const size_t caps = pos + 2 + (size_t)count * 4;
    if (len < caps + 2) {
        return false;
    }
    const uint16_t rsn_caps = (uint16_t)(rsn[caps] | (rsn[caps + 1] << 8));
    return (rsn_caps & 0x0040) != 0;
}

bool extcap_has_bss_transition(const uint8_t* extcap, uint16_t len) {
    // Bit 19 sits in byte 2 bit 3 of the Extended Capabilities field.
    if (extcap == nullptr || len < 3) {
        return false;
    }
    return (extcap[2] & 0x08) != 0;
}
