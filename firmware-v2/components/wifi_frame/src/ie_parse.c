// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "wifi_frame/ie_parse.h"

#include <string.h>

const uint8_t *wf_ie_find(const uint8_t *ies, size_t len, uint8_t id, size_t *out_len) {
    if (ies == NULL || out_len == NULL) {
        return NULL;
    }
    size_t offset = 0;
    while (offset + 2 <= len) {
        const uint8_t current = ies[offset];
        const size_t body_len = ies[offset + 1];
        if (offset + 2 + body_len > len) {
            return NULL;
        }
        if (current == id) {
            *out_len = body_len;
            return ies + offset + 2;
        }
        offset += 2 + body_len;
    }
    return NULL;
}

bool wf_parse_beacon(const uint8_t *frame, size_t len, wf_bss_t *out) {
    if (frame == NULL || out == NULL || len < WF_MGMT_HDR_LEN + 12) {
        return false;
    }
    const uint8_t subtype = (uint8_t)(frame[0] & 0xFC);
    if (subtype != WF_ST_BEACON && subtype != WF_ST_PROBE_RESP) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->bssid, frame + 16, 6);

    const uint8_t *ies = frame + WF_MGMT_HDR_LEN + 12;
    const size_t ies_len = len - WF_MGMT_HDR_LEN - 12;

    size_t body_len = 0;
    const uint8_t *ssid = wf_ie_find(ies, ies_len, WF_IE_SSID, &body_len);
    if (ssid != NULL) {
        out->ssid_len = (uint8_t)(body_len > 32 ? 32 : body_len);
        memcpy(out->ssid, ssid, out->ssid_len);
        out->ssid[out->ssid_len] = '\0';
    }

    const uint8_t *ds = wf_ie_find(ies, ies_len, WF_IE_DS_PARAMS, &body_len);
    if (ds != NULL && body_len >= 1) {
        out->channel = ds[0];
    }

    const uint8_t *rsn = wf_ie_find(ies, ies_len, WF_IE_RSN, &body_len);
    if (rsn != NULL) {
        out->has_rsn = true;
        out->sae = wf_rsn_has_akm(rsn, body_len, WF_AKM_SAE);
        out->mfpr = wf_rsn_mfpr_required(rsn, body_len);
    }

    const uint8_t *extcap = wf_ie_find(ies, ies_len, WF_IE_EXT_CAP, &body_len);
    if (extcap != NULL) {
        out->bss_transition = wf_extcap_has_bss_transition(extcap, body_len);
    }
    return true;
}

bool wf_rsn_has_akm(const uint8_t *rsn, size_t len, uint8_t akm_type) {
    if (rsn == NULL || len < 8) {
        return false;
    }
    size_t offset = 2;  // version
    if (offset + 4 > len) {
        return false;
    }
    offset += 4;  // group cipher suite
    if (offset + 2 > len) {
        return false;
    }
    const size_t pairwise_count = wf_le16(rsn + offset);
    offset += 2 + pairwise_count * 4;
    if (offset + 2 > len) {
        return false;
    }
    const size_t akm_count = wf_le16(rsn + offset);
    offset += 2;
    for (size_t i = 0; i < akm_count; i++) {
        if (offset + 4 > len) {
            return false;
        }
        const bool oui_ok = rsn[offset] == 0x00 && rsn[offset + 1] == 0x0F &&
                            rsn[offset + 2] == 0xAC;
        if (oui_ok && rsn[offset + 3] == akm_type) {
            return true;
        }
        offset += 4;
    }
    return false;
}

bool wf_rsn_mfpr_required(const uint8_t *rsn, size_t len) {
    if (rsn == NULL || len < 8) {
        return false;
    }
    size_t offset = 2;
    if (offset + 4 > len) {
        return false;
    }
    offset += 4;
    if (offset + 2 > len) {
        return false;
    }
    const size_t pairwise_count = wf_le16(rsn + offset);
    offset += 2 + pairwise_count * 4;
    if (offset + 2 > len) {
        return false;
    }
    const size_t akm_count = wf_le16(rsn + offset);
    offset += 2 + akm_count * 4;
    if (offset + 2 > len) {
        return false;
    }
    const uint16_t capabilities = wf_le16(rsn + offset);
    return (capabilities & 0x0040) != 0;  // bit 6 = MFP required
}

bool wf_extcap_has_bss_transition(const uint8_t *extcap, size_t len) {
    if (extcap == NULL || len < 3) {
        return false;
    }
    return (extcap[2] & 0x08) != 0;  // bit 19 of the capabilities field
}

bool wf_tim_parse(const uint8_t *ie, size_t len, wf_tim_t *out) {
    if (ie == NULL || out == NULL || len < 4) {
        return false;
    }
    out->dtim_count = ie[0];
    out->dtim_period = ie[1];
    out->bitmap_control = ie[2];
    out->pvbitmap = ie + 3;
    out->pv_len = len - 3;
    return true;
}

bool wf_tim_is_multicast_set(const wf_tim_t *tim) {
    return tim != NULL && (tim->bitmap_control & 0x01) != 0;
}

bool wf_tim_aid_set(const wf_tim_t *tim, uint16_t aid) {
    if (tim == NULL || tim->pvbitmap == NULL || aid == 0) {
        return false;
    }
    const size_t bit = (size_t)aid - 1;
    const size_t byte = bit / 8;
    if (byte >= tim->pv_len) {
        return false;
    }
    return (tim->pvbitmap[byte] & (1u << (bit % 8))) != 0;
}

bool wf_csa_parse(const uint8_t *ie, size_t len, uint8_t *channel, uint8_t *count) {
    if (ie == NULL || len < 3) {
        return false;
    }
    if (channel != NULL) {
        *channel = ie[1];
    }
    if (count != NULL) {
        *count = ie[2];
    }
    return true;
}
