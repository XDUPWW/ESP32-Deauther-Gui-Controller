// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 帧构造与 IE 解析的脱机测试：逐字节比对 probe request，用合成的 beacon 验解析。

#include <stdio.h>
#include <string.h>

#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wifi_frame/ie_parse.h"

static int g_pass;
static int g_fail;

#define CHECK(cond, what)                                           \
    do {                                                            \
        if (cond) {                                                 \
            g_pass++;                                               \
        } else {                                                    \
            g_fail++;                                               \
            printf("  FAIL %s (%s:%d)\n", what, __FILE__, __LINE__); \
        }                                                           \
    } while (0)

static const uint8_t kSta[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t kAp[6] = {0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};

static void test_probe_req(void) {
    printf("probe request\n");
    static const uint8_t kBcast[6] = WF_BROADCAST_ADDR_INIT;
    uint8_t frame[WF_FRAME_CAP];
    const int len = wf_build_probe_req(frame, sizeof(frame), kBcast, kSta, "", 0);
    CHECK(len == 36, "wildcard probe is 36 bytes");
    CHECK(frame[0] == WF_ST_PROBE_REQ, "frame control subtype");
    CHECK(frame[1] == 0x00, "flags");
    CHECK(frame[4] == 0xFF && frame[5] == 0xFF, "addr1 broadcast");
    CHECK(memcmp(frame + 10, kSta, 6) == 0, "addr2 is our mac");
    CHECK(frame[16] == 0xFF && frame[21] == 0xFF, "addr3 broadcast");
    CHECK(frame[24] == WF_IE_SSID && frame[25] == 0, "ssid ie, length 0");
    CHECK(frame[26] == 1 && frame[27] == 8, "supported rates ie");
    CHECK(frame[28] == 0x82 && frame[35] == 0x24, "rates body");

    const int named = wf_build_probe_req(frame, sizeof(frame), kBcast, kSta, "lab", 3);
    CHECK(named == 39, "named probe adds 3 bytes");
    CHECK(frame[25] == 3 && memcmp(frame + 26, "lab", 3) == 0, "ssid body");

    uint8_t small[20];
    CHECK(wf_build_probe_req(small, sizeof(small), kBcast, kSta, "", 0) < 0, "cap too small");
}

static size_t put_ie(uint8_t *buf, size_t off, uint8_t id, const uint8_t *body, uint8_t len) {
    buf[off++] = id;
    buf[off++] = len;
    memcpy(buf + off, body, len);
    return off + len;
}

static size_t build_beacon(uint8_t *frame, bool sae, bool mfpr) {
    static const uint8_t kBcast[6] = WF_BROADCAST_ADDR_INIT;
    memset(frame, 0, WF_FRAME_CAP);
    frame[0] = WF_ST_BEACON;
    memcpy(frame + 4, kBcast, 6);
    memcpy(frame + 10, kAp, 6);
    memcpy(frame + 16, kAp, 6);
    size_t off = WF_MGMT_HDR_LEN + 12;  // header + timestamp/interval/capability
    off = put_ie(frame, off, WF_IE_SSID, (const uint8_t *)"lab-ap", 6);
    const uint8_t ds = 6;
    off = put_ie(frame, off, WF_IE_DS_PARAMS, &ds, 1);

    uint8_t rsn[22];
    size_t n = 0;
    rsn[n++] = 0x01;
    rsn[n++] = 0x00;  // version 1
    const uint8_t group[4] = {0x00, 0x0F, 0xAC, 0x04};
    memcpy(rsn + n, group, 4);
    n += 4;
    rsn[n++] = 0x01;
    rsn[n++] = 0x00;  // one pairwise
    memcpy(rsn + n, group, 4);
    n += 4;
    rsn[n++] = 0x01;
    rsn[n++] = 0x00;  // one akm
    const uint8_t akm[4] = {0x00, 0x0F, 0xAC, (uint8_t)(sae ? WF_AKM_SAE : WF_AKM_PSK)};
    memcpy(rsn + n, akm, 4);
    n += 4;
    rsn[n++] = (uint8_t)(mfpr ? 0x40 : 0x00);
    rsn[n++] = 0x00;  // RSN capabilities
    off = put_ie(frame, off, WF_IE_RSN, rsn, (uint8_t)n);

    const uint8_t extcap[3] = {0x00, 0x00, 0x08};  // bit 19 = BSS transition
    off = put_ie(frame, off, WF_IE_EXT_CAP, extcap, 3);
    return off;
}

static void test_beacon(void) {
    printf("beacon parse\n");
    uint8_t frame[WF_FRAME_CAP];
    size_t len = build_beacon(frame, true, true);

    wf_bss_t bss;
    CHECK(wf_parse_beacon(frame, len, &bss), "parse ok");
    CHECK(strcmp(bss.ssid, "lab-ap") == 0, "ssid");
    CHECK(bss.ssid_len == 6, "ssid length");
    CHECK(bss.channel == 6, "ds channel");
    CHECK(memcmp(bss.bssid, kAp, 6) == 0, "bssid from addr3");
    CHECK(bss.has_rsn, "rsn present");
    CHECK(bss.sae, "sae akm");
    CHECK(bss.mfpr, "mfp required");
    CHECK(bss.bss_transition, "bss transition bit");

    len = build_beacon(frame, false, false);
    CHECK(wf_parse_beacon(frame, len, &bss), "parse psk beacon");
    CHECK(!bss.sae, "psk is not sae");
    CHECK(!bss.mfpr, "mfp not required");

    frame[0] = WF_ST_DEAUTH;
    CHECK(!wf_parse_beacon(frame, len, &bss), "deauth is not a beacon");
    CHECK(!wf_parse_beacon(frame, 20, &bss), "short frame rejected");
}

static void test_ie_helpers(void) {
    printf("ie helpers\n");
    uint8_t ies[32];
    size_t off = put_ie(ies, 0, 0, (const uint8_t *)"abc", 3);
    off = put_ie(ies, off, WF_IE_TIM, (const uint8_t *)"\x01\x02\x00\x01", 4);
    const size_t total = put_ie(ies, off, WF_IE_CSA, (const uint8_t *)"\x04\x0b\x05", 3);

    size_t body = 0;
    const uint8_t *ssid = wf_ie_find(ies, total, WF_IE_SSID, &body);
    CHECK(ssid != NULL && body == 3 && memcmp(ssid, "abc", 3) == 0, "find ssid");
    CHECK(wf_ie_find(ies, total, WF_IE_RSN, &body) == NULL, "missing ie is null");

    wf_tim_t tim;
    const uint8_t *tim_ie = wf_ie_find(ies, total, WF_IE_TIM, &body);
    CHECK(wf_tim_parse(tim_ie, body, &tim), "tim parse");
    CHECK(tim.dtim_count == 1 && tim.dtim_period == 2, "dtim fields");
    CHECK(!wf_tim_is_multicast_set(&tim), "multicast bit clear");
    CHECK(wf_tim_aid_set(&tim, 1), "aid 1 set");
    CHECK(!wf_tim_aid_set(&tim, 9), "aid 9 clear");
    CHECK(wf_tim_aid_set(&tim, 9) == false && tim.pv_len == 1, "bitmap length respected");

    uint8_t channel = 0;
    uint8_t count = 0;
    const uint8_t *csa = wf_ie_find(ies, total, WF_IE_CSA, &body);
    CHECK(wf_csa_parse(csa, body, &channel, &count), "csa parse");
    CHECK(channel == 11 && count == 5, "csa fields");
}

int main(void) {
    printf("wifi_frame host tests\n");
    test_probe_req();
    test_beacon();
    test_ie_helpers();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
