// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 帧构造与 IE 解析的脱机测试：逐字节比对 probe request，用合成的 beacon 验解析。

#include <stdio.h>
#include <string.h>

#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wifi_frame/ie_build.h"
#include "wifi_frame/ie_parse.h"
#include "wifi_frame/mac.h"

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

static void test_mac(void) {
    printf("mac helpers\n");
    uint8_t mac[6] = {0};
    CHECK(wf_mac_parse("aa:BB:01:02:03:04", mac), "parse mixed case");
    CHECK(mac[0] == 0xAA && mac[1] == 0xBB && mac[5] == 0x04, "parsed bytes");
    CHECK(!wf_mac_parse("aa:bb:01:02:03", mac), "short mac rejected");
    CHECK(!wf_mac_parse("aa:bb:01:02:03:1ff", mac), "overflow octet rejected");

    char text[18];
    wf_mac_format(text, mac);
    CHECK(strcmp(text, "aa:bb:01:02:03:04") == 0, "format");

    static const uint8_t kGroup[6] = {0x01, 0, 0, 0, 0, 0};
    static const uint8_t kUnicast[6] = {0x02, 0, 0, 0, 0, 0};
    static const uint8_t kBcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    CHECK(wf_mac_is_group(kGroup), "group bit");
    CHECK(!wf_mac_is_group(kUnicast), "unicast bit");
    CHECK(wf_mac_is_broadcast(kBcast), "broadcast");
    CHECK(!wf_mac_is_broadcast(kUnicast), "not broadcast");

    uint8_t rnd[6];
    wf_mac_randomize(rnd, 0x1122334455667788ULL);
    CHECK(!wf_mac_is_group(rnd), "randomized mac is unicast");
    CHECK((rnd[0] & 0x02) != 0, "randomized mac is locally administered");
    uint8_t again[6];
    wf_mac_randomize(again, 0x1122334455667788ULL);
    CHECK(memcmp(rnd, again, 6) == 0, "same entropy same mac");
    wf_mac_randomize(again, 0x8877665544332211ULL);
    CHECK(memcmp(rnd, again, 6) != 0, "different entropy different mac");
}

static void test_bar(void) {
    printf("block ack request\n");
    static const uint8_t kRa[6] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t kTa[6] = {0x02, 0x21, 0x22, 0x23, 0x24, 0x25};
    uint8_t frame[WF_FRAME_CAP];
    const int len = wf_build_bar(frame, sizeof(frame), kRa, kTa, 5, 0x123);
    CHECK(len == 20, "BAR is 20 bytes");
    CHECK(frame[0] == WF_ST_BAR, "control subtype 8");
    CHECK(frame[1] == 0x00, "flags");
    CHECK(memcmp(frame + 4, kRa, 6) == 0, "addr1 is RA");
    CHECK(memcmp(frame + 10, kTa, 6) == 0, "addr2 is TA");
    const uint16_t control = wf_le16(frame + 16);
    CHECK((control & 0x0004) != 0, "compressed bitmap bit");
    CHECK(((control >> 12) & 0x0F) == 5, "tid in bits12..15");
    CHECK(wf_le16(frame + 18) == (uint16_t)(0x123 << 4), "starting sequence");

    uint8_t small[10];
    CHECK(wf_build_bar(small, sizeof(small), kRa, kTa, 0, 0) < 0, "cap too small");
}


static void test_mgmt_builders(void) {
    printf("management builders\n");
    static const uint8_t kBcast[6] = WF_BROADCAST_ADDR_INIT;
    uint8_t frame[WF_FRAME_CAP];

    int len = wf_build_deauth(frame, sizeof(frame), kSta, kAp, kAp, 7);
    CHECK(len == 26, "deauth is 26 bytes");
    CHECK(frame[0] == WF_ST_DEAUTH, "deauth subtype");
    CHECK(memcmp(frame + 4, kSta, 6) == 0, "deauth addr1 is the station");
    CHECK(memcmp(frame + 10, kAp, 6) == 0, "deauth addr2 is the ap");
    CHECK(wf_le16(frame + 24) == 7, "deauth reason");

    len = wf_build_disassoc(frame, sizeof(frame), kSta, kAp, kAp, 8);
    CHECK(len == 26 && frame[0] == WF_ST_DISASSOC, "disassoc frame");
    CHECK(wf_le16(frame + 24) == 8, "disassoc reason");

    len = wf_build_auth(frame, sizeof(frame), kAp, kSta, kAp, 3, 1, 0);
    CHECK(len == 30, "auth is 30 bytes");
    CHECK(frame[0] == WF_ST_AUTH, "auth subtype");
    CHECK(wf_le16(frame + 24) == 3, "auth algorithm");
    CHECK(wf_le16(frame + 26) == 1, "auth sequence");
    CHECK(wf_le16(frame + 28) == 0, "auth status");

    const uint8_t ies[] = {WF_IE_SSID, 3, 'l', 'a', 'b'};
    len = wf_build_assoc_req(frame, sizeof(frame), kAp, kSta, kAp, 0x0411, 10, ies, sizeof(ies));
    CHECK(len == 33, "assoc request length");
    CHECK(frame[0] == WF_ST_ASSOC_REQ, "assoc subtype");
    CHECK(wf_le16(frame + 24) == 0x0411, "assoc capability");
    CHECK(wf_le16(frame + 26) == 10, "assoc listen interval");
    CHECK(memcmp(frame + 28, ies, sizeof(ies)) == 0, "assoc ies copied");

    len = wf_build_beacon(frame, sizeof(frame), kAp, 0x1122334455667788ULL, 100, 0x0401, ies,
                          sizeof(ies));
    CHECK(len == 41, "beacon length");
    CHECK(frame[0] == WF_ST_BEACON, "beacon subtype");
    CHECK(memcmp(frame + 4, kBcast, 6) == 0, "beacon addr1 broadcast");
    CHECK(memcmp(frame + 10, kAp, 6) == 0 && memcmp(frame + 16, kAp, 6) == 0, "beacon bssid");
    CHECK(frame[24] == 0x88 && frame[31] == 0x11, "beacon timestamp little endian");
    CHECK(wf_le16(frame + 32) == 100, "beacon interval");
    CHECK(wf_le16(frame + 34) == 0x0401, "beacon capability");
    CHECK(memcmp(frame + 36, ies, sizeof(ies)) == 0, "beacon ies copied");

    const uint8_t btm[] = {7, 1, 0};
    len = wf_build_action(frame, sizeof(frame), kSta, kAp, kAp, 10, btm, sizeof(btm));
    CHECK(len == 28, "action length");
    CHECK(frame[0] == WF_ST_ACTION, "action subtype");
    CHECK(frame[24] == 10, "action category");
    CHECK(memcmp(frame + 25, btm, sizeof(btm)) == 0, "action body copied");
}

static void test_data_builders(void) {
    printf("data builders\n");
    uint8_t frame[WF_FRAME_CAP];
    uint8_t eapol[4] = {0x02, 0x01, 0x00, 0x00};

    int len = wf_build_data(frame, sizeof(frame), kAp, kSta, kAp, true, false, true, 5, eapol, 4);
    CHECK(len == 30, "qos data length");
    CHECK(frame[0] == WF_ST_QOS_DATA, "qos data subtype");
    CHECK(frame[1] == 0x01, "toDS bit");
    CHECK(memcmp(frame + 4, kAp, 6) == 0, "toDS addr1 is the ap");
    CHECK(memcmp(frame + 10, kSta, 6) == 0, "toDS addr2 is the station");
    CHECK(memcmp(frame + 16, kAp, 6) == 0, "toDS addr3 is the destination");
    CHECK(wf_le16(frame + 24) == 5, "qos tid");
    CHECK(memcmp(frame + 26, eapol, 4) == 0, "payload copied");

    len = wf_build_data(frame, sizeof(frame), kSta, kAp, kAp, false, true, false, 0, eapol, 4);
    CHECK(len == 28, "plain data length");
    CHECK(frame[0] == 0x08, "plain data subtype");
    CHECK(frame[1] == 0x02, "fromDS bit");
    CHECK(memcmp(frame + 4, kSta, 6) == 0, "fromDS addr1 is the station");
    CHECK(memcmp(frame + 10, kAp, 6) == 0, "fromDS addr2 is the ap");
    CHECK(memcmp(frame + 16, kAp, 6) == 0, "fromDS addr3 is the source");

    CHECK(wf_build_data(frame, sizeof(frame), kSta, kAp, kAp, true, true, false, 0, eapol, 4) < 0,
          "WDS rejected");

    len = wf_build_null_data(frame, sizeof(frame), kAp, kSta, kAp, false, true);
    CHECK(len == 24, "null data length");
    CHECK(frame[0] == 0x48, "null data subtype");
    CHECK((frame[1] & 0x10) != 0, "power management bit");
    len = wf_build_null_data(frame, sizeof(frame), kAp, kSta, kAp, true, false);
    CHECK(len == 26 && frame[0] == WF_ST_QOS_NULL, "qos null length");
    CHECK((frame[1] & 0x10) == 0, "pm bit clear");

    len = wf_build_llc_snap(frame, sizeof(frame), 0x888E, eapol, 4);
    CHECK(len == 12, "llc/snap length");
    CHECK(frame[0] == 0xAA && frame[1] == 0xAA && frame[2] == 0x03, "llc/snap prefix");
    CHECK(frame[6] == 0x88 && frame[7] == 0x8E, "eapol ethertype big endian");
    CHECK(memcmp(frame + 8, eapol, 4) == 0, "llc/snap payload");
}

static void test_ctrl_builders(void) {
    printf("control builders\n");
    uint8_t frame[WF_FRAME_CAP];
    static const uint8_t kRa[6] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    int len = wf_build_rts(frame, sizeof(frame), kRa, kSta, 320);
    CHECK(len == 16, "rts is 16 bytes");
    CHECK(frame[0] == WF_ST_RTS, "rts subtype");
    CHECK(wf_le16(frame + 2) == 320, "rts duration");
    CHECK(memcmp(frame + 4, kRa, 6) == 0, "rts ra");
    CHECK(memcmp(frame + 10, kSta, 6) == 0, "rts ta");
}

static void test_ie_build(void) {
    printf("ie build\n");
    uint8_t ies[128];
    wf_ie_writer_t w;
    wf_ie_begin(&w, ies, sizeof(ies));

    CHECK(wf_ie_ssid(&w, "lab", 3), "ssid ok");
    CHECK(wf_ie_rates(&w, 1, 0x0C), "rates ok");
    CHECK(wf_ie_ds(&w, 6), "ds ok");
    CHECK(wf_ie_csa(&w, 11, 5), "csa ok");
    CHECK(wf_ie_extcap_btm(&w), "extcap ok");
    wf_ie_tim(&w, 1, 2, 0x01, (const uint8_t *)"\x02", 1);
    CHECK(wf_ie_ok(&w), "writer still ok");

    uint8_t frame[64];
    const int len = wf_build_beacon(frame, sizeof(frame), kAp, 0x1122334455667788ULL, 100, 0x0411,
                                    ies, wf_ie_len(&w));
    CHECK(len == 36 + (int)wf_ie_len(&w), "beacon length");

    wf_bss_t bss;
    CHECK(wf_parse_beacon(frame, (size_t)len, &bss), "cloned beacon parses");
    CHECK(memcmp(bss.ssid, "lab", 3) == 0, "ssid round trip");
    CHECK(bss.channel == 6, "ds channel round trip");
    CHECK(bss.bss_transition, "extcap btm round trip");

    size_t body = 0;
    const uint8_t *csa = wf_ie_find(frame + 36, wf_ie_len(&w), WF_IE_CSA, &body);
    uint8_t channel = 0;
    uint8_t count = 0;
    CHECK(wf_csa_parse(csa, body, &channel, &count), "csa round trip");
    CHECK(channel == 11 && count == 5, "csa values");

    // RSN 用解析器回读，AKM 和 MFPR 位都要能对上
    wf_ie_begin(&w, ies, sizeof(ies));
    CHECK(wf_ie_rsn_psk(&w), "rsn psk ok");
    const uint8_t *rsn = wf_ie_find(ies, wf_ie_len(&w), WF_IE_RSN, &body);
    CHECK(rsn != NULL && body == 20, "rsn psk body length");
    CHECK(wf_rsn_has_akm(rsn, body, WF_AKM_PSK), "rsn has psk akm");
    CHECK(!wf_rsn_has_akm(rsn, body, WF_AKM_SAE), "rsn has no sae");
    CHECK(!wf_rsn_mfpr_required(rsn, body), "mfpr clear");

    wf_ie_begin(&w, ies, sizeof(ies));
    CHECK(wf_ie_rsn_sae(&w), "rsn sae ok");
    rsn = wf_ie_find(ies, wf_ie_len(&w), WF_IE_RSN, &body);
    CHECK(rsn != NULL && body == 24, "rsn sae body length");
    CHECK(wf_rsn_has_akm(rsn, body, WF_AKM_SAE), "rsn has sae akm");
    CHECK(wf_rsn_has_akm(rsn, body, WF_AKM_PSK), "sae element keeps psk too");

    // 空间不够时必须置 ok=false，且 off 不越界
    uint8_t tight[6];
    wf_ie_begin(&w, tight, sizeof(tight));
    CHECK(wf_ie_ssid(&w, "abc", 3), "first ie fits");
    CHECK(!wf_ie_ds(&w, 6), "second ie refused");
    CHECK(!wf_ie_ok(&w), "writer flagged");
    CHECK(wf_ie_len(&w) == 5, "offset unchanged after refusal");

    // 克隆：跳过 TIM，其余原样搬
    uint8_t src[64];
    size_t off = put_ie(src, 0, WF_IE_SSID, (const uint8_t *)"ap", 2);
    off = put_ie(src, off, WF_IE_TIM, (const uint8_t *)"\x00\x01\x00\x01", 4);
    const size_t src_len = put_ie(src, off, WF_IE_CSA, (const uint8_t *)"\x00\x0b\x05", 3);
    wf_ie_begin(&w, ies, sizeof(ies));
    const size_t copied = wf_ie_copy(&w, src, src_len, WF_IE_TIM);
    CHECK(wf_ie_ok(&w), "copy ok");
    CHECK(copied == src_len - 6, "tim skipped");
    CHECK(wf_ie_find(ies, wf_ie_len(&w), WF_IE_TIM, &body) == NULL, "no tim in copy");
    CHECK(wf_ie_find(ies, wf_ie_len(&w), WF_IE_CSA, &body) != NULL, "csa survived");

    // 尾巴缺字节的 IE 串不能被照搬
    const uint8_t ragged[4] = {WF_IE_SSID, 8, 'a', 'b'};
    wf_ie_begin(&w, ies, sizeof(ies));
    CHECK(wf_ie_copy(&w, ragged, sizeof(ragged), -1) == 0, "ragged tail dropped");
}

static void test_auth_ext(void) {
    printf("auth with extra body\n");
    uint8_t frame[WF_FRAME_CAP];
    const uint8_t extra[4] = {0x13, 0x00, 0xAA, 0xBB};
    const int len = wf_build_auth_ext(frame, sizeof(frame), kAp, kSta, kAp, 3, 1, 0, extra,
                                      sizeof(extra));
    CHECK(len == 34, "auth + 4 bytes of body");
    CHECK(frame[0] == WF_ST_AUTH, "auth subtype");
    CHECK(wf_le16(frame + 24) == 3, "algorithm sae");
    CHECK(wf_le16(frame + 26) == 1, "sequence commit");
    CHECK(wf_le16(frame + 28) == 0, "status success");
    CHECK(memcmp(frame + 30, extra, sizeof(extra)) == 0, "extra body");

    // 不带 extra 时和旧接口一个字节都不差
    const int plain = wf_build_auth(frame, sizeof(frame), kAp, kSta, kAp, 0, 1, 0);
    CHECK(plain == 30, "plain auth is 30 bytes");

    uint8_t small[30];
    CHECK(wf_build_auth_ext(small, sizeof(small), kAp, kSta, kAp, 3, 1, 0, extra, sizeof(extra)) <
              0,
          "cap too small");
}

int main(void) {
    printf("wifi_frame host tests\n");
    test_mac();
    test_bar();
    test_mgmt_builders();
    test_data_builders();
    test_ctrl_builders();
    test_probe_req();
    test_beacon();
    test_ie_helpers();
    test_ie_build();
    test_auth_ext();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
