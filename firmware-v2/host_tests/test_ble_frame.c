// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 广播数据组帧的脱机测试：逐字节比对 AD Structure，顺带验地址格式。

#include <stdio.h>
#include <string.h>

#include "ble_frame/addr.h"
#include "ble_frame/adv.h"
#include "ble_frame/payload.h"

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

static const char *kLongName = "0123456789abcdefghijklmnopqrstuvwxyz";

static void test_flags(void) {
    printf("flags\n");
    uint8_t buf[BF_ADV_LEGACY_MAX];
    bf_adv_t set;
    bf_adv_init(&set, buf, sizeof(buf));
    CHECK(bf_adv_flags(&set, BF_FLAG_GENERAL_DISC | BF_FLAG_NO_BREDR), "flags pushed");
    CHECK(set.len == 3, "flags is 3 bytes");
    CHECK(buf[0] == 0x02 && buf[1] == BF_AD_FLAGS, "flags header");
    CHECK(buf[2] == 0x06, "flags value");
    CHECK(!set.truncated, "not truncated");
}

static void test_name(void) {
    printf("name\n");
    uint8_t buf[BF_ADV_LEGACY_MAX];
    bf_adv_t set;
    bf_adv_init(&set, buf, sizeof(buf));
    CHECK(bf_adv_name(&set, "abc", false), "name pushed");
    CHECK(set.len == 5, "name is 5 bytes");
    CHECK(buf[0] == 0x04 && buf[1] == BF_AD_NAME_COMPLETE, "name header");
    CHECK(memcmp(buf + 2, "abc", 3) == 0, "name body");
}

static void test_name_truncated(void) {
    printf("name 截断成短名\n");
    uint8_t buf[BF_ADV_LEGACY_MAX];
    bf_adv_t set;
    bf_adv_init(&set, buf, sizeof(buf));
    bf_adv_flags(&set, BF_FLAG_GENERAL_DISC | BF_FLAG_NO_BREDR);   // 3
    bf_adv_uuid16(&set, 0x180D, true);                             // 4
    CHECK(set.len == 7, "前缀占 7 字节");

    CHECK(!bf_adv_name(&set, kLongName, false), "放不下就拒绝");
    CHECK(set.truncated, "拒绝要置标记");
    CHECK(set.len == 7, "拒绝后长度不变");

    set.truncated = false;
    // 只剩 24 字节，短名最多塞 22 个字符
    CHECK(bf_adv_name(&set, kLongName, true), "短名 pushed");
    CHECK(set.len == BF_ADV_LEGACY_MAX, "正好填满 31");
    CHECK(buf[7] == 0x17 && buf[8] == BF_AD_NAME_SHORT, "短名 header");
    CHECK(memcmp(buf + 9, "0123456789abcdefghijkl", 22) == 0, "短名 body");
    CHECK(!set.truncated, "短名不算截断事故");
}

static void test_uuid(void) {
    printf("uuid\n");
    uint8_t buf[BF_ADV_LEGACY_MAX];
    bf_adv_t set;

    bf_adv_init(&set, buf, sizeof(buf));
    CHECK(bf_adv_uuid16(&set, 0x180D, true), "uuid16 pushed");
    CHECK(set.len == 4, "uuid16 是 4 字节");
    CHECK(buf[0] == 0x03 && buf[1] == BF_AD_UUID16_COMPLETE, "uuid16 header");
    CHECK(buf[2] == 0x0D && buf[3] == 0x18, "uuid16 小端");

    uint8_t uuid[16];
    for (int i = 0; i < 16; i++) {
        uuid[i] = (uint8_t)i;
    }
    bf_adv_init(&set, buf, sizeof(buf));
    CHECK(bf_adv_uuid128(&set, uuid, false), "uuid128 pushed");
    CHECK(set.len == 18, "uuid128 是 18 字节");
    CHECK(buf[0] == 0x11 && buf[1] == BF_AD_UUID128_INCOMPLETE, "uuid128 header");
    CHECK(buf[2] == 15 && buf[17] == 0, "uuid128 小端反转");
}

static void test_mfr(void) {
    printf("厂商数据\n");
    uint8_t buf[BF_ADV_LEGACY_MAX];
    bf_adv_t set;
    bf_adv_init(&set, buf, sizeof(buf));
    const uint8_t data[2] = {0xD0, 0xD1};
    CHECK(bf_adv_mfr(&set, 0x004C, data, sizeof(data)), "mfr pushed");
    CHECK(set.len == 6, "mfr 是 6 字节");
    CHECK(buf[0] == 0x05 && buf[1] == BF_AD_MFR, "mfr header，长度 = 1+2+2");
    CHECK(buf[2] == 0x4C && buf[3] == 0x00, "company id 小端");
    CHECK(buf[4] == 0xD0 && buf[5] == 0xD1, "mfr body");

    uint8_t big[300];
    memset(big, 0xAA, sizeof(big));
    bf_adv_init(&set, buf, sizeof(buf));
    CHECK(!bf_adv_mfr(&set, 0x004C, big, sizeof(big)), "超长拒绝");
    CHECK(!bf_adv_mfr(&set, 0x004C, big, 28), "28 字节数据塞不进 31");
    CHECK(bf_adv_mfr(&set, 0x004C, big, 27), "27 字节数据正好塞满");
    CHECK(set.len == BF_ADV_LEGACY_MAX, "填满 31");
    CHECK(buf[0] == 0x1E, "长度字段 = 1 + 2 + 27");
}

static void test_service_data(void) {
    printf("服务数据\n");
    uint8_t buf[BF_ADV_LEGACY_MAX];
    bf_adv_t set;
    bf_adv_init(&set, buf, sizeof(buf));
    const uint8_t data[2] = {0x01, 0x02};
    CHECK(bf_adv_service_data16(&set, 0xFE2C, data, 2), "service data pushed");
    CHECK(set.len == 6, "service data 是 6 字节");
    CHECK(buf[0] == 0x05 && buf[1] == BF_AD_SERVICE_DATA16, "service data header");
    CHECK(buf[2] == 0x2C && buf[3] == 0xFE, "uuid16 小端");
    CHECK(buf[4] == 0x01 && buf[5] == 0x02, "service data body");
}

static void test_payload(void) {
    printf("弹窗模板\n");
    CHECK(bf_payload_count() >= 1, "至少一条模板");
    const bf_payload_t *tpl = bf_payload_find("apple_airpods");
    CHECK(tpl != NULL, "按名字找到 apple_airpods");
    CHECK(bf_payload_find("nope") == NULL, "未知名字返回 NULL");
    CHECK(strcmp(bf_platform_name(BF_PLAT_APPLE), "apple") == 0, "平台名");

    uint8_t buf[BF_ADV_LEGACY_MAX];
    bf_adv_t set;
    bf_adv_init(&set, buf, sizeof(buf));
    CHECK(bf_payload_render(tpl, &set), "渲染进 31 字节");
    static const uint8_t kExpected[31] = {
        0x1E, 0xFF, 0x4C, 0x00, 0x07, 0x19, 0x01, 0x20, 0x02, 0x0C, 0x0E,
        0x0A, 0x0C, 0x0E, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    CHECK(set.len == sizeof(kExpected), "正好 31 字节");
    CHECK(!set.truncated, "不截断");
    CHECK(memcmp(buf, kExpected, sizeof(kExpected)) == 0, "整串字节");

    uint8_t small[8];
    bf_adv_init(&set, small, sizeof(small));
    CHECK(!bf_payload_render(tpl, &set), "放不下就拒绝，不截断");
    CHECK(set.truncated, "拒绝要置标记");

    const bf_payload_t *swift = bf_payload_find("microsoft_swiftpair");
    CHECK(swift != NULL, "找到 microsoft_swiftpair");
    bf_adv_init(&set, buf, sizeof(buf));
    CHECK(bf_payload_render(swift, &set), "SwiftPair 渲染进 31 字节");
    static const uint8_t kSwift[31] = {
        0x1E, 0xFF, 0x06, 0x00, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    CHECK(set.len == sizeof(kSwift), "SwiftPair 正好 31 字节");
    CHECK(memcmp(buf, kSwift, sizeof(kSwift)) == 0, "SwiftPair 整串字节");
}

static void test_full(void) {
    printf("填满后拒绝\n");
    uint8_t buf[BF_ADV_LEGACY_MAX];
    bf_adv_t set;
    bf_adv_init(&set, buf, sizeof(buf));
    bf_adv_flags(&set, BF_FLAG_GENERAL_DISC | BF_FLAG_NO_BREDR);   // 3
    bf_adv_uuid16(&set, 0x180D, true);                             // 4
    bf_adv_name(&set, "0123456789abcdefghijkl", true);             // 24 -> 正好 31
    CHECK(set.len == BF_ADV_LEGACY_MAX, "正好 31");
    CHECK(!bf_adv_tx_power(&set, -4), "再塞就拒绝");
    CHECK(set.truncated, "拒绝要置标记");
    CHECK(set.len == BF_ADV_LEGACY_MAX, "长度不变");

    uint8_t wide[BF_ADV_EXT_MAX];
    bf_adv_init(&set, wide, sizeof(wide));
    CHECK(bf_adv_tx_power(&set, -4), "扩展广播能到 255");
    CHECK(set.len == 3 && wide[2] == 0xFC, "tx power -4");
}

static void test_hex(void) {
    printf("十六进制\n");
    uint8_t buf[BF_ADV_LEGACY_MAX];
    bf_adv_t set;
    bf_adv_init(&set, buf, sizeof(buf));
    bf_adv_flags(&set, 0x06);
    char text[64];
    bf_adv_hex(&set, text, sizeof(text));
    CHECK(strcmp(text, "020106") == 0, "hex 输出");

    char tiny[5];
    bf_adv_hex(&set, tiny, sizeof(tiny));
    CHECK(strlen(tiny) == 4, "缓冲区小就截断，不溢出");
}

static void test_addr(void) {
    printf("地址\n");
    uint8_t addr[6];
    bf_addr_random_static(addr, 0x001122334455ULL);
    CHECK(bf_addr_is_random_static(addr), "最高两位是 11");
    CHECK(addr[0] == 0xC0, "熵高位为 0 时只剩最高两位");
    CHECK(addr[1] == 0x11 && addr[2] == 0x22 && addr[5] == 0x55, "小端铺开");

    bf_addr_random_static(addr, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(addr[0] == 0xFF && addr[5] == 0xFF, "全 1 保持");

    const uint8_t pub[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    CHECK(!bf_addr_is_random_static(pub), "public 不算 static");

    char text[18];
    bf_addr_format(text, pub);
    CHECK(strcmp(text, "11:22:33:44:55:66") == 0, "格式");
    uint8_t back[6];
    CHECK(bf_addr_parse(text, back), "解析");
    CHECK(memcmp(back, pub, 6) == 0, "往返一致");
    CHECK(!bf_addr_parse("zz:22:33:44:55:66", back), "非法输入拒绝");

    CHECK(strcmp(bf_addr_type_name(BF_ADDR_PUBLIC), "public") == 0, "类型名 public");
    CHECK(strcmp(bf_addr_type_name(BF_ADDR_RANDOM_STATIC), "static") == 0, "类型名 static");
}

int main(void) {
    test_flags();
    test_name();
    test_name_truncated();
    test_uuid();
    test_mfr();
    test_service_data();
    test_payload();
    test_full();
    test_hex();
    test_addr();

    printf("ble_frame: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
