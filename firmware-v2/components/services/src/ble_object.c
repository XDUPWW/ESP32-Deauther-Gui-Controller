// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "sdkconfig.h"

#if CONFIG_WB_BLE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ble_frame/addr.h"
#include "ble_frame/adv.h"
#include "esp_random.h"
#include "esp_system.h"
#include "hal_ble/hal_ble.h"
#include "services_private.h"
#include "wbus/wbus.h"

// 广播串最长 255，扫描结果最长 31。wb 调用都跑在同一个任务里，静态区够用。
static uint8_t s_adv_buf[HAL_BLE_ADV_EXT_MAX];
static uint8_t s_mfr_data[HAL_BLE_ADV_EXT_MAX];
static char s_hex_text[HAL_BLE_ADV_EXT_MAX * 2 + 1];

static const char *arg_text(wb_args_t *args, const char *name) {
    const char *text = wb_args_str(args, name);
    return (text == NULL) ? "" : text;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int hex_to_bytes(const char *text, uint8_t *out, size_t cap) {
    if (text == NULL || out == NULL) {
        return -1;
    }
    size_t n = 0;
    while (text[0] != 0) {
        if (text[1] == 0) {
            return -1;
        }
        const int hi = hex_nibble(text[0]);
        const int lo = hex_nibble(text[1]);
        if (hi < 0 || lo < 0 || n >= cap) {
            return -1;
        }
        out[n++] = (uint8_t)((hi << 4) | lo);
        text += 2;
    }
    return (int)n;
}

// mfr 写成 "004c:d0d1d2"，冒号前是 SIG 分配的公司编号，后面是数据
static bool parse_mfr(const char *text, uint16_t *company, size_t *len) {
    const char *colon = strchr(text, ':');
    if (colon == NULL || colon == text || (size_t)(colon - text) > 4) {
        return false;
    }
    char head[8] = {0};
    memcpy(head, text, (size_t)(colon - text));
    char *end = NULL;
    const unsigned long id = strtoul(head, &end, 16);
    if (end == head || *end != 0 || id > 0xFFFF) {
        return false;
    }
    const int n = hex_to_bytes(colon + 1, s_mfr_data, sizeof(s_mfr_data));
    if (n < 0) {
        return false;
    }
    *company = (uint16_t)id;
    *len = (size_t)n;
    return true;
}

// 毫秒换成 0.625ms 一格，规范里下限 100ms
static uint16_t ms_to_itvl(uint32_t ms) {
    if (ms == 0) {
        return HAL_BLE_ITVL_MIN;
    }
    uint32_t units = (ms * 1000u + 624u) / 625u;
    if (units < HAL_BLE_ITVL_MIN) {
        units = HAL_BLE_ITVL_MIN;
    }
    if (units > HAL_BLE_ITVL_MAX) {
        units = HAL_BLE_ITVL_MAX;
    }
    return (uint16_t)units;
}

static esp_err_t ble_info(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    uint8_t addr[6] = {0};
    uint8_t type = 0;
    hal_ble_addr_get(addr, &type);
    char text[18];
    bf_addr_format(text, addr);

    hal_ble_stats_t stats;
    hal_ble_stats(&stats);
    wb_reply_line(reply, "ready=%d adv=%d scan=%d owner=%s addr=%s type=%s",
                  hal_ble_ready() ? 1 : 0, hal_ble_adv_running() ? 1 : 0,
                  hal_ble_scan_running() ? 1 : 0,
                  (hal_ble_adv_owner() != NULL) ? hal_ble_adv_owner() : "-", text,
                  (type == 0) ? "public" : "random");
    wb_reply_line(reply, "adv_starts=%u adv_err=%u scan_reports=%u peers=%u timeouts=%u last_rc=%d",
                  (unsigned)stats.adv_starts, (unsigned)stats.adv_errors,
                  (unsigned)stats.scan_reports, (unsigned)hal_ble_scan_count(),
                  (unsigned)stats.job_timeouts, (int)stats.last_rc);
    wb_reply_line(reply, "cycles=%u cycle_err=%u addr_rot=%u data_rot=%u conn_refused=%u claim_denied=%u last_cycle_us=%u",
                  (unsigned)stats.adv_cycles, (unsigned)stats.cycle_errors,
                  (unsigned)stats.addr_rotations, (unsigned)stats.data_rotations,
                  (unsigned)stats.conn_refused, (unsigned)stats.claim_denied,
                  (unsigned)stats.last_cycle_us);
    wb_reply_line(reply, "scan_upserts=%u scan_full_drops=%u", (unsigned)stats.scan_upserts,
                  (unsigned)stats.scan_full_drops);
    wb_reply_line(reply, "heap_after_init=%u heap_now=%u", (unsigned)stats.heap_after_init,
                  (unsigned)esp_get_free_heap_size());
    return ESP_OK;
}

static const wb_policy_t kAddrPolicy[] = {
    {.name = "addr", .type = WB_T_STR, .required = false, .def_str = "random"},
};

static esp_err_t ble_addr(wb_args_t *args, wb_reply_t *reply) {
    const char *text = arg_text(args, "addr");
    uint8_t addr[6];
    if (strcmp(text, "random") == 0) {
        bf_addr_random_static(addr, ((uint64_t)esp_random() << 32) | esp_random());
    } else if (!bf_addr_parse(text, addr)) {
        wb_reply_fail(reply, "addr 要是 random 或 aa:bb:cc:dd:ee:ff");
        return ESP_ERR_INVALID_ARG;
    }
    if (!bf_addr_is_random_static(addr)) {
        // 广播用随机地址时控制器只认 static 格式，最高两位得是 11
        addr[0] = (uint8_t)(addr[0] | 0xC0);
    }
    const esp_err_t err = hal_ble_addr_set(addr);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "set addr failed (%s)", esp_err_to_name(err));
        return err;
    }
    char out[18];
    bf_addr_format(out, addr);
    wb_reply_line(reply, "addr=%s（下次广播开始生效）", out);
    return ESP_OK;
}

static const wb_policy_t kAdvPolicy[] = {
    {.name = "action", .type = WB_T_STR, .required = false, .def_str = "set"},
    {.name = "name", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "mfr", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "raw", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "itvl", .type = WB_T_U32, .required = false, .min = 0, .max = 10240, .def = 100},
    {.name = "connect", .type = WB_T_BOOL, .required = false, .def = 1},
};

static esp_err_t ble_adv(wb_args_t *args, wb_reply_t *reply) {
    const char *action = arg_text(args, "action");

    if (strcmp(action, "stop") == 0) {
        const esp_err_t err = hal_ble_adv_stop();
        if (err != ESP_OK) {
            wb_reply_fail(reply, "adv stop failed (%s)", esp_err_to_name(err));
            return err;
        }
        wb_reply_line(reply, "adv stopped");
        return ESP_OK;
    }

    if (strcmp(action, "start") == 0) {
        const uint16_t itvl = ms_to_itvl(wb_args_u32(args, "itvl"));
        const esp_err_t err = hal_ble_adv_start(itvl, itvl, wb_args_bool(args, "connect"));
        if (err != ESP_OK) {
            wb_reply_fail(reply, "adv start failed (%s)", esp_err_to_name(err));
            return err;
        }
        wb_reply_line(reply, "adv started itvl=%u.%ums connect=%d", (unsigned)(itvl * 5 / 8),
                      (unsigned)((itvl * 625u / 100u) % 10u),
                      wb_args_bool(args, "connect") ? 1 : 0);
        return ESP_OK;
    }

    // 剩下就是 set：raw 直接吃整串 AD，否则按 flags + 厂商数据 + 名字拼
    bf_adv_t set;
    bf_adv_init(&set, s_adv_buf, sizeof(s_adv_buf));
    const char *raw = arg_text(args, "raw");
    if (raw[0] != 0) {
        const int n = hex_to_bytes(raw, s_adv_buf, sizeof(s_adv_buf));
        if (n <= 0) {
            wb_reply_fail(reply, "raw 要偶数长度的十六进制串");
            return ESP_ERR_INVALID_ARG;
        }
        set.len = (size_t)n;
    } else {
        bf_adv_flags(&set, BF_FLAG_GENERAL_DISC | BF_FLAG_NO_BREDR);
        const char *mfr = arg_text(args, "mfr");
        if (mfr[0] != 0) {
            uint16_t company = 0;
            size_t len = 0;
            if (!parse_mfr(mfr, &company, &len)) {
                wb_reply_fail(reply, "mfr 要写成 004c:d0d1 这样");
                return ESP_ERR_INVALID_ARG;
            }
            bf_adv_mfr(&set, company, s_mfr_data, len);
        }
        const char *name = arg_text(args, "name");
        if (name[0] != 0) {
            bf_adv_name(&set, name, true);
        }
    }

    if (bf_adv_len(&set) == 0) {
        wb_reply_fail(reply, "空广播串，给 name / mfr / raw 之一");
        return ESP_ERR_INVALID_ARG;
    }
    const esp_err_t err = hal_ble_adv_set(s_adv_buf, bf_adv_len(&set));
    if (err != ESP_OK) {
        wb_reply_fail(reply, "adv set failed (%s)", esp_err_to_name(err));
        return err;
    }
    bf_hex(s_adv_buf, bf_adv_len(&set), s_hex_text, sizeof(s_hex_text));
    wb_reply_line(reply, "adv len=%u truncated=%d hex=%s", (unsigned)bf_adv_len(&set),
                  set.truncated ? 1 : 0, s_hex_text);
    return ESP_OK;
}

static const wb_policy_t kScanPolicy[] = {
    {.name = "action", .type = WB_T_STR, .required = false, .def_str = "list"},
    {.name = "duration", .type = WB_T_U32, .required = false, .min = 0, .max = 600000, .def = 0},
};

static esp_err_t ble_scan(wb_args_t *args, wb_reply_t *reply) {
    const char *action = arg_text(args, "action");

    if (strcmp(action, "start") == 0) {
        const esp_err_t err = hal_ble_scan_start(wb_args_u32(args, "duration"));
        if (err != ESP_OK) {
            wb_reply_fail(reply, "scan start failed (%s)", esp_err_to_name(err));
            return err;
        }
        wb_reply_line(reply, "scan started duration=%ums（0 表示一直扫）",
                      (unsigned)wb_args_u32(args, "duration"));
        return ESP_OK;
    }

    if (strcmp(action, "stop") == 0) {
        const esp_err_t err = hal_ble_scan_stop();
        if (err != ESP_OK) {
            wb_reply_fail(reply, "scan stop failed (%s)", esp_err_to_name(err));
            return err;
        }
        wb_reply_line(reply, "scan stopped peers=%u", (unsigned)hal_ble_scan_count());
        return ESP_OK;
    }

    if (strcmp(action, "clear") == 0) {
        hal_ble_scan_clear();
        wb_reply_line(reply, "cleared");
        return ESP_OK;
    }

    const size_t n = hal_ble_scan_count();
    wb_reply_line(reply, "peers n=%u", (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        const hal_ble_peer_t *peer = hal_ble_scan_at(i);
        if (peer == NULL) {
            break;
        }
        char text[18];
        bf_addr_format(text, peer->addr);
        bf_hex(peer->data, peer->data_len, s_hex_text, sizeof(s_hex_text));
        wb_reply_line(reply, "%u %s type=%u rssi=%d evt=%u len=%u data=%s", (unsigned)i, text,
                      (unsigned)peer->addr_type, (int)peer->rssi, (unsigned)peer->evt_type,
                      (unsigned)peer->data_len, s_hex_text);
    }
    return ESP_OK;
}

static const wb_method_t kBleMethods[] = {
    {"info", ble_info, "", NULL, 0},
    {"addr", ble_addr, "[addr=random|aa:bb:cc:dd:ee:ff]", kAddrPolicy, 1},
    {"adv", ble_adv,
     "[action=set|start|stop] [name=\"x\"] [mfr=004c:d0d1] [raw=hex] [itvl=100] [connect=1]",
     kAdvPolicy, 6},
    {"scan", ble_scan, "[action=start|stop|list|clear] [duration=0]", kScanPolicy, 2},
};

static const wb_object_t kBleObject = {
    .name = "ble",
    .methods = kBleMethods,
    .n_methods = sizeof(kBleMethods) / sizeof(kBleMethods[0]),
};

const wb_object_t *services_ble_object(void) {
    return &kBleObject;
}

#endif
