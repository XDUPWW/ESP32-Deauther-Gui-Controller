// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include <stdio.h>
#include <string.h>

#include "hal_wifi/hal_wifi.h"
#include "platform/plat_storage.h"
#include "services_private.h"
#include "wbus/wbus.h"
#include "wtarget/wtarget.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wifi_frame/mac.h"

#define RADIO_OWNER "radio"

static hal_rate_t parse_rate(const char *text);

static esp_err_t radio_info(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    hal_wifi_stats_t stats;
    hal_wifi_diag_t diag;
    hal_wifi_stats(&stats);
    hal_wifi_diag(&diag);

    uint8_t mac[6] = {0};
    hal_wifi_mac(mac);

    wb_reply_line(reply, "mac=%02x:%02x:%02x:%02x:%02x:%02x ch=%u owner=%s cc=%s/%u", mac[0],
                  mac[1], mac[2], mac[3], mac[4], mac[5], (unsigned)diag.channel,
                  hal_wifi_channel_owner(), diag.country, (unsigned)diag.country_nchan);
    wb_reply_line(reply, "tx ok=%u err=%u throttled=%u last_err=%d", (unsigned)stats.tx_ok,
                  (unsigned)stats.tx_err, (unsigned)stats.tx_throttled, (int)stats.last_tx_err);
    wb_reply_line(reply, "rx frames=%u dropped=%u too_long=%u promisc=%d filter=0x%x ctrl=0x%x",
                  (unsigned)stats.rx_frames, (unsigned)stats.rx_dropped,
                  (unsigned)stats.rx_too_long, diag.promiscuous ? 1 : 0,
                  (unsigned)diag.filter_mask, (unsigned)diag.ctrl_filter_mask);
    wb_reply_line(reply, "chan granted=%u denied=%u expired=%u tsf=%llu rate=%s",
                  (unsigned)stats.chan_granted, (unsigned)stats.chan_denied,
                  (unsigned)stats.chan_expired, (unsigned long long)hal_wifi_tsf(),
                  hal_wifi_rate_name(hal_wifi_tx_rate()));
    return ESP_OK;
}

static esp_err_t radio_chan(wb_args_t *args, wb_reply_t *reply) {
    const uint8_t channel = (uint8_t)wb_args_u32(args, "ch");
    const uint32_t hold = wb_args_u32(args, "hold");
    esp_err_t err = hal_wifi_channel_acquire(RADIO_OWNER, HAL_CH_PINNED, channel, hold);
    if (err == ESP_ERR_INVALID_STATE) {
        wb_reply_fail(reply, "channel busy with %s", hal_wifi_channel_owner());
        return err;
    }
    if (err != ESP_OK) {
        wb_reply_fail(reply, "set channel failed (%s)", esp_err_to_name(err));
        return err;
    }
    wb_reply_line(reply, "channel=%u owner=%s hold=%ums", (unsigned)hal_wifi_channel(),
                  hal_wifi_channel_owner(), (unsigned)hold);
    return ESP_OK;
}

static esp_err_t radio_release(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    hal_wifi_channel_release(RADIO_OWNER);
    wb_reply_line(reply, "released");
    return ESP_OK;
}

static esp_err_t radio_rate(wb_args_t *args, wb_reply_t *reply) {
    const char *text = wb_args_str(args, "rate");
    const hal_rate_t rate = parse_rate(text);
    if (rate == HAL_RATE_DEFAULT) {
        plat_storage_erase("tx_rate");
        wb_reply_line(reply, "rate=default（下次开机会清掉）");
        return ESP_OK;
    }
    const uint8_t stored = (uint8_t)rate;
    const esp_err_t err = plat_storage_set("tx_rate", &stored, sizeof(stored));
    if (err != ESP_OK) {
        wb_reply_fail(reply, "存 NVS 失败 (%s)", esp_err_to_name(err));
        return err;
    }
    // 官方只支持"init 之后、start 之前"设速率，运行期改不保证生效，这里不做
    wb_reply_line(reply, "saved rate=%s（重启后生效：esp_wifi_start() 之前应用）",
                  hal_wifi_rate_name(rate));
    return ESP_OK;
}

static const wb_policy_t kStaPolicy[] = {
    {.name = "src", .type = WB_T_STR, .required = false, .def_str = "auto"},
};

static esp_err_t radio_sta_list(wb_args_t *args, wb_reply_t *reply) {
    const char *src = wb_args_str(args, "src");
    hal_wifi_sta_t list[HAL_WIFI_STA_MAX];
    size_t n;
    if (strcmp(src, "passive") == 0) {
        n = hal_wifi_sta_list_passive(list, HAL_WIFI_STA_MAX);
    } else if (strcmp(src, "ap") == 0) {
        n = hal_wifi_sta_list_ap(list, HAL_WIFI_STA_MAX);
    } else {
        n = hal_wifi_sta_list(list, HAL_WIFI_STA_MAX);
    }
    if (n > HAL_WIFI_STA_MAX) {
        n = HAL_WIFI_STA_MAX;
    }
    wb_reply_line(reply, "sta src=%s n=%u", src, (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        char mac[18];
        wf_mac_format(mac, list[i].mac);
        wb_reply_line(reply, "%u %s rssi=%d ch=%u frames=%u", (unsigned)i, mac,
                      (int)list[i].rssi, (unsigned)list[i].channel, (unsigned)list[i].frames);
    }
    return ESP_OK;
}

static const wb_policy_t kApPolicy[] = {
    // idx 指向扫描表里的某个 BSS：SSID 和信道都照抄，省得手打中文 SSID
    {.name = "idx", .type = WB_T_U32, .required = false, .min = 0, .max = 64, .def = 0},
    {.name = "ssid", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "pass", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "ch", .type = WB_T_U32, .required = false, .min = 1, .max = 196, .def = 6},
};

static esp_err_t radio_ap(wb_args_t *args, wb_reply_t *reply) {
    const uint32_t idx = wb_args_u32(args, "idx");
    const char *ssid = wb_args_str(args, "ssid");
    const char *pass = wb_args_str(args, "pass");
    uint8_t ch = (uint8_t)wb_args_u32(args, "ch");
    if (idx > 0) {
        // 从扫描表克隆：SSID 带中文时手打容易传坏，直接用表里那份
        const wt_entry_t *e = wt_at(idx - 1);
        if (e == NULL || e->kind != WT_KIND_AP) {
            wb_reply_fail(reply, "idx 不是 AP，先跑 scan.ap");
            return ESP_ERR_INVALID_ARG;
        }
        ssid = e->ssid;
        ch = e->channel;
    }
    if (ssid == NULL || ssid[0] == '\0') {
        wb_reply_fail(reply, "要么给 idx，要么给 ssid");
        return ESP_ERR_INVALID_ARG;
    }
    const esp_err_t err = hal_wifi_ap_start(ssid, pass, ch);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "ap start failed (%s)", esp_err_to_name(err));
        return err;
    }
    wb_reply_line(reply, "ap up ssid_len=%u ch=%u（混杂已关，重开由攻击模块负责）",
                  (unsigned)strlen(ssid), (unsigned)ch);
    return ESP_OK;
}

static esp_err_t radio_ap_stop(wb_args_t *args, wb_reply_t *reply) {
    const esp_err_t err = hal_wifi_ap_stop();
    if (err != ESP_OK) {
        wb_reply_fail(reply, "ap stop failed (%s)", esp_err_to_name(err));
        return err;
    }
    wb_reply_line(reply, "ap down（sta_list 回到被动表）");
    return ESP_OK;
}

static esp_err_t radio_diag(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    hal_wifi_diag_t diag;
    hal_wifi_diag(&diag);
    wb_reply_line(reply, "promisc=%d filter=0x%x ctrl=0x%x ch=%u cc=%s/%u",
                  diag.promiscuous ? 1 : 0, (unsigned)diag.filter_mask,
                  (unsigned)diag.ctrl_filter_mask, (unsigned)diag.channel, diag.country,
                  (unsigned)diag.country_nchan);
    return ESP_OK;
}

static hal_rate_t parse_rate(const char *text) {
    if (strcmp(text, "1m") == 0) return HAL_RATE_1M;
    if (strcmp(text, "2m") == 0) return HAL_RATE_2M;
    if (strcmp(text, "5m5") == 0) return HAL_RATE_5M5;
    if (strcmp(text, "11m") == 0) return HAL_RATE_11M;
    if (strcmp(text, "6m") == 0) return HAL_RATE_6M;
    if (strcmp(text, "9m") == 0) return HAL_RATE_9M;
    if (strcmp(text, "12m") == 0) return HAL_RATE_12M;
    if (strcmp(text, "18m") == 0) return HAL_RATE_18M;
    if (strcmp(text, "24m") == 0) return HAL_RATE_24M;
    if (strcmp(text, "36m") == 0) return HAL_RATE_36M;
    if (strcmp(text, "48m") == 0) return HAL_RATE_48M;
    if (strcmp(text, "54m") == 0) return HAL_RATE_54M;
    if (strcmp(text, "mcs0") == 0) return HAL_RATE_MCS0;
    if (strcmp(text, "mcs1") == 0) return HAL_RATE_MCS1;
    if (strcmp(text, "mcs2") == 0) return HAL_RATE_MCS2;
    if (strcmp(text, "mcs3") == 0) return HAL_RATE_MCS3;
    if (strcmp(text, "mcs4") == 0) return HAL_RATE_MCS4;
    if (strcmp(text, "mcs5") == 0) return HAL_RATE_MCS5;
    if (strcmp(text, "mcs6") == 0) return HAL_RATE_MCS6;
    if (strcmp(text, "mcs7") == 0) return HAL_RATE_MCS7;
    if (strcmp(text, "mcs0sgi") == 0) return HAL_RATE_MCS0_SGI;
    if (strcmp(text, "mcs1sgi") == 0) return HAL_RATE_MCS1_SGI;
    if (strcmp(text, "mcs2sgi") == 0) return HAL_RATE_MCS2_SGI;
    if (strcmp(text, "mcs3sgi") == 0) return HAL_RATE_MCS3_SGI;
    if (strcmp(text, "mcs4sgi") == 0) return HAL_RATE_MCS4_SGI;
    if (strcmp(text, "mcs5sgi") == 0) return HAL_RATE_MCS5_SGI;
    if (strcmp(text, "mcs6sgi") == 0) return HAL_RATE_MCS6_SGI;
    if (strcmp(text, "mcs7sgi") == 0) return HAL_RATE_MCS7_SGI;
    return HAL_RATE_DEFAULT;
}

static bool resolve_mac(wb_args_t *args, const char *key, const uint8_t fallback[6], uint8_t out[6],
                        bool allow_random) {
    const char *text = wb_args_str(args, key);
    if (text[0] == 0) {
        memcpy(out, fallback, 6);
        return true;
    }
    if (allow_random && strcmp(text, "random") == 0) {
        // 两次拼 64 位，够了
        wf_mac_randomize(out, ((uint64_t)esp_random() << 32) | esp_random());
        return true;
    }
    return wf_mac_parse(text, out);
}

static esp_err_t radio_tx_test(wb_args_t *args, wb_reply_t *reply) {
    static const uint8_t kBroadcast[6] = WF_BROADCAST_ADDR_INIT;

    uint8_t ours[6] = {0};
    esp_err_t err = hal_wifi_mac(ours);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "no mac (%s)", esp_err_to_name(err));
        return err;
    }

    uint8_t ta[6];
    uint8_t ra[6];
    if (!resolve_mac(args, "ta", ours, ta, true)) {
        wb_reply_fail(reply, "ta must be aa:bb:cc:dd:ee:ff or random");
        return ESP_ERR_INVALID_ARG;
    }
    if (!resolve_mac(args, "ra", kBroadcast, ra, false)) {
        wb_reply_fail(reply, "ra must be aa:bb:cc:dd:ee:ff");
        return ESP_ERR_INVALID_ARG;
    }

    // 1500 字节压 console 任务那 4 KB 栈上太危险，用静态缓冲。wb 调用都在这一个
    // 任务里，不会有并发。
    static uint8_t s_tx_frame[WF_FRAME_CAP];
    uint8_t *frame = s_tx_frame;
    int len = 0;
    const char *kind = wb_args_str(args, "kind");
    if (strcmp(kind, "bar") == 0) {
        len = wf_build_bar(frame, WF_FRAME_CAP, ra, ta, (uint8_t)wb_args_u32(args, "tid"),
                           (uint16_t)wb_args_u32(args, "ssn"));
    } else if (strcmp(kind, "qosnull") == 0) {
        // QoS Null 是 26 字节、无 payload 的最小载体。如果 blob 的 HT 发送路径是按帧型
        // 门控的（只对带 QoS 位的帧构造 HT-SIG），这一帧能把它逼出来。
        // bssid 也填 RA：Addr1 落在组播地址上才不会等 ACK，否则驱动一轮重传十几次，
        // 每次降速，抓到的全是降速后的帧。
        len = wf_build_null_data(frame, WF_FRAME_CAP, ra, ta, ra, true, false);
    } else if (strcmp(kind, "data") == 0) {
        // ToDS 的 QoS data + LLC/SNAP(EAPOL)：数据帧不受管理帧的基本速率钳制
        uint8_t payload[32];
        const uint8_t eapol[4] = {0x02, 0x01, 0x00, 0x00};
        const int payload_len = wf_build_llc_snap(payload, sizeof(payload), 0x888E, eapol,
                                                  sizeof(eapol));
        if (payload_len <= 0) {
            wb_reply_fail(reply, "llc/snap build failed");
            return ESP_FAIL;
        }
        len = wf_build_data(frame, WF_FRAME_CAP, ta, ta, ta, true, false, true,
                            (uint8_t)wb_args_u32(args, "tid"), payload, (size_t)payload_len);
    } else {
        const char *ssid = wb_args_str(args, "ssid");
        len = wf_build_probe_req(frame, WF_FRAME_CAP, ra, ta, ssid, strlen(ssid));
    }
    if (len <= 0) {
        wb_reply_fail(reply, "build failed");
        return ESP_FAIL;
    }

    char ta_text[18];
    char ra_text[18];
    wf_mac_format(ta_text, ta);
    wf_mac_format(ra_text, ra);

    err = hal_wifi_tx(frame, (uint16_t)len);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "tx failed (%s) len=%d", esp_err_to_name(err), len);
        return err;
    }
    wb_reply_line(reply, "sent kind=%s len=%d ch=%u rate=%s ta=%s ra=%s", kind, len,
                  (unsigned)hal_wifi_channel(), hal_wifi_rate_name(hal_wifi_tx_rate()), ta_text,
                  ra_text);
    return ESP_OK;
}

// bench 要能把帧撑到 1000 字节以上，WF_FRAME_CAP 只有 512，用静态缓冲避免压栈
#define BENCH_FRAME_MAX 1600
static uint8_t s_bench_frame[BENCH_FRAME_MAX];
static uint8_t s_bench_scratch[BENCH_FRAME_MAX];
static uint8_t s_bench_body[BENCH_FRAME_MAX];
static uint8_t s_bench_payload[BENCH_FRAME_MAX];

static esp_err_t radio_tx_bench(wb_args_t *args, wb_reply_t *reply) {
    static const uint8_t kBroadcast[6] = WF_BROADCAST_ADDR_INIT;
    const uint32_t count = wb_args_u32(args, "count");
    const uint32_t gap_ms = wb_args_u32(args, "gap");
    const uint32_t pad = wb_args_u32(args, "pad");
    const bool unicast = wb_args_bool(args, "unicast");
    const char *kind = wb_args_str(args, "kind");

    uint8_t ours[6] = {0};
    esp_err_t err = hal_wifi_mac(ours);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "no mac (%s)", esp_err_to_name(err));
        return err;
    }

    uint8_t *frame = s_bench_frame;
    int len = 0;
    if (strcmp(kind, "bar") == 0) {
        len = wf_build_bar(frame, BENCH_FRAME_MAX, unicast ? ours : kBroadcast, ours, 0, 0);
    } else if (strcmp(kind, "data") == 0) {
        // pad 用来把帧撑大：帧越长，空中时长差异越能反推实际速率
        const uint8_t eapol[4] = {0x02, 0x01, 0x00, 0x00};
        memcpy(s_bench_body, eapol, sizeof(eapol));
        memset(s_bench_body + sizeof(eapol), 0xAB, pad);
        const int payload_len = wf_build_llc_snap(s_bench_payload, BENCH_FRAME_MAX, 0x888E,
                                                  s_bench_body, sizeof(eapol) + pad);
        // ToDS 时 addr1 = 后一个参数（BSSID），传广播就不会等 ACK、也不触发单播节流
        const uint8_t *ra_mac = unicast ? ours : kBroadcast;
        len = wf_build_data(frame, BENCH_FRAME_MAX, ours, ours, ra_mac, true, false, true, 0,
                            s_bench_payload, (size_t)payload_len);
    } else {
        len = wf_build_probe_req(frame, BENCH_FRAME_MAX, unicast ? ours : kBroadcast, ours, "", 0);
    }
    if (len <= 0) {
        wb_reply_fail(reply, "build failed");
        return ESP_FAIL;
    }

    // 先单独量构建耗时，用独立的 scratch，别把要发的帧覆盖掉
    uint8_t *scratch = s_bench_scratch;
    const uint32_t build_start = (uint32_t)(esp_timer_get_time() / 1000);
    volatile int sink = 0;
    for (uint32_t i = 0; i < count; i++) {
        sink += wf_build_probe_req(scratch, BENCH_FRAME_MAX, kBroadcast, ours, "bench", 5);
    }
    const uint32_t build_ms = (uint32_t)(esp_timer_get_time() / 1000) - build_start;
    (void)sink;

    uint32_t ok = 0;
    uint32_t throttled = 0;
    uint32_t failed = 0;
    const uint32_t start = (uint32_t)(esp_timer_get_time() / 1000);
    for (uint32_t i = 0; i < count; i++) {
        // HAL 有最小帧间隔。被挡回来就等一会儿重试，否则 gap=0 时只能统计到第一帧，
        // bench 就测不出真实吞吐了。throttled 记的是"被挡了几次"。
        esp_err_t tx = hal_wifi_tx(frame, (uint16_t)len);
        uint32_t retries = 0;
        while (tx == ESP_ERR_INVALID_STATE && retries < 200) {
            retries++;
            vTaskDelay(pdMS_TO_TICKS(2));
            tx = hal_wifi_tx(frame, (uint16_t)len);
        }
        throttled += retries;
        if (tx == ESP_OK) {
            ok++;
        } else {
            failed++;
        }
        if (gap_ms > 0) {
            vTaskDelay(pdMS_TO_TICKS(gap_ms));
        }
    }
    const uint32_t elapsed = (uint32_t)(esp_timer_get_time() / 1000) - start;
    if (elapsed == 0) {
        wb_reply_fail(reply, "elapsed too short");
        return ESP_FAIL;
    }

    wb_reply_line(reply, "bench kind=%s len=%d count=%u gap=%ums unicast=%d rate=%s", kind, len,
                  (unsigned)count, (unsigned)gap_ms, unicast ? 1 : 0,
                  hal_wifi_rate_name(hal_wifi_tx_rate()));
    wb_reply_line(reply, "inject_ms=%u fps=%u.%u ok=%u throttled=%u err=%u", (unsigned)elapsed,
                  (unsigned)(ok * 1000u / elapsed), (unsigned)((ok * 10000u / elapsed) % 10u),
                  (unsigned)ok, (unsigned)throttled, (unsigned)failed);
    wb_reply_line(reply, "build_us_each=%u.%u", (unsigned)(build_ms * 1000u / count),
                  (unsigned)((build_ms * 10000u / count) % 10u));
    return ESP_OK;
}

static const wb_policy_t kChanPolicy[] = {
    {.name = "ch", .type = WB_T_U32, .required = true, .min = 1, .max = HAL_WIFI_CHANNEL_MAX},
    {.name = "hold", .type = WB_T_U32, .required = false, .min = 0, .max = 600000, .def = 30000},
};

static const wb_policy_t kRatePolicy[] = {
    {.name = "rate", .type = WB_T_STR, .required = true, .def_str = "default"},
};

static const wb_policy_t kBenchPolicy[] = {
    {.name = "count", .type = WB_T_U32, .required = false, .min = 1, .max = 2000, .def = 100},
    {.name = "gap", .type = WB_T_U32, .required = false, .min = 0, .max = 500, .def = 30},
    {.name = "kind", .type = WB_T_STR, .required = false, .def_str = "probe"},
    {.name = "unicast", .type = WB_T_BOOL, .required = false, .def = 0},
    {.name = "pad", .type = WB_T_U32, .required = false, .min = 0, .max = 1440, .def = 0},
};

static const wb_policy_t kTxTestPolicy[] = {
    {.name = "kind", .type = WB_T_STR, .required = false, .def_str = "probe"},
    {.name = "ssid", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "ta", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "ra", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "tid", .type = WB_T_U32, .required = false, .min = 0, .max = 15, .def = 0},
    {.name = "ssn", .type = WB_T_U32, .required = false, .min = 0, .max = 4095, .def = 0},
};

static const wb_method_t kRadioMethods[] = {
    {"info", radio_info, "", NULL, 0},
    {"chan", radio_chan, "ch=1..196 [hold=0..600000]", kChanPolicy, 2},
    {"release", radio_release, "", NULL, 0},
    {"rate", radio_rate,
     "rate=default|1m|2m|5m5|11m|6m..54m|mcs0..mcs7|mcs0sgi..mcs7sgi（重启生效）",
     kRatePolicy, 1},
    {"diag", radio_diag, "", NULL, 0},
    {"sta_list", radio_sta_list, "[src=auto|passive|ap]", kStaPolicy, 1},
    {"ap", radio_ap, "[ssid=\"v2-ap\"] [pass=\"\"] [ch=1..196]", kApPolicy, 3},
    {"ap_stop", radio_ap_stop, "", NULL, 0},
    {"tx_bench", radio_tx_bench,
     "[count=1..2000] [gap=0..500] [kind=probe|bar|data] [unicast=bool] [pad=0..1440]",
     kBenchPolicy, 5},
    {"tx_test", radio_tx_test, "[kind=probe|bar|data|qosnull] [ta=mac|random] [ra=mac] [tid] [ssn]",
     kTxTestPolicy, 6},
};

static const wb_object_t kRadioObject = {
    .name = "radio",
    .methods = kRadioMethods,
    .n_methods = sizeof(kRadioMethods) / sizeof(kRadioMethods[0]),
};

const wb_object_t *services_radio_object(void) {
    return &kRadioObject;
}
