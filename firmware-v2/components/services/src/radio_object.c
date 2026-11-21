// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include <stdio.h>
#include <string.h>

#include "hal_wifi/hal_wifi.h"
#include "services_private.h"
#include "wbus/wbus.h"
#include "esp_random.h"
#include "wifi_frame/frame_build.h"
#include "wifi_frame/frames.h"
#include "wifi_frame/mac.h"

#define RADIO_OWNER "radio"

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

    const char *rate_text = wb_args_str(args, "rate");
    if (strcmp(rate_text, "keep") != 0) {
        const hal_rate_t rate = parse_rate(rate_text);
        err = hal_wifi_set_tx_rate((rate == HAL_RATE_DEFAULT) ? HAL_RATE_1M : rate);
        if (err != ESP_OK) {
            wb_reply_fail(reply, "rate not accepted (%s)", esp_err_to_name(err));
            return err;
        }
    }

    uint8_t frame[WF_FRAME_CAP];
    int len = 0;
    const char *kind = wb_args_str(args, "kind");
    if (strcmp(kind, "bar") == 0) {
        len = wf_build_bar(frame, sizeof(frame), ra, ta, (uint8_t)wb_args_u32(args, "tid"),
                           (uint16_t)wb_args_u32(args, "ssn"));
    } else {
        const char *ssid = wb_args_str(args, "ssid");
        len = wf_build_probe_req(frame, sizeof(frame), ra, ta, ssid, strlen(ssid));
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

static const wb_policy_t kChanPolicy[] = {
    {.name = "ch", .type = WB_T_U32, .required = true, .min = 1, .max = HAL_WIFI_CHANNEL_MAX},
    {.name = "hold", .type = WB_T_U32, .required = false, .min = 0, .max = 600000, .def = 30000},
};

static const wb_policy_t kTxTestPolicy[] = {
    {.name = "kind", .type = WB_T_STR, .required = false, .def_str = "probe"},
    {.name = "ssid", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "ta", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "ra", .type = WB_T_STR, .required = false, .def_str = ""},
    {.name = "rate", .type = WB_T_STR, .required = false, .def_str = "keep"},
    {.name = "tid", .type = WB_T_U32, .required = false, .min = 0, .max = 15, .def = 0},
    {.name = "ssn", .type = WB_T_U32, .required = false, .min = 0, .max = 4095, .def = 0},
};

static const wb_method_t kRadioMethods[] = {
    {"info", radio_info, "", NULL, 0},
    {"chan", radio_chan, "ch=1..196 [hold=0..600000]", kChanPolicy, 2},
    {"release", radio_release, "", NULL, 0},
    {"diag", radio_diag, "", NULL, 0},
    {"tx_test", radio_tx_test, "[kind=probe|bar] [ta=mac|random] [ra=mac] [rate=1m..54m|keep]",
     kTxTestPolicy, 7},
};

static const wb_object_t kRadioObject = {
    .name = "radio",
    .methods = kRadioMethods,
    .n_methods = sizeof(kRadioMethods) / sizeof(kRadioMethods[0]),
};

const wb_object_t *services_radio_object(void) {
    return &kRadioObject;
}
