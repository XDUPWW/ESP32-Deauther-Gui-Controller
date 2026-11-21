// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "hal_wifi/hal_wifi.h"

#include <stdlib.h>
#include <string.h>

#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

static const char *TAG = "hal_wifi";

#define RX_QUEUE_DEPTH 16
#define RX_FRAME_MAX 512
#define RX_TASK_STACK 4096
#define RX_TASK_PRIO 6
#define NEVER_EXPIRE 0xFFFFFFFFu

typedef struct {
    uint16_t len;
    int8_t rssi;
    uint8_t channel;
    uint8_t data[RX_FRAME_MAX];
} rx_item_t;

typedef struct {
    bool used;
    char owner[HAL_WIFI_OWNER_MAX];
    hal_ch_mode_t mode;
    uint8_t channel;
    uint32_t expire_ms;
} lease_t;

typedef struct {
    hal_wifi_rx_fn fn;
    void *ctx;
} rx_sub_t;

static QueueHandle_t s_rxq;
static rx_sub_t s_subs[HAL_WIFI_RX_SUBS];
static size_t s_sub_count;
static lease_t s_lease;
static uint8_t s_channel;
static uint32_t s_last_unicast_ms;
static bool s_ap_netif_done;

static volatile uint32_t s_tx_ok;
static volatile uint32_t s_tx_err;
static volatile uint32_t s_tx_throttled;
static volatile uint32_t s_rx_frames;
static volatile uint32_t s_rx_dropped;
static volatile uint32_t s_rx_too_long;
static volatile uint32_t s_chan_granted;
static volatile uint32_t s_chan_denied;
static volatile uint32_t s_chan_expired;
static volatile int32_t s_last_tx_err;

static hal_rate_t s_rate = HAL_RATE_DEFAULT;

static hal_scan_ap_t s_scan[HAL_WIFI_SCAN_MAX];
static uint32_t s_scan_count;

// The closed-source check in libnet80211 rejects forged management frames.
// Overriding it is what makes raw injection work at all.
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    (void)arg;
    (void)arg2;
    (void)arg3;
    return 0;
}

static uint32_t now_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static bool ra_is_group(const uint8_t *frame) {
    return (frame[4] & 0x01) != 0;
}

static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    (void)type;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint16_t len = pkt->rx_ctrl.sig_len;
    if (len == 0 || s_rxq == NULL) {
        return;
    }
    if (len > RX_FRAME_MAX) {
        s_rx_too_long++;
        return;
    }
    rx_item_t item = {
        .len = len,
        .rssi = pkt->rx_ctrl.rssi,
        .channel = pkt->rx_ctrl.channel,
    };
    memcpy(item.data, pkt->payload, len);
    s_rx_frames++;
    if (xQueueSend(s_rxq, &item, 0) != pdTRUE) {
        s_rx_dropped++;
    }
}

static void rx_task(void *arg) {
    (void)arg;
    rx_item_t item;
    for (;;) {
        if (xQueueReceive(s_rxq, &item, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        for (size_t i = 0; i < s_sub_count; i++) {
            if (s_subs[i].fn != NULL) {
                s_subs[i].fn(item.data, item.len, item.rssi, item.channel, s_subs[i].ctx);
            }
        }
    }
}

esp_err_t hal_wifi_init(void) {
    ESP_RETURN_ON_FALSE(esp_netif_init() == ESP_OK, ESP_FAIL, TAG, "netif init");
    const esp_err_t loop_err = esp_event_loop_create_default();
    if (loop_err != ESP_OK && loop_err != ESP_ERR_INVALID_STATE) {
        return loop_err;
    }
    if (esp_netif_create_default_wifi_sta() == NULL) {
        return ESP_FAIL;
    }

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&init_cfg), TAG, "wifi init");
    ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_RAM), TAG, "storage");
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "mode");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "start");
    esp_wifi_disconnect();
    esp_wifi_set_ps(WIFI_PS_NONE);
    hal_wifi_set_country("CN", 13, 20, true);

    s_rxq = xQueueCreate(RX_QUEUE_DEPTH, sizeof(rx_item_t));
    if (s_rxq == NULL) {
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(rx_task, "hal_rx", RX_TASK_STACK, NULL, RX_TASK_PRIO, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "radio ready");
    return ESP_OK;
}

esp_err_t hal_wifi_set_country(const char *cc, uint8_t nchan, int8_t max_dbm, bool manual) {
    wifi_country_t country = {0};
    if (cc != NULL) {
        country.cc[0] = cc[0];
        country.cc[1] = cc[1];
    }
    country.schan = 1;
    country.nchan = (nchan == 0) ? 13 : nchan;
    country.max_tx_power = max_dbm;
    country.policy = manual ? WIFI_COUNTRY_POLICY_MANUAL : WIFI_COUNTRY_POLICY_AUTO;
    return esp_wifi_set_country(&country);
}

esp_err_t hal_wifi_set_band_auto(bool enable) {
#if CONFIG_SOC_WIFI_SUPPORT_5G
    return esp_wifi_set_band_mode(enable ? WIFI_BAND_MODE_AUTO : WIFI_BAND_MODE_2G_ONLY);
#else
    (void)enable;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

esp_err_t hal_wifi_mac(uint8_t out[6]) {
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return esp_wifi_get_mac(WIFI_IF_STA, out);
}

static wifi_phy_rate_t to_phy_rate(hal_rate_t rate) {
    switch (rate) {
        case HAL_RATE_1M:
            return WIFI_PHY_RATE_1M_L;
        case HAL_RATE_2M:
            return WIFI_PHY_RATE_2M_L;
        case HAL_RATE_5M5:
            return WIFI_PHY_RATE_5M_L;
        case HAL_RATE_11M:
            return WIFI_PHY_RATE_11M_L;
        case HAL_RATE_6M:
            return WIFI_PHY_RATE_6M;
        case HAL_RATE_9M:
            return WIFI_PHY_RATE_9M;
        case HAL_RATE_12M:
            return WIFI_PHY_RATE_12M;
        case HAL_RATE_18M:
            return WIFI_PHY_RATE_18M;
        case HAL_RATE_24M:
            return WIFI_PHY_RATE_24M;
        case HAL_RATE_36M:
            return WIFI_PHY_RATE_36M;
        case HAL_RATE_48M:
            return WIFI_PHY_RATE_48M;
        case HAL_RATE_54M:
            return WIFI_PHY_RATE_54M;
        default:
            return WIFI_PHY_RATE_1M_L;
    }
}

esp_err_t hal_wifi_set_tx_rate(hal_rate_t rate) {
    if (rate == HAL_RATE_DEFAULT) {
        return ESP_ERR_INVALID_ARG;
    }
    const esp_err_t err = esp_wifi_config_80211_tx_rate(WIFI_IF_STA, to_phy_rate(rate));
    if (err == ESP_OK) {
        s_rate = rate;
    }
    return err;
}

hal_rate_t hal_wifi_tx_rate(void) {
    return s_rate;
}

const char *hal_wifi_rate_name(hal_rate_t rate) {
    switch (rate) {
        case HAL_RATE_1M:
            return "1m";
        case HAL_RATE_2M:
            return "2m";
        case HAL_RATE_5M5:
            return "5m5";
        case HAL_RATE_11M:
            return "11m";
        case HAL_RATE_6M:
            return "6m";
        case HAL_RATE_9M:
            return "9m";
        case HAL_RATE_12M:
            return "12m";
        case HAL_RATE_18M:
            return "18m";
        case HAL_RATE_24M:
            return "24m";
        case HAL_RATE_36M:
            return "36m";
        case HAL_RATE_48M:
            return "48m";
        case HAL_RATE_54M:
            return "54m";
        default:
            return "default";
    }
}

esp_err_t hal_wifi_channel_acquire(const char *owner, hal_ch_mode_t mode, uint8_t channel,
                                   uint32_t hold_ms) {
    if (owner == NULL || strlen(owner) >= HAL_WIFI_OWNER_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    hal_wifi_channel_tick(now_ms());
    const bool same = s_lease.used && strcmp(s_lease.owner, owner) == 0;
    if (s_lease.used && !same) {
        s_chan_denied++;
        return ESP_ERR_INVALID_STATE;
    }
    s_lease.used = true;
    strncpy(s_lease.owner, owner, sizeof(s_lease.owner) - 1);
    s_lease.mode = mode;
    s_lease.channel = (mode == HAL_CH_PINNED) ? channel : 0;
    s_lease.expire_ms = (hold_ms == 0) ? NEVER_EXPIRE : now_ms() + hold_ms;
    s_chan_granted++;
    if (mode == HAL_CH_PINNED && channel != 0) {
        return hal_wifi_channel_select(owner, channel);
    }
    return ESP_OK;
}

esp_err_t hal_wifi_channel_select(const char *owner, uint8_t channel) {
    if (owner == NULL || !s_lease.used || strcmp(s_lease.owner, owner) != 0) {
        s_chan_denied++;
        return ESP_ERR_INVALID_STATE;
    }
    if (channel == 0 || channel > HAL_WIFI_CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_lease.mode == HAL_CH_PINNED && s_lease.channel != 0 && channel != s_lease.channel) {
        return ESP_ERR_INVALID_ARG;
    }
    const esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err == ESP_OK) {
        s_channel = channel;
    }
    return err;
}

void hal_wifi_channel_release(const char *owner) {
    if (owner != NULL && s_lease.used && strcmp(s_lease.owner, owner) == 0) {
        s_lease.used = false;
    }
}

void hal_wifi_channel_tick(uint32_t now) {
    if (s_lease.used && s_lease.expire_ms != NEVER_EXPIRE && now >= s_lease.expire_ms) {
        s_lease.used = false;
        s_chan_expired++;
    }
}

uint8_t hal_wifi_channel(void) {
    return s_channel;
}

const char *hal_wifi_channel_owner(void) {
    return s_lease.used ? s_lease.owner : "";
}

esp_err_t hal_wifi_tx(const uint8_t *frame, uint16_t len) {
    if (frame == NULL || len < 10) {
        s_tx_err++;
        s_last_tx_err = ESP_ERR_INVALID_ARG;
        return ESP_ERR_INVALID_ARG;
    }
    const bool group = ra_is_group(frame);
    const uint32_t now = now_ms();
    if (!group && s_last_unicast_ms != 0 && (now - s_last_unicast_ms) < HAL_WIFI_UNICAST_GAP_MS) {
        s_tx_throttled++;
        return ESP_ERR_INVALID_STATE;
    }
    if (!group) {
        s_last_unicast_ms = now;
    }

    const esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, (int)len, false);
    if (err == ESP_OK) {
        s_tx_ok++;
        return err;
    }
    s_tx_err++;
    s_last_tx_err = err;
    if (err == ESP_ERR_NO_MEM) {
        ESP_LOGE(TAG, "tx pool gone (0x101) ok=%u err=%u heap=%u", (unsigned)s_tx_ok,
                 (unsigned)s_tx_err, (unsigned)esp_get_free_heap_size());
        vTaskDelay(pdMS_TO_TICKS(20));
        esp_restart();
    }
    return err;
}

esp_err_t hal_wifi_rx_subscribe(hal_wifi_rx_fn fn, void *ctx) {
    if (fn == NULL || s_sub_count >= HAL_WIFI_RX_SUBS) {
        return ESP_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < s_sub_count; i++) {
        if (s_subs[i].fn == fn) {
            s_subs[i].ctx = ctx;
            return ESP_OK;
        }
    }
    s_subs[s_sub_count].fn = fn;
    s_subs[s_sub_count].ctx = ctx;
    s_sub_count++;
    return ESP_OK;
}

esp_err_t hal_wifi_rx_unsubscribe(hal_wifi_rx_fn fn) {
    for (size_t i = 0; i < s_sub_count; i++) {
        if (s_subs[i].fn != fn) {
            continue;
        }
        for (size_t j = i + 1; j < s_sub_count; j++) {
            s_subs[j - 1] = s_subs[j];
        }
        s_sub_count--;
        return ESP_OK;
    }
    return ESP_ERR_NOT_FOUND;
}

esp_err_t hal_wifi_rx_set_filter(bool mgmt, bool ctrl, bool data) {
    wifi_promiscuous_filter_t filter = {0};
    if (mgmt) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    }
    if (ctrl) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    }
    if (data) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    }
    ESP_RETURN_ON_ERROR(esp_wifi_set_promiscuous_filter(&filter), TAG, "type filter");

    // Without this one the driver drops every control frame, whatever the type
    // mask says.
    wifi_promiscuous_filter_t ctrl_filter = {0};
    ctrl_filter.filter_mask = ctrl ? WIFI_PROMIS_CTRL_FILTER_MASK_ALL : 0;
    return esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter);
}

esp_err_t hal_wifi_sniffer_enable(bool enable) {
    if (enable) {
        ESP_RETURN_ON_ERROR(hal_wifi_rx_set_filter(true, true, true), TAG, "filter");
        ESP_RETURN_ON_ERROR(esp_wifi_set_promiscuous_rx_cb(sniffer_cb), TAG, "rx cb");
    }
    return esp_wifi_set_promiscuous(enable);
}

esp_err_t hal_wifi_scan_blocking(uint8_t dwell_ms) {
    wifi_scan_config_t cfg = {
        .show_hidden = true,
    };
    if (dwell_ms > 0) {
        cfg.scan_time.active.min = dwell_ms;
        cfg.scan_time.active.max = dwell_ms;
    }
    esp_err_t err = esp_wifi_scan_start(&cfg, true);
    if (err != ESP_OK) {
        return err;
    }
    uint16_t total = 0;
    err = esp_wifi_scan_get_ap_num(&total);
    if (err != ESP_OK) {
        return err;
    }
    uint16_t want = (total > HAL_WIFI_SCAN_MAX) ? HAL_WIFI_SCAN_MAX : total;
    wifi_ap_record_t *records = (wifi_ap_record_t *)calloc(HAL_WIFI_SCAN_MAX,
                                                           sizeof(wifi_ap_record_t));
    if (records == NULL) {
        return ESP_ERR_NO_MEM;
    }
    uint16_t got = want;
    err = esp_wifi_scan_get_ap_records(&got, records);
    if (err == ESP_OK) {
        s_scan_count = got;
        for (uint16_t i = 0; i < got; i++) {
            memcpy(s_scan[i].bssid, records[i].bssid, 6);
            s_scan[i].channel = records[i].primary;
            s_scan[i].rssi = records[i].rssi;
            s_scan[i].authmode = (uint8_t)records[i].authmode;
            strncpy(s_scan[i].ssid, (const char *)records[i].ssid, sizeof(s_scan[i].ssid) - 1);
            s_scan[i].ssid[sizeof(s_scan[i].ssid) - 1] = '\0';
        }
    }
    free(records);
    return err;
}

uint32_t hal_wifi_scan_count(void) {
    return s_scan_count;
}

const hal_scan_ap_t *hal_wifi_scan_at(uint32_t index) {
    return (index < s_scan_count) ? &s_scan[index] : NULL;
}

esp_err_t hal_wifi_ap_start(const char *ssid, const char *password, uint8_t channel) {
    if (ssid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_ap_netif_done) {
        if (esp_netif_create_default_wifi_ap() == NULL) {
            return ESP_FAIL;
        }
        s_ap_netif_done = true;
    }
    wifi_config_t cfg = {0};
    strncpy((char *)cfg.ap.ssid, ssid, sizeof(cfg.ap.ssid) - 1);
    cfg.ap.ssid_len = (uint8_t)strlen(ssid);
    cfg.ap.channel = (channel == 0) ? 1 : channel;
    cfg.ap.max_connection = 4;
    if (password != NULL && strlen(password) >= 8) {
        strncpy((char *)cfg.ap.password, password, sizeof(cfg.ap.password) - 1);
        cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
    } else {
        cfg.ap.authmode = WIFI_AUTH_OPEN;
    }
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_AP), TAG, "ap mode");
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_AP, &cfg), TAG, "ap config");
    return esp_wifi_start();
}

esp_err_t hal_wifi_ap_stop(void) {
    esp_wifi_stop();
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "sta mode");
    return esp_wifi_start();
}

uint64_t hal_wifi_tsf(void) {
    const int64_t tsf = esp_wifi_get_tsf_time(WIFI_IF_STA);
    return (tsf > 0) ? (uint64_t)tsf : 0;
}

void hal_wifi_stats(hal_wifi_stats_t *out) {
    if (out == NULL) {
        return;
    }
    *out = (hal_wifi_stats_t){
        .tx_ok = s_tx_ok,
        .tx_err = s_tx_err,
        .tx_throttled = s_tx_throttled,
        .rx_frames = s_rx_frames,
        .rx_dropped = s_rx_dropped,
        .rx_too_long = s_rx_too_long,
        .chan_granted = s_chan_granted,
        .chan_denied = s_chan_denied,
        .chan_expired = s_chan_expired,
        .last_tx_err = s_last_tx_err,
    };
}

void hal_wifi_diag(hal_wifi_diag_t *out) {
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    uint8_t primary = 0;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
    if (esp_wifi_get_channel(&primary, &second) == ESP_OK) {
        out->channel = primary;
    }
    esp_wifi_get_promiscuous(&out->promiscuous);
    wifi_promiscuous_filter_t type_filter = {0};
    if (esp_wifi_get_promiscuous_filter(&type_filter) == ESP_OK) {
        out->filter_mask = type_filter.filter_mask;
    }
    wifi_promiscuous_filter_t ctrl_filter = {0};
    if (esp_wifi_get_promiscuous_ctrl_filter(&ctrl_filter) == ESP_OK) {
        out->ctrl_filter_mask = ctrl_filter.filter_mask;
    }
    wifi_country_t country = {0};
    if (esp_wifi_get_country(&country) == ESP_OK) {
        memcpy(out->country, country.cc, 2);
        out->country[2] = '\0';
        out->country_nchan = country.nchan;
    }
}
