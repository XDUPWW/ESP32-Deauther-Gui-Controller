// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

// BLE 侧的文本通道：手机往 RX 特征写一行命令，回复从 TX 特征通知回去。
// 和串口插件是同一个接口，所以屏幕、串口、手机看到的是同一份东西。

#include <stdio.h>
#include <string.h>

#include "esp_log.h"

#include "hal_ble/hal_ble.h"
#include "sdkconfig.h"
#include "transport/transport.h"
#include "wbus/wbus.h"

#if CONFIG_WB_BLE

static const char *TAG = "transport.ble";

typedef struct {
    transport_plugin_t plugin;
    char line[WB_LINE_MAX];
    size_t len;
    bool overflow;
    bool has_pending;
} ble_text_t;

static ble_text_t s_ble;

static void ble_conn(bool connected) {
    // 这个回调在 BLE host 任务里，别在这儿干活，只记状态
    if (!connected) {
        s_ble.len = 0;
        s_ble.has_pending = false;
        s_ble.overflow = false;
    }
}

static bool s_gatt_started;

static esp_err_t ble_start(transport_plugin_t *self) {
    (void)self;
    // BLE host 跟控制器同步是异步的，启动这会儿多半还没好。
    // 不在这儿等，交给 poll 轮询，别把开机卡住几秒。
    return ESP_OK;
}

// 返回 true 表示还没轮到读数据，本轮先返回
static bool ble_lazy_start(void) {
    if (s_gatt_started) {
        return false;
    }
    if (!hal_ble_ready()) {
        return true;
    }
    const esp_err_t err = hal_ble_gatt_start("AirBench", ble_conn);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "gatt up");
    } else {
        ESP_LOGE(TAG, "gatt start failed (%s)", esp_err_to_name(err));
    }
    s_gatt_started = true;
    return true;
}

static void ble_stop(transport_plugin_t *self) {
    (void)self;
    hal_ble_adv_stop();
}

static void ble_line_out(transport_plugin_t *self, const char *line) {
    (void)self;
    if (line == NULL || !hal_ble_gatt_connected()) {
        return;
    }
    // 手机没订阅通知、或者发失败，都直接丢。BLE 是辅助通道，不能因为它卡住串口。
    char buf[WB_LINE_MAX + 2];
    const int n = snprintf(buf, sizeof(buf), "%s\n", line);
    if (n > 0) {
        hal_ble_gatt_send(buf);
    }
}

static void ble_poll(transport_plugin_t *self, uint32_t now_ms) {
    (void)now_ms;
    ble_text_t *s = (ble_text_t *)self;

    if (ble_lazy_start()) {
        return;
    }

    // 队列满时不读新字节，未送达的那行留着下轮重试
    if (s->has_pending) {
        if (transport_submit(s->line) != ESP_OK) {
            return;
        }
        s->has_pending = false;
        s->len = 0;
    }

    uint8_t chunk[64];
    const int n = hal_ble_gatt_read(chunk, sizeof(chunk));
    for (int i = 0; i < n; i++) {
        const char c = (char)chunk[i];
        if (c == '\r' || c == '\n') {
            if (s->overflow) {
                transport_out("ERR syntax: line too long");
                s->overflow = false;
                s->len = 0;
                continue;
            }
            if (s->len == 0) {
                continue;
            }
            s->line[s->len] = 0;
            if (transport_submit(s->line) != ESP_OK) {
                s->has_pending = true;
                return;
            }
            s->len = 0;
            continue;
        }
        if (s->len + 1 >= sizeof(s->line)) {
            s->overflow = true;
            continue;
        }
        s->line[s->len++] = c;
    }
}

transport_plugin_t *transport_ble_text(void) {
    s_ble.plugin.name = "ble";
    s_ble.plugin.start = ble_start;
    s_ble.plugin.stop = ble_stop;
    s_ble.plugin.poll = ble_poll;
    s_ble.plugin.line_out = ble_line_out;
    s_ble.plugin.ctx = &s_ble;
    return &s_ble.plugin;
}

#endif
