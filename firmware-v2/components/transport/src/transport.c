// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "transport/transport.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "wbus/wbus.h"

static const char *TAG = "transport";

#define PLUGIN_MAX 4
#define QUEUE_DEPTH 6
#define TASK_STACK 5120
#define TASK_PRIORITY 5
#define POLL_PERIOD_MS 5

static transport_plugin_t *s_plugins[PLUGIN_MAX];
static size_t s_plugin_count;
static QueueHandle_t s_inbox;

static void broadcast(void *ctx, const char *line) {
    (void)ctx;
    for (size_t i = 0; i < s_plugin_count; i++) {
        if (s_plugins[i]->line_out != NULL) {
            s_plugins[i]->line_out(s_plugins[i], line);
        }
    }
}

static void on_event(void *ctx, const char *line) {
    (void)ctx;
    broadcast(NULL, line);
}

void transport_out(const char *line) {
    if (line != NULL) {
        broadcast(NULL, line);
    }
}

esp_err_t transport_add(transport_plugin_t *plugin) {
    if (plugin == NULL || s_plugin_count >= PLUGIN_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    s_plugins[s_plugin_count++] = plugin;
    if (plugin->start != NULL) {
        return plugin->start(plugin);
    }
    return ESP_OK;
}

esp_err_t transport_submit(const char *line) {
    if (line == NULL || s_inbox == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    char copy[WB_LINE_MAX];
    strncpy(copy, line, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    return (xQueueSend(s_inbox, copy, 0) == pdTRUE) ? ESP_OK : ESP_ERR_TIMEOUT;
}

static void transport_task(void *arg) {
    (void)arg;
    char line[WB_LINE_MAX];
    for (;;) {
        const uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        for (size_t i = 0; i < s_plugin_count; i++) {
            if (s_plugins[i]->poll != NULL) {
                s_plugins[i]->poll(s_plugins[i], now);
            }
        }
        while (xQueueReceive(s_inbox, line, 0) == pdTRUE) {
            wb_call_line(line, broadcast, NULL);
        }
        vTaskDelay(pdMS_TO_TICKS(POLL_PERIOD_MS));
    }
}

esp_err_t transport_start(void) {
    if (s_inbox != NULL) {
        return ESP_OK;
    }
    s_inbox = xQueueCreate(QUEUE_DEPTH, WB_LINE_MAX);
    if (s_inbox == NULL) {
        ESP_LOGE(TAG, "inbox alloc failed");
        return ESP_ERR_NO_MEM;
    }
    // 所有对象的事件都往所有插件上广播，界面和串口看到的是同一份
    wb_subscribe("*", on_event, NULL);
    if (xTaskCreate(transport_task, "transport", TASK_STACK, NULL, TASK_PRIORITY, NULL) != pdPASS) {
        ESP_LOGE(TAG, "task create failed");
        vQueueDelete(s_inbox);
        s_inbox = NULL;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
