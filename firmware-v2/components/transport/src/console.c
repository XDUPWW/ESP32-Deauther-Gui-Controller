// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "transport/console.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "platform/plat_console.h"
#include "platform/plat_display.h"

static const char *TAG = "transport";

#define CONSOLE_LINE_MAX 128
#define QUEUE_DEPTH 4
#define TASK_STACK 4096
#define READ_TIMEOUT_MS 20
#define CONSOLE_EXTRA_MAX 8

typedef struct {
    const char *verb;
    transport_command_fn fn;
} extra_cmd_t;

static QueueHandle_t s_inbox;
static transport_mirror_fn s_mirror;
static void *s_mirror_ctx;
static extra_cmd_t s_extra[CONSOLE_EXTRA_MAX];
static size_t s_extra_count;

static void out_line(const char *line) {
    plat_console_write(line);
    plat_console_write("\r\n");
    if (s_mirror != NULL) {
        s_mirror(s_mirror_ctx, line);
    }
}

void transport_console_out(const char *line) {
    if (line != NULL) {
        out_line(line);
    }
}

static void out_fmt(const char *fmt, ...) {
    char line[CONSOLE_LINE_MAX * 2];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    out_line(line);
}

static void print_help(void) {
    out_line("PING                       liveness check");
    out_line("INFO                       firmware, heap, uptime");
    out_line("TOUCH                      one raw touch sample");
    out_line("HELP                       this text");
}

static void execute(char *line) {
    char *verb = line;
    while (*verb == ' ') {
        verb++;
    }
    if (*verb == '\0') {
        return;
    }
    char *rest = verb;
    while (*rest != '\0' && *rest != ' ') {
        rest++;
    }
    if (*rest == ' ') {
        *rest++ = '\0';
        while (*rest == ' ') {
            rest++;
        }
    }

    for (char *p = verb; *p != '\0'; p++) {
        *p = (char)toupper((unsigned char)*p);
    }

    if (strcmp(verb, "PING") == 0) {
        out_fmt("PONG ms=%u", (unsigned)(esp_timer_get_time() / 1000));
    } else if (strcmp(verb, "INFO") == 0) {
        out_fmt("IDF=%s", esp_get_idf_version());
        out_fmt("HEAP=%u MIN=%u", (unsigned)esp_get_free_heap_size(),
                (unsigned)esp_get_minimum_free_heap_size());
        out_fmt("UPTIME_S=%u", (unsigned)(esp_timer_get_time() / 1000000));
    } else if (strcmp(verb, "TOUCH") == 0) {
        int raw_x = 0;
        int raw_y = 0;
        const bool pressed = plat_touch_read(&raw_x, &raw_y);
        out_fmt("TOUCH raw_x=%d raw_y=%d pressed=%d", raw_x, raw_y, pressed ? 1 : 0);
    } else if (strcmp(verb, "HELP") == 0) {
        print_help();
        for (size_t i = 0; i < s_extra_count; i++) {
            out_fmt("%-26s (registered)", s_extra[i].verb);
        }
    } else {
        for (size_t i = 0; i < s_extra_count; i++) {
            if (strcmp(verb, s_extra[i].verb) == 0) {
                const int rc = s_extra[i].fn(rest);
                if (rc == 0) {
                    out_fmt("OK %s", verb);
                } else {
                    out_fmt("ERR %s: %d", verb, rc);
                }
                return;
            }
        }
        out_fmt("ERR unknown command: %s", verb);
        return;
    }
    out_fmt("OK %s", verb);
}

int transport_console_register(const char *verb, transport_command_fn fn) {
    if (verb == NULL || fn == NULL || s_extra_count >= CONSOLE_EXTRA_MAX) {
        return -1;
    }
    s_extra[s_extra_count].verb = verb;
    s_extra[s_extra_count].fn = fn;
    s_extra_count++;
    return 0;
}

int transport_console_submit(const char *line) {
    if (s_inbox == NULL || line == NULL) {
        return -1;
    }
    char copy[CONSOLE_LINE_MAX];
    strncpy(copy, line, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    return (xQueueSend(s_inbox, copy, 0) == pdTRUE) ? 0 : -1;
}

void transport_console_set_mirror(transport_mirror_fn fn, void *ctx) {
    s_mirror = fn;
    s_mirror_ctx = ctx;
}

static void console_task(void *arg) {
    (void)arg;
    char line[CONSOLE_LINE_MAX];
    size_t len = 0;
    bool overflow = false;
    uint8_t chunk[64];

    for (;;) {
        const int n = plat_console_read(chunk, sizeof(chunk), READ_TIMEOUT_MS);
        for (int i = 0; i < n; i++) {
            const char c = (char)chunk[i];
            if (c == '\r' || c == '\n') {
                if (overflow) {
                    out_line("ERR line too long");
                    overflow = false;
                    len = 0;
                    continue;
                }
                if (len == 0) {
                    continue;
                }
                line[len] = '\0';
                execute(line);
                len = 0;
                continue;
            }
            if (c == '\b' || c == 0x7F) {
                if (len > 0) {
                    len--;
                }
                continue;
            }
            if ((unsigned char)c < 0x20) {
                continue;
            }
            if (len + 1 >= sizeof(line)) {
                overflow = true;
                len = 0;
                continue;
            }
            line[len++] = c;
        }

        char queued[CONSOLE_LINE_MAX];
        while (xQueueReceive(s_inbox, queued, 0) == pdTRUE) {
            execute(queued);
        }
    }
}

void transport_console_start(void) {
    if (s_inbox != NULL) {
        return;
    }
    s_inbox = xQueueCreate(QUEUE_DEPTH, CONSOLE_LINE_MAX);
    if (s_inbox == NULL) {
        ESP_LOGE(TAG, "inbox alloc failed");
        return;
    }
    if (xTaskCreate(console_task, "console", TASK_STACK, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "console task failed");
        vQueueDelete(s_inbox);
        s_inbox = NULL;
    }
}
