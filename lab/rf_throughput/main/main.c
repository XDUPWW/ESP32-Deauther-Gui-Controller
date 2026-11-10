// Lab-only AP/STA throughput probe.
//
// Purpose: create a *real* 802.11n link with an active Block Ack session, so the
// DELBA attack can be measured instead of guessed at. Two boards run this
// firmware (one "ap", one "sta"), a third board runs the attack firmware.
//
//   ap <ssid> [channel]   start a softAP, listen on TCP 4444, stream data
//   sta <ssid>            join that softAP and read from TCP 4444 as fast as
//                         possible
//   rate                  1 kibyte / second lines, printed as RATE tx=/rx=
//   status                connection state
//
// Everything here is test scaffolding; it is deliberately not part of the
// wireless-attack firmware.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "nvs.h"
#include "nvs_flash.h"

#define TAG "lab"
#define TCP_PORT 4444
#define CHUNK 1448

static volatile uint32_t s_bytes;
static volatile uint32_t s_last_bytes;
static volatile bool s_running;

static void rate_task(void* arg) {
    (void)arg;
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        const uint32_t now = s_bytes;
        const uint32_t delta = now - s_last_bytes;
        s_last_bytes = now;
        printf("RATE kib=%u total=%u\n", (unsigned)(delta / 1024), (unsigned)(now / 1024));
        fflush(stdout);
    }
}

static void ap_stream(int fd) {
    static uint8_t buf[CHUNK];
    memset(buf, 0xA5, sizeof(buf));
    s_running = true;
    while (s_running) {
        const int n = send(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            printf("AP peer gone (%d)\n", n);
            break;
        }
        s_bytes += (uint32_t)n;
    }
    s_running = false;
}

static void ap_task(void* arg) {
    (void)arg;
    const int srv = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(TCP_PORT);
    const int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        printf("AP bind failed\n");
        vTaskDelete(NULL);
        return;
    }
    listen(srv, 2);
    printf("AP listening on %d\n", TCP_PORT);
    while (true) {
        const int fd = accept(srv, NULL, NULL);
        if (fd < 0) {
            continue;
        }
        printf("AP client connected\n");
        ap_stream(fd);
        close(fd);
    }
}

static uint32_t s_gateway;

static void sta_task(void* arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(500));
    while (true) {
        const int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(TCP_PORT);
        addr.sin_addr.s_addr = s_gateway;
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            printf("STA connect failed, retrying\n");
            close(fd);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        printf("STA connected\n");
        static uint8_t buf[4096];
        while (true) {
            const int n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                printf("STA stream ended (%d)\n", n);
                break;
            }
            s_bytes += (uint32_t)n;
        }
        close(fd);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

static void on_wifi_event(void* arg, esp_event_base_t base, int32_t id, void* data) {
    (void)arg;
    (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_AP_START) {
        printf("WIFI ap started\n");
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        printf("WIFI sta disconnected, retrying\n");
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t* got = (const ip_event_got_ip_t*)data;
        s_gateway = got->ip_info.gw.addr;
        printf("WIFI sta got ip " IPSTR "\n", IP2STR(&got->ip_info.ip));
        static bool started;
        if (!started) {
            started = true;
            xTaskCreate(sta_task, "sta", 4096, NULL, 5, NULL);
        }
    }
}

static void start_ap(const char* ssid, int channel) {
    esp_netif_create_default_wifi_ap();
    wifi_config_t cfg = {0};
    strncpy((char*)cfg.ap.ssid, ssid, sizeof(cfg.ap.ssid) - 1);
    cfg.ap.ssid_len = (uint8_t)strlen(ssid);
    cfg.ap.channel = (uint8_t)channel;
    cfg.ap.max_connection = 2;
    cfg.ap.authmode = WIFI_AUTH_OPEN;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_NONE);
    xTaskCreate(ap_task, "ap", 4096, NULL, 5, NULL);
}

static void start_sta(const char* ssid) {
    esp_netif_create_default_wifi_sta();
    wifi_config_t cfg = {0};
    strncpy((char*)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid) - 1);
    cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_NONE);
    printf("WIFI sta joining %s\n", ssid);
}

static char s_line[96];
static size_t s_len;

// The role is persisted so the board can be re-attached at any time: opening the
// port resets the ESP32, and the link has to come back up on its own.
static void config_save(const char* role, const char* ssid, int channel) {
    nvs_handle_t h;
    if (nvs_open("lab", NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    nvs_set_str(h, "role", role);
    nvs_set_str(h, "ssid", ssid);
    nvs_set_i32(h, "ch", channel);
    nvs_commit(h);
    nvs_close(h);
}

static void run_command(char* line) {
    char* cmd = strtok(line, " ");
    if (cmd == nullptr) {
        return;
    }
    if (strcmp(cmd, "ap") == 0) {
        char* ssid = strtok(nullptr, " ");
        char* ch = strtok(nullptr, " ");
        if (ssid == nullptr) {
            printf("ERR usage: ap <ssid> [channel]\n");
            return;
        }
        const int channel = ch ? atoi(ch) : 1;
        config_save("ap", ssid, channel);
        start_ap(ssid, channel);
    } else if (strcmp(cmd, "sta") == 0) {
        char* ssid = strtok(nullptr, " ");
        if (ssid == nullptr) {
            printf("ERR usage: sta <ssid>\n");
            return;
        }
        config_save("sta", ssid, 1);
        start_sta(ssid);
    } else if (strcmp(cmd, "clear") == 0) {
        nvs_handle_t h;
        if (nvs_open("lab", NVS_READWRITE, &h) == ESP_OK) {
            nvs_erase_all(h);
            nvs_commit(h);
            nvs_close(h);
        }
        printf("OK cleared, reboot to stay idle\n");
    } else if (strcmp(cmd, "status") == 0) {
        printf("STATUS bytes=%u kib=%u\n", (unsigned)s_bytes, (unsigned)(s_bytes / 1024));
        fflush(stdout);
    } else {
        printf("ERR unknown '%s' (ap/sta/status)\n", cmd);
    }
}

void app_main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    esp_err_t err = nvs_flash_init();
    if (err != ESP_OK) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_wifi_event, NULL));
    xTaskCreate(rate_task, "rate", 3072, NULL, 4, NULL);

    nvs_handle_t h;
    char role[8] = {0};
    char ssid[33] = {0};
    size_t len = sizeof(role);
    if (nvs_open("lab", NVS_READONLY, &h) == ESP_OK) {
        len = sizeof(role);
        const bool have_role = nvs_get_str(h, "role", role, &len) == ESP_OK;
        len = sizeof(ssid);
        if (have_role && nvs_get_str(h, "ssid", ssid, &len) == ESP_OK) {
            int32_t ch = 1;
            nvs_get_i32(h, "ch", &ch);
            printf("INFO auto %s ssid=%s ch=%d\n", role, ssid, (int)ch);
            if (strcmp(role, "ap") == 0) {
                start_ap(ssid, (int)ch);
            } else if (strcmp(role, "sta") == 0) {
                start_sta(ssid);
            }
        }
        nvs_close(h);
    }
    printf("INFO lab rf_throughput ready (ap <ssid> [ch] / sta <ssid> / clear / status)\n");

    while (true) {
        uint8_t c;
        const int n = fread(&c, 1, 1, stdin);
        if (n != 1) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            s_line[s_len] = 0;
            if (s_len > 0) {
                run_command(s_line);
            }
            s_len = 0;
        } else if (s_len < sizeof(s_line) - 1) {
            s_line[s_len++] = (char)c;
        }
    }
}
