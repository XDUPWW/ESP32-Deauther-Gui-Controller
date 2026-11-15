// Lab-only AP/STA throughput probe.
//
// Purpose: create a *real* 802.11n link with an active Block Ack session, so the
// DELBA attack can be measured instead of guessed at. Two boards run this
// firmware (one "ap", one "sta"), a third board runs the attack firmware.
//
//   ap <ssid> [channel]   start a softAP, listen on TCP 4444, stream data
//   sta <ssid>            join that softAP and read from TCP 4444 as fast as
//                         possible
//   ps <0|1|2>            power save: 0 none / 1 min-modem (DTIM) / 2 max-modem.
//                         Needed by the TIM tests: only a station that sleeps
//                         honours the TIM element, and only then does a forged
//                         TIM change what it receives.
//   btm <0|1>             advertise/accept 802.11v BSS Transition Management
//                         (needs CONFIG_ESP_WIFI_11KV_SUPPORT=y). The station
//                         then answers a forged BTM Request with a BTM Response,
//                         which is what the attack board counts as `wnmresp`.
//   sniff <ch>            beacon sniffer: print the TIM element of every beacon on
//                         that channel (the forged clone vs the real AP). Needed to
//                         check frame bytes when the C5 capture pipe is not running.
//   sniffpoll <ch>        PS-Poll / Null Data sniffer: prints the AID carried in
//                         the PS-Poll Duration/ID field and the PM bit of Null
//                         Data frames. This is how the PS-Poll attack is checked
//                         on the air (the C5 capture pipe may not be running).
//   sniffstop             end the dump and report how many beacons were seen
//   rate                  1 kibyte / second lines, printed as RATE tx=/rx=
//   status                connection state + ps/btm
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
static volatile uint32_t s_sniff_frames;
static volatile uint32_t s_sniff_polls;
static volatile uint32_t s_ctrl_sub[16];  // control frames by subtype, per run
static bool s_sniffing;
static wifi_ps_type_t s_ps = WIFI_PS_NONE;
static bool s_btm;
static char s_sta_ssid[33] = {0};

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

// Beacon dump for TIM verification. Runs in the Wi-Fi task, so keep it small and
// allocation free: one line per beacon, TIM element body in hex.
static void sniff_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    if (type != WIFI_PKT_MGMT || pkt == NULL) {
        return;
    }
    const uint8_t* f = pkt->payload;
    const int len = pkt->rx_ctrl.sig_len;
    if (len < 38 || (f[0] & 0xF0) != 0x80) {
        return;  // beacons only
    }
    const uint8_t* p = f + 36;
    const uint8_t* end = f + len;
    while (p + 2 <= end) {
        const int id = p[0];
        const int ie_len = p[1];
        if (p + 2 + ie_len > end) {
            return;
        }
        if (id == 5) {
            s_sniff_frames++;
            printf("BEACON ta=%02X:%02X:%02X:%02X:%02X:%02X seq=%u%u interval=%u tim=",
                   f[10], f[11], f[12], f[13], f[14], f[15], (unsigned)(f[22] >> 4),
                   (unsigned)(f[23] & 0x0F), (unsigned)(f[32] | (f[33] << 8)));
            for (int i = 0; i < ie_len; i++) {
                printf("%02X", p[2 + i]);
            }
            printf("\n");
            return;
        }
        p += 2 + ie_len;
    }
}

// PS-Poll (control 10) / Null Data (data 4, QoS Null 12) dump. Both are 802.11
// header only, so a few bytes decode them completely:
//   * PS-Poll Duration/ID = 0xC000 | AID (802.11-2020 §9.2.4.2)
//   * Null Data Frame Control byte 1 bit 4 = Power Management
// The driver rewrites Duration for some frame types (measured on RTS: 990..1102 us
// instead of the value we wrote), so whether the AID survives is exactly what this
// mode is for.
static void sniff_poll_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    if (pkt == NULL) {
        return;
    }
    const uint8_t* f = pkt->payload;
    const int len = pkt->rx_ctrl.sig_len;
    if (len < 20) {
        return;
    }
    const int ftype = (f[0] >> 2) & 0x03;
    const int subtype = (f[0] >> 4) & 0x0F;

    if (type == WIFI_PKT_CTRL) {
        if (subtype >= 0 && subtype < 16) {
            s_ctrl_sub[subtype]++;
        }
        if (ftype == 1 && subtype == 10) {
            const unsigned dur = (unsigned)(f[2] | (f[3] << 8));
            s_sniff_polls++;
            printf("POLL ra=%02X:%02X:%02X:%02X:%02X:%02X ta=%02X:%02X:%02X:%02X:%02X:%02X"
                   " dur=0x%04X aid=%u len=%d\n",
                   f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11], f[12], f[13], f[14], f[15],
                   dur, (unsigned)(dur & 0x3FFF), len);
        }
        return;
    }
    if (type == WIFI_PKT_DATA && ftype == 2 && (subtype == 4 || subtype == 12)) {
        printf("NULL ta=%02X:%02X:%02X:%02X:%02X:%02X ra=%02X:%02X:%02X:%02X:%02X:%02X"
               " pm=%d tods=%d qos=%d len=%d\n",
               f[10], f[11], f[12], f[13], f[14], f[15], f[4], f[5], f[6], f[7], f[8], f[9],
               (f[1] >> 4) & 0x01, f[1] & 0x01, subtype == 12 ? 1 : 0, len);
    }
}

static void sniff_stop(void) {
    if (!s_sniffing) {
        return;
    }
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    s_sniffing = false;
    printf("OK sniff end frames=%u polls=%u ctrl=", (unsigned)s_sniff_frames,
           (unsigned)s_sniff_polls);
    // Subtype histogram: 11 should be RTS (a CTRLTEST run) and 10 PS-Poll. A zero
    // everywhere means the control filter is not letting anything through, which is
    // a property of the *sniffer*, not of the injection under test.
    for (int i = 0; i < 16; i++) {
        printf("%u", (unsigned)s_ctrl_sub[i]);
        if (i != 15) {
            printf(",");
        }
        s_ctrl_sub[i] = 0;
    }
    printf("\n");
}

static void start_sniff(int channel) {
    sniff_stop();
    esp_wifi_stop();
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_NONE);
    // A station that still thinks it is connecting refuses a channel change; a
    // fresh boot tries to join whenever a role is stored in NVS.
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(100));
    const esp_err_t err = esp_wifi_set_channel((uint8_t)channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        printf("ERR set channel %d: %d\n", channel, (int)err);
        return;
    }
    wifi_promiscuous_filter_t filter = {0};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(sniff_cb);
    esp_wifi_set_promiscuous(true);
    s_sniff_frames = 0;
    s_sniff_polls = 0;
    s_sniffing = true;
    printf("OK sniff ch=%d (beacon TIM dump, `sniffstop` ends it)\n", channel);
}

// PS-Poll / PM-bit sniffer: management noise is filtered out, control and data are
// both needed (PS-Poll is control, Null Data is data), and the second-stage control
// filter has to be widened explicitly -- its default drops every control frame.
static void start_sniff_poll(int channel) {
    sniff_stop();
    // Works on top of a running role: an AP already owns its channel, and tearing
    // the interface down just to sniff would remove the very AP that produces the
    // traffic under test. A board with no role gets a bare STA interface instead.
    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_NULL) {
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_start());
        esp_wifi_set_ps(WIFI_PS_NONE);
        esp_wifi_disconnect();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    const esp_err_t err = esp_wifi_set_channel((uint8_t)channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        // An AP owns its channel and refuses the change; sniffing on that AP then
        // happens on the channel it was started with, which is the useful case
        // (the traffic under test is its own).
        if (mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA) {
            printf("NOTE sniff on the AP's own channel (set_channel %d refused: %d)\n",
                   channel, (int)err);
        } else {
            printf("ERR set channel %d: %d\n", channel, (int)err);
            return;
        }
    }
    wifi_promiscuous_filter_t filter = {0};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_CTRL | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    wifi_promiscuous_filter_t ctrl_filter = {0};
    ctrl_filter.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter);
    esp_wifi_set_promiscuous_rx_cb(sniff_poll_cb);
    esp_wifi_set_promiscuous(true);
    s_sniff_frames = 0;
    s_sniff_polls = 0;
    for (int i = 0; i < 16; i++) {
        s_ctrl_sub[i] = 0;
    }
    s_sniffing = true;
    printf("OK sniffpoll ch=%d (PS-Poll AID / Null Data PM dump, `sniffstop` ends it)\n",
           channel);
}

static void on_wifi_event(void* arg, esp_event_base_t base, int32_t id, void* data) {
    (void)arg;
    (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_AP_START) {
        printf("WIFI ap started\n");
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        // Only join when a role is actually configured. An unconditional connect()
        // leaves the interface "connecting", and a connecting station refuses
        // esp_wifi_set_channel() -- which killed the sniffer modes on the C5.
        if (s_sta_ssid[0] != 0) {
            esp_wifi_connect();
        }
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t* disc = (const wifi_event_sta_disconnected_t*)data;
        printf("WIFI sta disconnected reason=%d, retrying\n", disc != NULL ? disc->reason : -1);
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

// Every STA setting goes through here so `ps` / `btm` can be changed at runtime
// without losing the SSID: the driver keeps the last configuration, and a
// disconnect/reconnect is enough to apply a new one.
static void apply_sta_cfg(void) {
    wifi_config_t cfg = {0};
    strncpy((char*)cfg.sta.ssid, s_sta_ssid, sizeof(cfg.sta.ssid) - 1);
    cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
#if CONFIG_ESP_WIFI_11KV_SUPPORT
    cfg.sta.rm_enabled = s_btm ? 1 : 0;
    cfg.sta.btm_enabled = s_btm ? 1 : 0;
#else
    if (s_btm) {
        printf("ERR this build has no 11kv support (CONFIG_ESP_WIFI_11KV_SUPPORT)\n");
    }
#endif
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    esp_wifi_set_ps(s_ps);
}

static void start_sta(const char* ssid) {
    esp_netif_create_default_wifi_sta();
    strncpy(s_sta_ssid, ssid, sizeof(s_sta_ssid) - 1);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    apply_sta_cfg();
    ESP_ERROR_CHECK(esp_wifi_start());
    printf("WIFI sta joining %s ps=%d btm=%d\n", ssid, (int)s_ps, s_btm ? 1 : 0);
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
    nvs_set_i32(h, "ps", (int32_t)s_ps);
    nvs_set_i32(h, "btm", s_btm ? 1 : 0);
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
    } else if (strcmp(cmd, "ps") == 0) {
        char* arg = strtok(nullptr, " ");
        const int want = arg ? atoi(arg) : -1;
        if (want < 0 || want > 2) {
            printf("ERR usage: ps <0|1|2>  (0 none / 1 min-modem / 2 max-modem)\n");
            return;
        }
        s_ps = (wifi_ps_type_t)want;
        esp_wifi_set_ps(s_ps);
        config_save(s_sta_ssid[0] ? "sta" : "ap", s_sta_ssid, 1);
        printf("OK ps=%d\n", (int)s_ps);
    } else if (strcmp(cmd, "btm") == 0) {
        char* arg = strtok(nullptr, " ");
        if (arg == nullptr) {
            printf("OK btm=%d\n", s_btm ? 1 : 0);
            return;
        }
        s_btm = (strcmp(arg, "1") == 0 || strcmp(arg, "on") == 0);
        config_save(s_sta_ssid[0] ? "sta" : "ap", s_sta_ssid, 1);
        printf("OK btm=%d (reconnecting)\n", s_btm ? 1 : 0);
        if (s_sta_ssid[0]) {
            apply_sta_cfg();
            esp_wifi_disconnect();  // the event handler reconnects with the new cfg
        }
    } else if (strcmp(cmd, "sniff") == 0) {
        char* arg = strtok(nullptr, " ");
        const int ch = arg ? atoi(arg) : 1;
        if (ch < 1 || ch > 196) {
            printf("ERR usage: sniff <channel>\n");
            return;
        }
        start_sniff(ch);
    } else if (strcmp(cmd, "sniffpoll") == 0) {
        char* arg = strtok(nullptr, " ");
        const int ch = arg ? atoi(arg) : 1;
        if (ch < 1 || ch > 196) {
            printf("ERR usage: sniffpoll <channel>\n");
            return;
        }
        start_sniff_poll(ch);
    } else if (strcmp(cmd, "sniffstop") == 0) {
        sniff_stop();
    } else if (strcmp(cmd, "reboot") == 0) {
        printf("OK rebooting\n");
        fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(50));
        esp_restart();
    } else if (strcmp(cmd, "clear") == 0) {
        nvs_handle_t h;
        if (nvs_open("lab", NVS_READWRITE, &h) == ESP_OK) {
            nvs_erase_all(h);
            nvs_commit(h);
            nvs_close(h);
        }
        printf("OK cleared, reboot to stay idle\n");
    } else if (strcmp(cmd, "status") == 0) {
        // The station MAC is part of the status because the PS-Poll / PM-bit attack
        // has to name its victim: a bench run hands this MAC to the attack board
        // instead of waiting for the sniffer to learn it.
        uint8_t mac[6] = {0};
        esp_wifi_get_mac(WIFI_IF_STA, mac);
        printf("STATUS bytes=%u kib=%u ps=%d btm=%d mac=%02X:%02X:%02X:%02X:%02X:%02X\n",
               (unsigned)s_bytes, (unsigned)(s_bytes / 1024), (int)s_ps, s_btm ? 1 : 0, mac[0],
               mac[1], mac[2], mac[3], mac[4], mac[5]);
        fflush(stdout);
    } else {
        printf("ERR unknown '%s' (ap/sta/ps/btm/sniff/sniffpoll/sniffstop/status/clear/reboot)\n", cmd);
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
            int32_t ps = 0;
            nvs_get_i32(h, "ps", &ps);
            int32_t btm = 0;
            nvs_get_i32(h, "btm", &btm);
            if (ps >= 0 && ps <= 2) {
                s_ps = (wifi_ps_type_t)ps;
            }
            s_btm = btm != 0;
            printf("INFO auto %s ssid=%s ch=%d\n", role, ssid, (int)ch);
            if (strcmp(role, "ap") == 0) {
                start_ap(ssid, (int)ch);
            } else if (strcmp(role, "sta") == 0) {
                start_sta(ssid);
            }
        }
        nvs_close(h);
    }
    printf("INFO lab rf_throughput ready (ap <ssid> [ch] / sta <ssid> / ps <0|1|2> / btm <0|1> / "
           "sniff <ch> / sniffpoll <ch> / sniffstop / clear / reboot / status)\n");

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
