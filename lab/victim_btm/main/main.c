// Lab-only 802.11v/802.11k victim station.
//
// Why this project exists: the attack firmware can put a forged BTM Request on
// the air, but "did the station care" is only observable from the station's side.
// An ESP-IDF STA reports a disconnect with a reason code, so the whole experiment
// reduces to "which reason do we get": 12 (BSS transition) means the station acted
// on the forged request, anything else means it did not.
//
//   ssid <text>             SSID (rest of the line, so spaces work)
//   pass <text>             WPA2-PSK passphrase (empty = open network)
//   country <cc>            country code, needed for channels 12/13
//   join                    associate with the saved ssid/pass
//   ap <ssid> <pass> [ch]   run a WPA2 softAP instead (second BSS to roam to).
//                           Same SSID + same passphrase as the AP under test, or
//                           the station refuses the transition and the experiment
//                           measures nothing.
//   sta <ssid>              shorthand for one-token SSIDs
//   btm <0|1>               btm_enabled in wifi_sta_config_t (reconnects to apply)
//   rm  <0|1>               rm_enabled (802.11k radio measurements)
//   ps  <0|1|2>             power save (0 = always awake, the default here). A
//                           sleeping station misses injected unicast frames
//                           between DTIMs, which would silently invalidate every
//                           "the station ignored it" conclusion.
//   status                  flags, counters, last reason, station MAC
//   scan                    active scan, one line per AP
//   clear / reboot          wipe the saved role / restart
//
// Log format is one line per event, timestamps in seconds from boot, so a bench
// script can grep for BSS_TRANSITION and diff two runs.
//
// Nothing here attacks anything: it is the receiving end of the test, the sibling
// of lab/rf_throughput (which stays untouched and supplies the "ap" role).

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "nvs.h"
#include "nvs_flash.h"

// Disassociation reason codes, copied from this IDF version:
//   components/esp_wifi/include/esp_wifi_types_generic.h (WIFI_REASON_*)
// BSS_TRANSITION_DISASSOC is 12 in IDF v6.1 (checked with grep, not from memory).
// That single number is the pass/fail line of the whole bench run, so it gets its
// own macro and a marker string instead of being one table entry among many.
//
// Note on events: IDF v6.1 has no WIFI_EVENT_STA_ROAMING (no roaming event at all,
// and no BTM event either). The 11k/11v events that do exist are
// WIFI_EVENT_STA_NEIGHBOR_REP and WIFI_EVENT_STA_BSS_RSSI_LOW, both logged below.
// So "the station acted on a forged BTM" can only show up as a disconnect with
// reason 12 -- there is nothing else to watch.
#define REASON_BSS_TRANSITION 12
#define REASON_ROAMING 207
#define MARKER "BSS_TRANSITION!"

typedef struct {
    int code;
    const char* name;
} reason_name_t;

static const reason_name_t kReasons[] = {
    {1, "UNSPECIFIED"},
    {2, "AUTH_EXPIRE"},
    {3, "AUTH_LEAVE"},
    {4, "ASSOC_EXPIRE"},
    {5, "ASSOC_TOOMANY"},
    {6, "NOT_AUTHED"},
    {7, "NOT_ASSOCED"},
    {8, "ASSOC_LEAVE"},
    {9, "ASSOC_NOT_AUTHED"},
    {10, "DISASSOC_PWRCAP_BAD"},
    {11, "DISASSOC_SUPCHAN_BAD"},
    {REASON_BSS_TRANSITION, MARKER},
    {13, "IE_INVALID"},
    {14, "MIC_FAILURE"},
    {15, "4WAY_HANDSHAKE_TIMEOUT"},
    {16, "GROUP_KEY_UPDATE_TIMEOUT"},
    {17, "IE_IN_4WAY_DIFFERS"},
    {18, "GROUP_CIPHER_INVALID"},
    {19, "PAIRWISE_CIPHER_INVALID"},
    {20, "AKMP_INVALID"},
    {21, "UNSUPP_RSN_IE_VERSION"},
    {22, "INVALID_RSN_IE_CAP"},
    {23, "802_1X_AUTH_FAILED"},
    {24, "CIPHER_SUITE_REJECTED"},
    {200, "BEACON_TIMEOUT"},
    {201, "NO_AP_FOUND"},
    {202, "AUTH_FAIL"},
    {203, "ASSOC_FAIL"},
    {204, "HANDSHAKE_TIMEOUT"},
    {205, "CONNECTION_FAIL"},
    {206, "AP_TSF_RESET"},
    {REASON_ROAMING, "ROAMING"},
};

static const char* reason_name(int code) {
    for (size_t i = 0; i < sizeof(kReasons) / sizeof(kReasons[0]); i++) {
        if (kReasons[i].code == code) {
            return kReasons[i].name;
        }
    }
    return "UNKNOWN";
}

static char s_ssid[33];
static char s_pass[65];
static char s_country[3] = "01";
static bool s_btm = true;
static bool s_rm = true;
// Always awake by default. The driver's own default is WIFI_PS_MIN_MODEM, and a
// station that sleeps only listens around DTIM -- a unicast frame injected from a
// third board between those windows is simply not heard. Learned the hard way: the
// first BTM runs had the victim sending PM=1 Null Data (power save on) and it
// answered only once in a while.
static wifi_ps_type_t s_ps = WIFI_PS_NONE;

static bool s_connected;
static int64_t s_conn_ms;     // when the current/last association came up
static int64_t s_disc_ms;     // when the last disconnect happened (0 = none yet)
static uint32_t s_disc_count;
static int s_last_reason = -1;
static uint32_t s_reconnects;

static int64_t now_ms(void) {
    return esp_timer_get_time() / 1000;
}

// One timestamp format everywhere: "t=12.345s" plus a delta when one is relevant.
static void print_time(const char* key, int64_t ms) {
    printf(" %s=%" PRId64 ".%03" PRId64 "s", key, ms / 1000, ms % 1000);
}

static void log_retry_scheduled(void) {
    if (s_ssid[0] != 0) {
        esp_wifi_connect();
    }
}

static void on_wifi_event(void* arg, esp_event_base_t base, int32_t id, void* data) {
    (void)arg;
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t* got = (const ip_event_got_ip_t*)data;
        print_time("t", now_ms());
        printf(" EVT sta_got_ip ip=" IPSTR "\n", IP2STR(&got->ip_info.ip));
        return;
    }
    if (base != WIFI_EVENT) {
        return;
    }

    switch (id) {
        case WIFI_EVENT_STA_START:
            print_time("t", now_ms());
            printf(" EVT sta_start btm=%d rm=%d 11kv=%d ssid=%s\n", s_btm ? 1 : 0, s_rm ? 1 : 0,
#if CONFIG_ESP_WIFI_11KV_SUPPORT
                   1,
#else
                   0,
#endif
                   s_ssid[0] ? s_ssid : "-");
            log_retry_scheduled();
            break;

        case WIFI_EVENT_STA_CONNECTED: {
            const wifi_event_sta_connected_t* conn = (const wifi_event_sta_connected_t*)data;
            const int64_t t = now_ms();
            s_connected = true;
            s_conn_ms = t;
            print_time("t", t);
            printf(" EVT sta_connected bssid=%02X:%02X:%02X:%02X:%02X:%02X ch=%u authmode=%d aid=%u",
                   conn->bssid[0], conn->bssid[1], conn->bssid[2], conn->bssid[3], conn->bssid[4],
                   conn->bssid[5], (unsigned)conn->channel, (int)conn->authmode,
                   (unsigned)conn->aid);
            if (s_disc_ms != 0) {
                // Reconnect delay of the previous drop: the attack's "how long did
                // it stay off" is this number, not the disconnect timestamp.
                s_reconnects++;
                printf(" back_after=%" PRId64 ".%03" PRId64 "s", (t - s_disc_ms) / 1000,
                       (t - s_disc_ms) % 1000);
            }
            printf("\n");
            break;
        }

        case WIFI_EVENT_STA_DISCONNECTED: {
            const wifi_event_sta_disconnected_t* disc = (const wifi_event_sta_disconnected_t*)data;
            const int64_t t = now_ms();
            s_disc_count++;
            s_connected = false;
            if (disc != NULL) {
                s_last_reason = disc->reason;
            }
            print_time("t", t);
            printf(" EVT sta_disconnected n=%u reason=%d %s", (unsigned)s_disc_count,
                   disc != NULL ? (int)disc->reason : -1,
                   reason_name(disc != NULL ? (int)disc->reason : -1));
            if (disc != NULL && disc->reason == REASON_BSS_TRANSITION) {
                // Same line, extra token: `grep BSS_TRANSITION` hits the name above,
                // this one is easy to spot when reading by eye.
                printf(" <<< MARKER");
            }
            if (s_conn_ms != 0) {
                print_time("up_for", t - s_conn_ms);
            }
            if (disc != NULL) {
                printf(" bssid=%02X:%02X:%02X:%02X:%02X:%02X rssi=%d", disc->bssid[0],
                       disc->bssid[1], disc->bssid[2], disc->bssid[3], disc->bssid[4],
                       disc->bssid[5], (int)disc->rssi);
            }
            printf("\n");
            s_disc_ms = t;
            log_retry_scheduled();
            break;
        }

        case WIFI_EVENT_STA_NEIGHBOR_REP: {
            // 802.11k Neighbor Report reached the application: proof the 11k half of
            // the link works (the forged RRM module is checked against this).
            const wifi_event_neighbor_report_t* rep = (const wifi_event_neighbor_report_t*)data;
            print_time("t", now_ms());
            printf(" EVT sta_neighbor_rep len=%u\n", (unsigned)(rep != NULL ? rep->report_len : 0));
            break;
        }

        case WIFI_EVENT_STA_BSS_RSSI_LOW: {
            const wifi_event_bss_rssi_low_t* low = (const wifi_event_bss_rssi_low_t*)data;
            print_time("t", now_ms());
            printf(" EVT sta_bss_rssi_low rssi=%d\n", (int)(low != NULL ? low->rssi : 0));
            break;
        }

        default:
            break;
    }
}

// Every STA setting goes through here so `btm` / `rm` can be toggled at runtime.
// With btm_enabled the driver is told not to pin a BSSID or channel (the whole
// point of the feature), so neither is set.
static void apply_sta_cfg(void) {
    wifi_config_t cfg = {0};
    strncpy((char*)cfg.sta.ssid, s_ssid, sizeof(cfg.sta.ssid) - 1);
    if (s_pass[0] != 0) {
        // WPA2-PSK. threshold.authmode keeps the driver from silently joining a
        // weaker AP with the same SSID.
        strncpy((char*)cfg.sta.password, s_pass, sizeof(cfg.sta.password) - 1);
        cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    } else {
        cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
    }
#if CONFIG_ESP_WIFI_11KV_SUPPORT
    cfg.sta.rm_enabled = s_rm ? 1 : 0;
    cfg.sta.btm_enabled = s_btm ? 1 : 0;
#else
    printf("ERR this build has no 11kv support (CONFIG_ESP_WIFI_11KV_SUPPORT)\n");
#endif
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    esp_wifi_set_ps(s_ps);
}

static void config_save(void) {
    nvs_handle_t h;
    if (nvs_open("vbtm", NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    nvs_set_str(h, "ssid", s_ssid);
    nvs_set_str(h, "pass", s_pass);
    nvs_set_str(h, "cc", s_country);
    nvs_set_i32(h, "btm", s_btm ? 1 : 0);
    nvs_set_i32(h, "rm", s_rm ? 1 : 0);
    nvs_set_i32(h, "ps", (int32_t)s_ps);
    nvs_commit(h);
    nvs_close(h);
}

// Both guards exist because `join` can be issued again on a running board (change
// ssid/pass, join again). Creating a second default netif is an assert, and calling
// esp_wifi_start() twice is a state error -- both of which reset the board in the
// middle of a bench run.
static bool s_netif_ready;
static bool s_wifi_started;
static bool s_ap_started;

static void start_sta(const char* ssid) {
    strncpy(s_ssid, ssid, sizeof(s_ssid) - 1);
    // Country code first: with the default "01" the driver refuses channels 12/13,
    // and a real AP happily sits on channel 12.
    esp_wifi_set_country_code(s_country, true);
    if (!s_netif_ready) {
        esp_netif_create_default_wifi_sta();
        s_netif_ready = true;
    }
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    apply_sta_cfg();
    if (!s_wifi_started) {
        ESP_ERROR_CHECK(esp_wifi_start());
        s_wifi_started = true;
    } else {
        esp_wifi_disconnect();  // event handler reconnects with the new config
    }
    print_time("t", now_ms());
    printf(" INFO joining %s cc=%s auth=%s btm=%d rm=%d ps=%d\n", s_ssid, s_country,
           s_pass[0] ? "wpa2-psk" : "open", s_btm ? 1 : 0, s_rm ? 1 : 0, (int)s_ps);
}

// SoftAP role: a second BSS the victim can actually *roam to*. Same SSID and the
// same WPA2 passphrase as the AP under test makes it a legal transition target
// (a different SSID or a weaker security mode is refused outright, and then the
// BTM experiment measures nothing). Used on a second board, not on the victim.
static bool s_netif_ap_ready;

static void start_ap(const char* ssid, const char* pass, int channel) {
    if (s_wifi_started) {
        // set_mode on a running interface is a state error; stop first.
        esp_wifi_stop();
        s_wifi_started = false;
    }
    esp_wifi_set_country_code(s_country, true);
    if (!s_netif_ap_ready) {
        esp_netif_create_default_wifi_ap();
        s_netif_ap_ready = true;
    }
    wifi_config_t cfg = {0};
    snprintf((char*)cfg.ap.ssid, sizeof(cfg.ap.ssid), "%s", ssid);
    cfg.ap.ssid_len = (uint8_t)strlen(ssid);
    cfg.ap.channel = (uint8_t)channel;
    cfg.ap.max_connection = 4;
    if (pass != nullptr && strlen(pass) >= 8) {
        snprintf((char*)cfg.ap.password, sizeof(cfg.ap.password), "%s", pass);
        cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
    } else {
        cfg.ap.authmode = WIFI_AUTH_OPEN;
    }
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    s_wifi_started = true;
    s_ap_started = true;
    uint8_t mac[6] = {0};
    esp_wifi_get_mac(WIFI_IF_AP, mac);
    print_time("t", now_ms());
    printf(" INFO ap up ssid=%s cc=%s auth=%s ch=%d bssid=%02X:%02X:%02X:%02X:%02X:%02X\n", ssid,
           s_country, cfg.ap.authmode == WIFI_AUTH_OPEN ? "open" : "wpa2-psk", channel, mac[0],
           mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void do_scan(void) {
    wifi_scan_config_t scan = {0};
    scan.show_hidden = true;
    const esp_err_t err = esp_wifi_scan_start(&scan, true);
    if (err != ESP_OK) {
        printf("ERR scan start %d\n", (int)err);
        return;
    }
    uint16_t count = 20;
    wifi_ap_record_t aps[20];
    esp_wifi_scan_get_ap_records(&count, aps);
    printf("SCAN_BEGIN %u\n", (unsigned)count);
    for (uint16_t i = 0; i < count; i++) {
        printf("AP %u rssi=%d ch=%u bssid=%02X:%02X:%02X:%02X:%02X:%02X ssid=%s\n", (unsigned)i,
               (int)aps[i].rssi, (unsigned)aps[i].primary, aps[i].bssid[0], aps[i].bssid[1],
               aps[i].bssid[2], aps[i].bssid[3], aps[i].bssid[4], aps[i].bssid[5],
               (const char*)aps[i].ssid);
    }
    printf("SCAN_END %u\n", (unsigned)count);
    fflush(stdout);
}

static char s_line[96];
static size_t s_len;

static void run_command(char* line) {
    // Remember the tail before strtok() chops the command word: SSIDs and
    // passphrases may contain spaces, so those two take "everything after the
    // command" instead of one token.
    char* rest = strchr(line, ' ');
    char* cmd = strtok(line, " ");
    if (cmd == nullptr) {
        return;
    }
    if (strcmp(cmd, "ssid") == 0) {
        if (rest == nullptr) {
            printf("ERR usage: ssid <text>\n");
            return;
        }
        snprintf(s_ssid, sizeof(s_ssid), "%s", rest + 1);
        config_save();
        printf("OK ssid=%s (use `join`)\n", s_ssid);
        return;
    }
    if (strcmp(cmd, "pass") == 0) {
        if (rest == nullptr) {
            s_pass[0] = 0;
        } else {
            snprintf(s_pass, sizeof(s_pass), "%s", rest + 1);
        }
        config_save();
        // Never echo the passphrase itself, only whether one is set.
        printf("OK pass=%s (use `join`)\n", s_pass[0] ? "set" : "none");
        return;
    }
    if (strcmp(cmd, "country") == 0) {
        char* cc = (rest != nullptr) ? rest + 1 : nullptr;
        if (cc == nullptr || strlen(cc) < 2) {
            printf("OK cc=%s\n", s_country);
            return;
        }
        strncpy(s_country, cc, 2);
        s_country[2] = 0;
        esp_wifi_set_country_code(s_country, true);
        config_save();
        printf("OK cc=%s\n", s_country);
        return;
    }
    if (strcmp(cmd, "join") == 0) {
        if (s_ssid[0] == 0) {
            printf("ERR no ssid saved (use `ssid <text>` first)\n");
            return;
        }
        start_sta(s_ssid);
        return;
    }
    if (strcmp(cmd, "ap") == 0) {
        char* ssid = strtok(nullptr, " ");
        char* pw = strtok(nullptr, " ");
        char* chs = strtok(nullptr, " ");
        if (ssid == nullptr) {
            printf("ERR usage: ap <ssid> [pass] [channel]\n");
            return;
        }
        const int ch = (chs != nullptr) ? atoi(chs) : 6;
        if (ch < 1 || ch > 196) {
            printf("ERR usage: channel 1..196\n");
            return;
        }
        start_ap(ssid, pw, ch);
        return;
    }
    if (strcmp(cmd, "sta") == 0) {
        char* ssid = strtok(nullptr, " ");
        if (ssid == nullptr) {
            printf("ERR usage: sta <ssid>\n");
            return;
        }
        config_save();
        start_sta(ssid);
        config_save();
    } else if (strcmp(cmd, "btm") == 0) {
        char* arg = strtok(nullptr, " ");
        if (arg == nullptr) {
            printf("OK btm=%d rm=%d\n", s_btm ? 1 : 0, s_rm ? 1 : 0);
            return;
        }
        s_btm = (strcmp(arg, "1") == 0 || strcmp(arg, "on") == 0);
        config_save();
        printf("OK btm=%d (reconnecting)\n", s_btm ? 1 : 0);
        if (s_ssid[0] != 0) {
            apply_sta_cfg();
            esp_wifi_disconnect();  // the event handler reconnects with the new cfg
        }
    } else if (strcmp(cmd, "rm") == 0) {
        char* arg = strtok(nullptr, " ");
        if (arg == nullptr) {
            printf("OK rm=%d btm=%d\n", s_rm ? 1 : 0, s_btm ? 1 : 0);
            return;
        }
        s_rm = (strcmp(arg, "1") == 0 || strcmp(arg, "on") == 0);
        config_save();
        printf("OK rm=%d (reconnecting)\n", s_rm ? 1 : 0);
        if (s_ssid[0] != 0) {
            apply_sta_cfg();
            esp_wifi_disconnect();
        }
    } else if (strcmp(cmd, "ps") == 0) {
        char* arg = strtok(nullptr, " ");
        const int want = arg ? atoi(arg) : -1;
        if (want < 0 || want > 2) {
            printf("ERR usage: ps <0|1|2>  (0 none / 1 min-modem / 2 max-modem)\n");
            return;
        }
        s_ps = (wifi_ps_type_t)want;
        esp_wifi_set_ps(s_ps);
        config_save();
        printf("OK ps=%d (was %d)\n", (int)s_ps, want);
    } else if (strcmp(cmd, "scan") == 0) {
        do_scan();
    } else if (strcmp(cmd, "status") == 0) {
        uint8_t mac[6] = {0};
        esp_wifi_get_mac(WIFI_IF_STA, mac);
        uint8_t ch = 0;
        wifi_second_chan_t sec = WIFI_SECOND_CHAN_NONE;
        esp_wifi_get_channel(&ch, &sec);
        print_time("t", now_ms());
        printf(" STATUS up=%d ap=%d ssid=%s cc=%s auth=%s ps=%d btm=%d rm=%d 11kv=%d ch=%u"
               " mac=%02X:%02X:%02X:%02X:%02X:%02X"
               " disc=%u reconnect=%u last_reason=%d %s target_reason=%d\n",
               s_connected ? 1 : 0, s_ap_started ? 1 : 0, s_ssid[0] ? s_ssid : "-", s_country,
               s_pass[0] ? "wpa2-psk" : "open", (int)s_ps, s_btm ? 1 : 0,
               s_rm ? 1 : 0,
#if CONFIG_ESP_WIFI_11KV_SUPPORT
               1,
#else
               0,
#endif
               (unsigned)ch, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
               (unsigned)s_disc_count, (unsigned)s_reconnects, s_last_reason,
               reason_name(s_last_reason), (int)REASON_BSS_TRANSITION);
        fflush(stdout);
    } else if (strcmp(cmd, "clear") == 0) {
        nvs_handle_t h;
        if (nvs_open("vbtm", NVS_READWRITE, &h) == ESP_OK) {
            nvs_erase_all(h);
            nvs_commit(h);
            nvs_close(h);
        }
        printf("OK cleared, reboot to stay idle\n");
    } else if (strcmp(cmd, "reboot") == 0) {
        printf("OK rebooting\n");
        fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(50));
        esp_restart();
    } else {
        printf("ERR unknown '%s' (ssid/pass/country/join/ap/sta/btm/rm/ps/scan/status/clear/reboot)\n", cmd);
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

    nvs_handle_t h;
    size_t len = sizeof(s_ssid);
    if (nvs_open("vbtm", NVS_READONLY, &h) == ESP_OK) {
        len = sizeof(s_ssid);
        if (nvs_get_str(h, "ssid", s_ssid, &len) != ESP_OK) {
            s_ssid[0] = 0;
        }
        len = sizeof(s_pass);
        if (nvs_get_str(h, "pass", s_pass, &len) != ESP_OK) {
            s_pass[0] = 0;
        }
        len = sizeof(s_country);
        if (nvs_get_str(h, "cc", s_country, &len) != ESP_OK) {
            strcpy(s_country, "01");
        }
        int32_t v = 0;
        if (nvs_get_i32(h, "btm", &v) == ESP_OK) {
            s_btm = v != 0;
        }
        v = 0;
        if (nvs_get_i32(h, "rm", &v) == ESP_OK) {
            s_rm = v != 0;
        }
        v = 0;
        if (nvs_get_i32(h, "ps", &v) == ESP_OK && v >= 0 && v <= 2) {
            s_ps = (wifi_ps_type_t)v;
        }
        nvs_close(h);
    }

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_wifi_event, NULL));

    printf("INFO victim_btm ready 11kv=%d target_reason=%d ps=%d ssid=%s\n",
#if CONFIG_ESP_WIFI_11KV_SUPPORT
           1,
#else
           0,
#endif
           (int)REASON_BSS_TRANSITION, (int)s_ps, s_ssid[0] ? s_ssid : "-");
    if (s_ssid[0] != 0) {
        start_sta(s_ssid);
    }

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
