#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/ble_sm.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"

/* Only a deliberately configured test advertiser should use this UUID. */
static const ble_uuid128_t kTestUuid = BLE_UUID128_INIT(
    0x91, 0x3f, 0x62, 0x70, 0xf8, 0xc6, 0x46, 0x9f,
    0x96, 0x41, 0xb1, 0xf0, 0xf6, 0x77, 0x13, 0x5e);
static const char *kTag = "pair_probe";
static uint8_t s_addr_type;
static bool s_attempted;
static uint32_t s_reports;
static uint32_t s_uuid_reports;
static ble_addr_t s_connectable[64];
static size_t s_connectable_count;

static bool seen_connectable(const ble_addr_t *addr) {
    for (size_t i = 0; i < s_connectable_count; ++i) {
        if (s_connectable[i].type == addr->type &&
            memcmp(s_connectable[i].val, addr->val, sizeof(addr->val)) == 0) {
            return true;
        }
    }
    return false;
}

void ble_store_config_init(void);

static int gap_event(struct ble_gap_event *event, void *arg) {
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_DISC: {
        const struct ble_gap_disc_desc *d = &event->disc;
        struct ble_hs_adv_fields fields;
        ++s_reports;
        if (d->event_type == BLE_HCI_ADV_RPT_EVTYPE_ADV_IND &&
            !seen_connectable(&d->addr) && s_connectable_count < 64) {
            s_connectable[s_connectable_count++] = d->addr;
        }
        if (s_attempted || ble_hs_adv_parse_fields(&fields, d->data, d->length_data) != 0) {
            return 0;
        }
        if (fields.num_uuids128) {
            ++s_uuid_reports;
        }
        for (int i = 0; i < fields.num_uuids128; ++i) {
            if (ble_uuid_cmp(&fields.uuids128[i].u, &kTestUuid.u) == 0) {
                ESP_LOGI(kTag, "test UUID report type=%d", d->event_type);
                if (!seen_connectable(&d->addr)) {
                    return 0;
                }
                s_attempted = true;
                int rc = ble_gap_disc_cancel();
                ESP_LOGI(kTag, "test advertiser found; scan_cancel=%d", rc);
                if (rc == 0) {
                    rc = ble_gap_connect(s_addr_type, &d->addr, 10000, NULL, gap_event, NULL);
                    ESP_LOGI(kTag, "connect request rc=%d", rc);
                }
                break;
            }
        }
        return 0;
    }
    case BLE_GAP_EVENT_CONNECT:
        ESP_LOGI(kTag, "connect status=%d", event->connect.status);
        if (event->connect.status == 0) {
            int rc = ble_gap_security_initiate(event->connect.conn_handle);
            ESP_LOGI(kTag, "security request rc=%d", rc);
        }
        return 0;
    case BLE_GAP_EVENT_PASSKEY_ACTION: {
        struct ble_sm_io io = {0};
        io.action = event->passkey.params.action;
        if (io.action != BLE_SM_IOACT_DISP) {
            ESP_LOGW(kTag, "unsupported passkey action=%d; rejecting", io.action);
            ble_gap_terminate(event->passkey.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            return 0;
        }
        io.passkey = esp_random() % 1000000;
        printf("Enter the following passkey on the test phone: %06" PRIu32 "\n", io.passkey);
        ESP_LOGI(kTag, "passkey injected rc=%d", ble_sm_inject_io(event->passkey.conn_handle, &io));
        return 0;
    }
    case BLE_GAP_EVENT_ENC_CHANGE: {
        struct ble_gap_conn_desc desc;
        int rc = ble_gap_conn_find(event->enc_change.conn_handle, &desc);
        ESP_LOGI(kTag, "encryption status=%d encrypted=%d authenticated=%d bonded=%d",
                 event->enc_change.status, rc == 0 ? desc.sec_state.encrypted : 0,
                 rc == 0 ? desc.sec_state.authenticated : 0, rc == 0 ? desc.sec_state.bonded : 0);
        return 0;
    }
    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(kTag, "disconnected reason=%d; experiment ended", event->disconnect.reason);
        return 0;
    case BLE_GAP_EVENT_DISC_COMPLETE:
        ESP_LOGI(kTag, "scan ended reason=%d reports=%" PRIu32 " uuid128=%" PRIu32,
                 event->disc_complete.reason, s_reports, s_uuid_reports);
        return 0;
    case BLE_GAP_EVENT_REPEAT_PAIRING:
        ESP_LOGW(kTag, "existing bond retained; repeat pairing rejected");
        return BLE_GAP_REPEAT_PAIRING_IGNORE;
    default:
        return 0;
    }
}

static void on_sync(void) {
    int rc = ble_hs_id_infer_auto(0, &s_addr_type);
    if (rc != 0) {
        ESP_LOGE(kTag, "address setup failed rc=%d", rc);
        return;
    }
    struct ble_gap_disc_params params = {0};
    params.passive = 0;
    params.filter_duplicates = 1;
    rc = ble_gap_disc(s_addr_type, 30000, &params, gap_event, NULL);
    ESP_LOGI(kTag, "30-second scan started rc=%d", rc);
}

static void host_task(void *arg) {
    (void)arg;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "NVS init failed: %s; no erase attempted", esp_err_to_name(err));
        return;
    }
    ESP_ERROR_CHECK(nimble_port_init());
    ble_svc_gap_init();
    ble_svc_gap_device_name_set("Pair Probe");
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_DISPLAY_ONLY;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 1;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_store_config_init();
    nimble_port_freertos_init(host_task);
}
