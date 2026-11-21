// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "sdkconfig.h"

#if CONFIG_WB_BLE

#include "hal_ble/hal_ble.h"

#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "ble_frame/adv.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_hs_mbuf.h"
#include "host/ble_hs_id.h"
#include "host/util/util.h"
#include "nimble/nimble_npl.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

static const char *TAG = "hal_ble";

// NimBLE 的 host 跑在自己的任务里，ble_gap_* 必须在那个任务的上下文里调。
// 所以这里做一个小任务队列：谁的线程想动 BLE，就把活丢过去再等结果。
#define JOB_POOL 4
#define JOB_WAIT_MS 3000

typedef enum {
    OP_ADDR_SET = 0,
    OP_ADV_SET,
    OP_ADV_START,
    OP_ADV_STOP,
    OP_SCAN_START,
    OP_SCAN_STOP,
} ble_op_t;

typedef struct {
    struct ble_npl_event ev;
    ble_op_t op;
    bool used;
    SemaphoreHandle_t done;
    int rc;
    uint8_t data[HAL_BLE_ADV_EXT_MAX];
    size_t len;
    uint8_t addr[6];
    uint16_t itvl_min;
    uint16_t itvl_max;
    uint32_t duration_ms;
    bool connectable;
} ble_job_t;

static ble_job_t s_jobs[JOB_POOL];
static SemaphoreHandle_t s_job_lock;
static struct ble_npl_eventq *s_evq;
static TaskHandle_t s_host_task;
static bool s_inited;
static bool s_synced;
static uint8_t s_own_addr_type = BLE_OWN_ADDR_PUBLIC;
static uint8_t s_id_addr[6];
static volatile bool s_adv_running;
static struct ble_gap_adv_params s_adv_params;
static bool s_gatt_ready;
static volatile bool s_scan_running;
static hal_ble_stats_t s_stats;
static hal_ble_peer_t s_peers[HAL_BLE_PEER_MAX];
static volatile size_t s_peer_count;

// 我们这边按人读顺序存，空口和 NimBLE 是 LSB 在前
static void addr_to_wire(const uint8_t in[6], uint8_t out[6]) {
    for (int i = 0; i < 6; i++) {
        out[i] = in[5 - i];
    }
}

static void addr_from_wire(const uint8_t in[6], uint8_t out[6]) {
    for (int i = 0; i < 6; i++) {
        out[i] = in[5 - i];
    }
}

static int gatt_register_sync(void);
static int gatt_handle_event(struct ble_gap_event *event);

static esp_err_t rc_to_err(int rc) {
    if (rc == 0) {
        return ESP_OK;
    }
    if (rc == BLE_HS_EINVAL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (rc == BLE_HS_ENOMEM) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_FAIL;
}

static void peer_record(const struct ble_gap_disc_desc *desc) {
    s_stats.scan_reports++;
    uint8_t mac[6];
    addr_from_wire(desc->addr.val, mac);

    // 同一个地址只更新，不然扫十分钟表就被重复条目塞满了
    const size_t n = s_peer_count;
    for (size_t i = 0; i < n && i < HAL_BLE_PEER_MAX; i++) {
        if (memcmp(s_peers[i].addr, mac, 6) == 0) {
            s_peers[i].rssi = desc->rssi;
            s_peers[i].evt_type = desc->event_type;
            uint8_t len = desc->length_data;
            if (len > HAL_BLE_ADV_LEGACY_MAX) {
                len = HAL_BLE_ADV_LEGACY_MAX;
            }
            s_peers[i].data_len = len;
            memcpy(s_peers[i].data, desc->data, len);
            return;
        }
    }
    if (n >= HAL_BLE_PEER_MAX) {
        return;
    }
    hal_ble_peer_t *slot = &s_peers[n];
    memcpy(slot->addr, mac, 6);
    slot->addr_type = desc->addr.type;
    slot->evt_type = desc->event_type;
    slot->rssi = desc->rssi;
    uint8_t len = desc->length_data;
    if (len > HAL_BLE_ADV_LEGACY_MAX) {
        len = HAL_BLE_ADV_LEGACY_MAX;
    }
    slot->data_len = len;
    memcpy(slot->data, desc->data, len);
    // 表是在 host 任务里写的，读的人可能正看到一半。条目少、用途是列出来看，
    // 不为此上锁，最后才推计数，至少保证读到的都是填完的槽位。
    __sync_synchronize();
    s_peer_count = n + 1;
}

static int gap_event(struct ble_gap_event *event, void *arg) {
    (void)arg;
    switch (event->type) {
        case BLE_GAP_EVENT_DISC:
            peer_record(&event->disc);
            return 0;
        case BLE_GAP_EVENT_DISC_COMPLETE:
            s_scan_running = false;
            return 0;
        case BLE_GAP_EVENT_ADV_COMPLETE:
            s_adv_running = false;
            return 0;
        default:
            // 连接、订阅这些归 GATT 那边管
            return gatt_handle_event(event);
    }
}

static int job_execute(const ble_job_t *job) {
    switch (job->op) {
        case OP_ADDR_SET: {
            uint8_t wire[6];
            addr_to_wire(job->addr, wire);
            // NimBLE 靠最高有效字节判地址类型，random static 要求最高两位是 11
            if ((wire[5] & 0xC0) != 0xC0) {
                return BLE_HS_EINVAL;
            }
            const int rc = ble_hs_id_set_rnd(wire);
            if (rc == 0) {
                s_own_addr_type = BLE_OWN_ADDR_RANDOM;
                memcpy(s_id_addr, job->addr, 6);
            }
            return rc;
        }
        case OP_ADV_SET:
            return ble_gap_adv_set_data(job->data, (int)job->len);
        case OP_ADV_START: {
            struct ble_gap_adv_params params;
            memset(&params, 0, sizeof(params));
            params.conn_mode = job->connectable ? BLE_GAP_CONN_MODE_UND : BLE_GAP_CONN_MODE_NON;
            params.disc_mode = BLE_GAP_DISC_MODE_GEN;
            params.itvl_min = job->itvl_min;
            params.itvl_max = job->itvl_max;
            s_adv_params = params;
            const int rc =
                ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER, &params, gap_event, NULL);
            if (rc == 0) {
                s_adv_running = true;
                s_stats.adv_starts++;
                return 0;
            }
            if (rc == BLE_HS_EALREADY) {
                // 本来就在广播，对调用方来说结果一样
                s_adv_running = true;
                return 0;
            }
            s_stats.adv_errors++;
            return rc;
        }
        case OP_ADV_STOP: {
            const int rc = ble_gap_adv_stop();
            s_adv_running = false;
            return (rc == BLE_HS_EALREADY) ? 0 : rc;
        }
        case OP_SCAN_START: {
            struct ble_gap_disc_params params;
            memset(&params, 0, sizeof(params));
            // 100ms 里扫 100ms，最灵敏也最费电；调低窗口能省一点
            params.itvl = 160;
            params.window = 160;
            params.passive = 1;
            params.filter_duplicates = 0;
            const int32_t duration =
                (job->duration_ms == 0) ? BLE_HS_FOREVER : (int32_t)job->duration_ms;
            const int rc = ble_gap_disc(s_own_addr_type, duration, &params, gap_event, NULL);
            if (rc == 0 || rc == BLE_HS_EALREADY) {
                s_scan_running = true;
            }
            return rc;
        }
        case OP_SCAN_STOP: {
            const int rc = ble_gap_disc_cancel();
            s_scan_running = false;
            return rc;
        }
        default:
            return BLE_HS_EINVAL;
    }
}

static void job_handler(struct ble_npl_event *ev) {
    ble_job_t *job = ble_npl_event_get_arg(ev);
    if (job == NULL) {
        return;
    }
    job->rc = job_execute(job);
    s_stats.last_rc = job->rc;
    if (job->done != NULL) {
        xSemaphoreGive(job->done);
    }
}

static ble_job_t *job_alloc(void) {
    if (s_job_lock == NULL) {
        return NULL;
    }
    ble_job_t *found = NULL;
    xSemaphoreTake(s_job_lock, portMAX_DELAY);
    for (int i = 0; i < JOB_POOL; i++) {
        if (!s_jobs[i].used) {
            found = &s_jobs[i];
            break;
        }
    }
    if (found != NULL) {
        memset(found, 0, sizeof(*found));
        found->used = true;
    }
    xSemaphoreGive(s_job_lock);
    return found;
}

static void job_release(ble_job_t *job) {
    xSemaphoreTake(s_job_lock, portMAX_DELAY);
    job->used = false;
    xSemaphoreGive(s_job_lock);
}

static esp_err_t job_submit(ble_job_t *job) {
    if (job == NULL) {
        return ESP_ERR_NO_MEM;
    }
    if (!s_inited || s_evq == NULL) {
        job_release(job);
        return ESP_ERR_INVALID_STATE;
    }
    // 已经在 host 任务里（比如扫描回调里），再投队列就是自己等自己
    if (xTaskGetCurrentTaskHandle() == s_host_task) {
        job->rc = job_execute(job);
        s_stats.last_rc = job->rc;
        const esp_err_t err = rc_to_err(job->rc);
        job_release(job);
        return err;
    }

    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (done == NULL) {
        job_release(job);
        return ESP_ERR_NO_MEM;
    }
    job->done = done;
    ble_npl_event_init(&job->ev, job_handler, job);
    ble_npl_eventq_put(s_evq, &job->ev);

    if (xSemaphoreTake(done, pdMS_TO_TICKS(JOB_WAIT_MS)) != pdTRUE) {
        // host 任务没在超时内接手。这个 job 不能再回收：事件可能还挂在队列里，
        // 复用它会让队列指到别的调用身上。
        s_stats.job_timeouts++;
        job->done = NULL;
        vSemaphoreDelete(done);
        return ESP_ERR_TIMEOUT;
    }
    job->done = NULL;
    vSemaphoreDelete(done);
    const esp_err_t err = rc_to_err(job->rc);
    job_release(job);
    return err;
}

static void on_reset(int reason) {
    (void)reason;
    s_synced = false;
    s_adv_running = false;
    s_scan_running = false;
    ESP_LOGW(TAG, "host reset");
}

static void on_sync(void) {
    if (ble_hs_util_ensure_addr(0) != 0) {
        ESP_LOGE(TAG, "no usable identity address");
        return;
    }
    uint8_t type = BLE_OWN_ADDR_PUBLIC;
    if (ble_hs_id_infer_auto(0, &type) != 0) {
        ESP_LOGE(TAG, "infer addr type failed");
        return;
    }
    s_own_addr_type = type;
    uint8_t wire[6] = {0};
    if (ble_hs_id_copy_addr(type, wire, NULL) == 0) {
        addr_from_wire(wire, s_id_addr);
    }
    s_synced = true;
    ESP_LOGI(TAG, "synced, addr %02x:%02x:%02x:%02x:%02x:%02x type=%u", s_id_addr[0], s_id_addr[1],
             s_id_addr[2], s_id_addr[3], s_id_addr[4], s_id_addr[5], (unsigned)type);
}

static void host_task(void *param) {
    (void)param;
    s_host_task = xTaskGetCurrentTaskHandle();
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t hal_ble_init(void) {
    if (s_inited) {
        return ESP_OK;
    }
    s_job_lock = xSemaphoreCreateMutex();
    if (s_job_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    const esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed (%s)", esp_err_to_name(err));
        return err;
    }
    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;

    s_evq = nimble_port_get_dflt_eventq();
    if (s_evq == NULL) {
        ESP_LOGE(TAG, "no host event queue");
        return ESP_FAIL;
    }
    // GATT 服务必须在 host 跑起来之前登记。放到 host 任务的 job 里去调，
    // add_svcs 会返回 0 但 val_handle 不填，手机连上来看不到任何服务。
    const int grc = gatt_register_sync();
    if (grc == 0) {
        s_gatt_ready = true;
    } else {
        ESP_LOGE(TAG, "gatt register failed rc=%d", grc);
    }
    nimble_port_freertos_init(host_task);
    s_inited = true;
    s_stats.heap_after_init = esp_get_free_heap_size();
    ESP_LOGI(TAG, "host up, free heap %u", (unsigned)s_stats.heap_after_init);
    return ESP_OK;
}

bool hal_ble_ready(void) {
    return s_inited && s_synced;
}

esp_err_t hal_ble_addr_set(const uint8_t addr[6]) {
    if (addr == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    ble_job_t *job = job_alloc();
    if (job == NULL) {
        return ESP_ERR_NO_MEM;
    }
    job->op = OP_ADDR_SET;
    memcpy(job->addr, addr, 6);
    return job_submit(job);
}

esp_err_t hal_ble_addr_get(uint8_t out[6], uint8_t *addr_type) {
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(out, s_id_addr, 6);
    if (addr_type != NULL) {
        *addr_type = s_own_addr_type;
    }
    return s_synced ? ESP_OK : ESP_ERR_INVALID_STATE;
}

esp_err_t hal_ble_adv_set(const uint8_t *data, size_t len) {
    if (data == NULL || len == 0 || len > HAL_BLE_ADV_EXT_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    ble_job_t *job = job_alloc();
    if (job == NULL) {
        return ESP_ERR_NO_MEM;
    }
    job->op = OP_ADV_SET;
    memcpy(job->data, data, len);
    job->len = len;
    return job_submit(job);
}

esp_err_t hal_ble_adv_start(uint16_t itvl_min, uint16_t itvl_max, bool connectable) {
    ble_job_t *job = job_alloc();
    if (job == NULL) {
        return ESP_ERR_NO_MEM;
    }
    job->op = OP_ADV_START;
    job->connectable = connectable;
    uint16_t lo = (itvl_min == 0) ? HAL_BLE_ITVL_MIN : itvl_min;
    uint16_t hi = (itvl_max == 0) ? lo : itvl_max;
    if (lo < HAL_BLE_ITVL_MIN) {
        lo = HAL_BLE_ITVL_MIN;
    }
    if (lo > HAL_BLE_ITVL_MAX) {
        lo = HAL_BLE_ITVL_MAX;
    }
    if (hi < lo) {
        hi = lo;
    }
    if (hi > HAL_BLE_ITVL_MAX) {
        hi = HAL_BLE_ITVL_MAX;
    }
    job->itvl_min = lo;
    job->itvl_max = hi;
    return job_submit(job);
}

esp_err_t hal_ble_adv_stop(void) {
    ble_job_t *job = job_alloc();
    if (job == NULL) {
        return ESP_ERR_NO_MEM;
    }
    job->op = OP_ADV_STOP;
    return job_submit(job);
}

bool hal_ble_adv_running(void) {
    return s_adv_running;
}

esp_err_t hal_ble_scan_start(uint32_t duration_ms) {
    ble_job_t *job = job_alloc();
    if (job == NULL) {
        return ESP_ERR_NO_MEM;
    }
    job->op = OP_SCAN_START;
    job->duration_ms = duration_ms;
    return job_submit(job);
}

esp_err_t hal_ble_scan_stop(void) {
    ble_job_t *job = job_alloc();
    if (job == NULL) {
        return ESP_ERR_NO_MEM;
    }
    job->op = OP_SCAN_STOP;
    return job_submit(job);
}

bool hal_ble_scan_running(void) {
    return s_scan_running;
}

size_t hal_ble_scan_count(void) {
    return s_peer_count;
}

const hal_ble_peer_t *hal_ble_scan_at(size_t index) {
    if (index >= s_peer_count || index >= HAL_BLE_PEER_MAX) {
        return NULL;
    }
    return &s_peers[index];
}

void hal_ble_scan_clear(void) {
    s_peer_count = 0;
}

void hal_ble_stats(hal_ble_stats_t *out) {
    if (out == NULL) {
        return;
    }
    *out = s_stats;
}

// ---------------- GATT 串口 ----------------

static const ble_uuid128_t kSvcUuid = BLE_UUID128_INIT(
    0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x01, 0x00, 0x40,
    0x6e);
static const ble_uuid128_t kRxUuid = BLE_UUID128_INIT(
    0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x02, 0x00, 0x40,
    0x6e);
static const ble_uuid128_t kTxUuid = BLE_UUID128_INIT(
    0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x03, 0x00, 0x40,
    0x6e);

static uint8_t s_gatt_rx[HAL_BLE_GATT_RX_CAP];
static volatile size_t s_gatt_head;
static volatile size_t s_gatt_tail;
static uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static uint16_t s_tx_handle;
static volatile bool s_tx_notify_on;
static hal_ble_gatt_conn_fn s_conn_cb;
static char s_gatt_name[32] = "AirBench";
static bool s_gatt_ready;

static int gatt_access(uint16_t conn_handle, uint16_t attr_handle,
                       struct ble_gatt_access_ctxt *ctxt, void *arg) {
    (void)conn_handle;
    (void)attr_handle;
    (void)arg;

    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint8_t chunk[64];
    uint16_t len = 0;
    while (OS_MBUF_PKTLEN(ctxt->om) > len) {
        uint16_t take = 0;
        if (ble_hs_mbuf_to_flat(ctxt->om, chunk, sizeof(chunk), &take) != 0 || take == 0) {
            break;
        }
        for (uint16_t i = 0; i < take; i++) {
            const size_t next = (s_gatt_head + 1) % HAL_BLE_GATT_RX_CAP;
            if (next == s_gatt_tail) {
                // 满了就丢，命令流丢了比卡死强
                break;
            }
            s_gatt_rx[s_gatt_head] = chunk[i];
            s_gatt_head = next;
        }
        len = (uint16_t)(len + take);
        break;
    }
    return 0;
}

static int gatt_handle_event(struct ble_gap_event *event) {
    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            if (event->connect.status == 0) {
                s_conn_handle = event->connect.conn_handle;
                if (s_conn_cb != NULL) {
                    s_conn_cb(true);
                }
            }
            return 0;
        case BLE_GAP_EVENT_DISCONNECT:
            s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
            s_tx_notify_on = false;
            if (s_conn_cb != NULL) {
                s_conn_cb(false);
            }
            // 连上时控制器会停广播，断开不会自己恢复，得手动再开一次
            if (s_adv_running) {
                ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER, &s_adv_params, gap_event,
                                  NULL);
            }
            return 0;
        case BLE_GAP_EVENT_SUBSCRIBE:
            if (event->subscribe.attr_handle == s_tx_handle) {
                s_tx_notify_on = event->subscribe.cur_notify;
            }
            return 0;
        case BLE_GAP_EVENT_MTU:
            return 0;
        default:
            return 0;
    }
}

static const struct ble_gatt_svc_def kGattSvcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &kSvcUuid.u,
        .characteristics =
            (struct ble_gatt_chr_def[]){
                {
                    .uuid = &kRxUuid.u,
                    .access_cb = gatt_access,
                    .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
                },
                {
                    .uuid = &kTxUuid.u,
                    .access_cb = gatt_access,
                    .flags = BLE_GATT_CHR_F_NOTIFY,
                    .val_handle = &s_tx_handle,
                },
                {0},
            },
    },
    {0},
};

// host 启动前调，真正把服务挂上去
static int gatt_register_sync(void) {
    const int rc = ble_gatts_count_cfg(kGattSvcs);
    if (rc != 0) {
        return rc;
    }
    return ble_gatts_add_svcs(kGattSvcs);
}

esp_err_t hal_ble_gatt_start(const char *device_name, hal_ble_gatt_conn_fn conn_cb) {
    if (!hal_ble_ready()) {
        return ESP_ERR_INVALID_STATE;
    }
    s_conn_cb = conn_cb;
    if (device_name != NULL && device_name[0] != 0) {
        strncpy(s_gatt_name, device_name, sizeof(s_gatt_name) - 1);
        s_gatt_name[sizeof(s_gatt_name) - 1] = 0;
    }

    if (!s_gatt_ready) {
        ESP_LOGE(TAG, "gatt services not registered");
        return ESP_ERR_INVALID_STATE;
    }

    // 广播里带上服务 UUID，手机按服务过滤才看得到
    uint8_t adv[HAL_BLE_ADV_EXT_MAX];
    bf_adv_t set;
    bf_adv_init(&set, adv, sizeof(adv));
    bf_adv_flags(&set, BF_FLAG_GENERAL_DISC | BF_FLAG_NO_BREDR);
    uint8_t uuid_be[16];
    for (int i = 0; i < 16; i++) {
        uuid_be[i] = kSvcUuid.value[15 - i];
    }
    bf_adv_uuid128(&set, uuid_be, true);
    bf_adv_name(&set, s_gatt_name, true);
    esp_err_t err = hal_ble_adv_set(adv, bf_adv_len(&set));
    if (err != ESP_OK) {
        return err;
    }
    return hal_ble_adv_start(HAL_BLE_ITVL_MIN, HAL_BLE_ITVL_MIN, true);
}

bool hal_ble_gatt_connected(void) {
    return s_conn_handle != BLE_HS_CONN_HANDLE_NONE;
}

int hal_ble_gatt_read(uint8_t *out, size_t cap) {
    if (out == NULL) {
        return 0;
    }
    size_t n = 0;
    while (n < cap && s_gatt_tail != s_gatt_head) {
        out[n++] = s_gatt_rx[s_gatt_tail];
        s_gatt_tail = (s_gatt_tail + 1) % HAL_BLE_GATT_RX_CAP;
    }
    return (int)n;
}

uint16_t hal_ble_gatt_mtu(void) {
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        return 23;
    }
    const uint16_t mtu = ble_att_mtu(s_conn_handle);
    return (mtu == 0) ? 23 : mtu;
}

esp_err_t hal_ble_gatt_send(const char *text) {
    if (text == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE || !s_tx_notify_on) {
        return ESP_ERR_INVALID_STATE;
    }
    const uint16_t mtu = hal_ble_gatt_mtu();
    size_t payload = (mtu > 3) ? (size_t)(mtu - 3) : 20;
    if (payload > 180) {
        payload = 180;
    }
    const size_t total = strlen(text);
    for (size_t off = 0; off < total; off += payload) {
        size_t chunk = total - off;
        if (chunk > payload) {
            chunk = payload;
        }
        struct os_mbuf *om = ble_hs_mbuf_from_flat(text + off, (uint16_t)chunk);
        if (om == NULL) {
            return ESP_ERR_NO_MEM;
        }
        const int rc = ble_gatts_notify_custom(s_conn_handle, s_tx_handle, om);
        if (rc != 0) {
            os_mbuf_free_chain(om);
            return ESP_FAIL;
        }
    }
    return ESP_OK;
}

#endif
