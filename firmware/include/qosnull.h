#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 伪造单播 QoS Null 冒充受害者回 AP，靠 PM 位把 AP 对该站的省电状态抢过来。
//
// PM 位是 Frame Control 第 12 位（第二个字节的 0x10）。STA 置 1 表示"我要睡了，
// 下行先缓存"，AP 于是停发并把该站记进 TIM，直到收到它的 PM=0。用受害者的 TA
// 发这个帧，AP 对它的状态就归我们拨。
//
// 只用一种帧：QoS Null（data subtype 12，24 字节头 + 2 字节 QoS Control，无 payload）。
// 这是 QoS/WMM 关联下 STA 回 AP 的省电状态帧，跟 AP 的 ACK 一起构成一次正常的上行
// 交互，不需要 payload 也不需要密钥。控制帧 PS-Poll 已经被否掉：单播 RA 时 MAC 根本
// 不发（附录 A of attack-principles.md）。
//
// 每 kFlushEvery 帧改成 PM=0：告诉 AP "我醒了，把缓存的发过来"，那批帧就冲着不在
// 听的站发出去，延迟变成丢包。QOSNULLREL 也是同一个 PM=0 帧，用来善后。
//
// 做不到的事：AP 会把缓存的帧老化丢掉，受害者自己每个上行帧都带 PM=0 又把状态拨回
// 去，所以效果是下行劣化/丢包，不是永久阻断，关联一直挂着（测试报告 §4.4.9/§4.4.10）。
//
// 节奏：单播要等 ACK，全走 tx_guard。10 帧/秒 —— 这类短帧在 20 帧/秒下几百帧就把
// 32 个帧池打穿，整板重启。

typedef enum {
    QOSNULL_OFF = 0,
    QOSNULL_PM = 1,  // 发 PM=1，隔几帧插一个 PM=0
} qosnull_mode_t;

// 拉全站的 target 列表；sta 非空就直接登记这个受害者（台架上不必等它自己冒出来）。
bool qosnull_start(int index, const uint8_t* sta);

// 登记一个被冒充的 STA。
void qosnull_add_station(const uint8_t mac[6]);

void qosnull_stop(void);

// 给每个受害者补一个 PM=0，然后停。
void qosnull_release(void);

// 主循环调用（attack_step 里）。
void qosnull_step(void);

// 混杂回调逐帧调用。
void qosnull_on_rx(const uint8_t* frame, uint16_t len, uint8_t type, uint8_t subtype);

// 打印 PM=1 / PM=0 两种形态的帧和解码字段（格式自检）。
void qosnull_selftest(void);

bool qosnull_active(void);
const char* qosnull_mode_name(void);
uint32_t qosnull_frames(void);
// PM=1 的帧数（把 AP 往"缓存"方向拨）。
uint32_t qosnull_pm1_frames(void);
// PM=0 的帧数（反向拨，也是善后用的那批）。
uint32_t qosnull_pm0_frames(void);
uint32_t qosnull_clients(void);
// 空口上抓到的、发往受害者的下行数据帧：还有就说明伪造的 PM 状态没生效或没撑住。
uint32_t qosnull_dl_frames(void);
// 受害者自己的 Null/QoS Null 帧数，以及其中 PM=1 的条数。
uint32_t qosnull_rx_nulls(void);
uint32_t qosnull_rx_pm1(void);
// qosnull_start() 里 esp_wifi_set_channel 的结果，非 0 表示帧发在了当前信道上
// （通常是 SCAN 还没收尾）。
int32_t qosnull_channel_err(void);

#ifdef __cplusplus
}
#endif
