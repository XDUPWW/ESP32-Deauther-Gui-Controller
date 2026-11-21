// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "wbus/wbus.h"
#include "wtarget/wtarget.h"

// 从 SCAN 结果里取一个 AP。越界或那个槽位是 STA 都返回 false。
bool attack_target_ap(uint32_t idx, wt_entry_t *out);

// 一个射频同一时刻只干一件事。start 的第一句调它。
void attack_exclusive(void);

// 把射频钉在目标 AP 的信道上。owner 用攻击名，出错时能看出是谁占着。
esp_err_t attack_pin(const char *owner, uint8_t channel);

void attack_unpin(const char *owner);

// 广播一条 state 事件，界面和上位机靠它刷新
void attack_emit(const char *object, bool active, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

// 目标 AP 下所有能看到的 STA，按信道过滤后拷进 out。返回条数。
// 被动表只认"这个 MAC 在空气里发过帧"，不保证它归谁，够 deauth/delba 用。
size_t attack_sta_on_channel(uint8_t channel, uint8_t out[][6], size_t cap);

// 随机 MAC，本地管理位 + 单播
void attack_random_mac(uint8_t out[6]);

// 理由码：1..65535，0 当作 1
uint16_t attack_reason(uint32_t value);

uint32_t attack_now_ms(void);

// start 时打点，stop 时就能算出真实速率。fps 是帧数除以墙钟时间，
// 不是按 tick 周期估的。
void attack_mark_start(void);
uint32_t attack_elapsed_ms(void);
void attack_report_rate(wb_reply_t *reply, const char *name, uint32_t frames);

// SAE Commit 的载荷：P-256 的标量 32 字节 + 点 64 字节。两个模块共用。
#define ATTACK_SAE_SCALAR_LEN 32
#define ATTACK_SAE_ELEMENT_LEN 64
#define ATTACK_SAE_GROUP_P256 19

// real_point 时把 element 填成 P-256 生成元（合法点，AP 会继续算下去）；
// 否则填随机字节，AP 在点校验就退回，可以当 A/B 对照。
void attack_sae_fill(uint8_t scalar[ATTACK_SAE_SCALAR_LEN],
                     uint8_t element[ATTACK_SAE_ELEMENT_LEN], bool real_point);

// Auth 帧：algorithm=3（SAE）、seq=1（Commit）、status=0，后面跟 group/scalar/element
int attack_build_sae_commit(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                            const uint8_t bssid[6], const uint8_t scalar[ATTACK_SAE_SCALAR_LEN],
                            const uint8_t element[ATTACK_SAE_ELEMENT_LEN]);

// 同上，但把 AP 发来的 anti-clogging token 原样塞在 group 后面。token 为空就是普通 Commit。
int attack_build_sae_commit_tok(uint8_t *buf, size_t cap, const uint8_t da[6], const uint8_t sa[6],
                                const uint8_t bssid[6], const uint8_t *token, size_t token_len,
                                const uint8_t scalar[ATTACK_SAE_SCALAR_LEN],
                                const uint8_t element[ATTACK_SAE_ELEMENT_LEN]);
