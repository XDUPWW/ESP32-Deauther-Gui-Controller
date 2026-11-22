# 攻击原理 —— 802.11 协议层攻击全量梳理

本文件逐个说明 `firmware/src/` 下**每一个**会向空口发帧的模块：它站在 802.11 协议栈的哪一层、
帧长什么样、为什么有效、什么情况下失效、在 ESP32 上落地时被硬件约束成什么样。

## 0. 读法、事实分层与合规

**三类事实分开标注**

| 标注 | 含义 | 怎么核对 |
| --- | --- | --- |
| 【标准】 | 802.11 / 802.1X 等标准文本的规定 | 给出条款名（和能确认的条款号），可全文检索 |
| 【代码】 | 本仓库实现的事实 | 给 `path:line`，与 `firmware/README.md §5` 冲突时**以代码为准** |
| 【实测】 | 空口 / 串口测到的数字 | 给脚本与日期；未测的一律写"未实测" |

实测环境（除非另注）：攻击板 COM5 = ESP32-2432S028R（CYD，带 LVGL）；抓包板 COM8 = ESP32-C5，
把空口帧以 pcap 流发布到命名管道 `\\.\pipe\esp_sdr_wifi`（linktype 127、含 4 字节 FCS、信道固定 12），
解析脚本 `lab/cap_frames.py`。目标 AP 是一台信道 12 的华为家用 AP `BE:41:99:0B:20:36`（WPA2-PSK）。
吞吐类实验用三块板（`lab/rf_throughput`：一块做 AP + TCP 4444、一块做 STA 下载、CYD 做攻击板）。
数字全部出自 `firmware/测试报告.md`：§4.1（DELBA）、§4.2（BA）、§4.3（NAV 与 Duration）、§4.4（五个新模块）。

**条款号的处理**

本文给条款**名称**，条款号只在能确认时给出。802.11 的条款号跨版本会整体位移（同一段文字在
802.11-2016 与 802.11-2020 里编号不同），编一个漂亮的编号比不写更糟，所以宁可给名字。

**长度的口径**：帧格式一节给的是**构造长度**（`esp_wifi_80211_tx()` 的 len 参数）。
抓包管道的 pcap 记录比它多 4 字节 FCS，所以同一帧在 `测试报告` 里看到的是 +4 的值
（例：EAPOL 构造 36 / 抓包 40，SAE 构造 128 / 抓包 132）。

**合规**：全部命令只允许在自有或书面授权的网络上使用。`README.md §8` 的免责声明、GUI 的确认框、
`DEAUTH_ALL` 之类的目标校验都是有意保留的边界（`AGENTS.md §10`），不要为了方便去掉。

**和别的文档的关系**

- `firmware/README.md` —— 行为、命令、限制（操作视角）
- `firmware/测试报告.md` —— 实测数据、缺陷记录（实验视角）
- `firmware/代码框架与攻击原理.md` —— 早期版本，覆盖 7 种攻击与代码框架；其中 NAV 一节已失效，
  攻击原理部分以本文为准
- 本文 —— 攻击的协议层依据（原理视角）

---

## 1. 总表：模块 × 协议层 × 防护 × 实测状态

| 节 | 模块 | 入口文件 | CLI | 工作模式 | 帧（类型/子类型/类别） | 协议层位置 | 依赖的协议机制 | PMF 等防护 | 实测状态 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2 | Deauth 洪泛 | `deauth.cpp` | `DEAUTH` `DEAUTH_ALL` `DEAUTH_ONLY` `DEAUTH_EXCEPT` `REASON` | 单个 AP / 全部 AP / 白名单 / 黑名单；reason 固定或每束随机 | mgmt / 12 | MLME 关联状态机 | Class 2/3 帧状态机、Reason Code | **被拦**（deauth 是 robust 帧，MFPR 下无效） | 帧上空气 ✅，计数器 ✅，断连未量化 |
| 3 | Probe/Beacon 泛洪 | `deauth.cpp` | `PROBE_BROADCAST` | 单模式（广播泛洪），每 120 ms 跳信道 | mgmt / 8、5 | 扫描（MLME-scan） | 客户端扫描表 | 无（beacon/probe 从不加密） | 帧数 ✅（3 s 2512 帧） |
| 4.1 | CSA（Action 帧） | `csa.cpp` | `CSA` | announce（倒计时）→ hold（新信道克隆 beacon）→ 循环 | mgmt / 13，cat 4 act 4 | 信道管理（802.11h） | CSA 通告 + 倒计时 | **被拦**（spectrum mgmt action 属 robust） | 帧上空气 ✅ |
| 4.2 | CSA（Beacon IE） | `csa.cpp` | `CSA` | 同上，两条路径同一轮发出 | mgmt / 8 + IE 37 | 信道管理 | beacon 里的 CSA 元素 | **不受保护**（beacon 不是 robust 帧） | 帧上空气 ✅，客户端是否跟随未实测 |
| 5 | DELBA 欺骗 | `delba.cpp` | `DELBA` `DELBATEST` | 双向单播（学了 TID）或广播兜底 | mgmt / 13，cat 3 act 2 | Block Ack 会话管理 | 每个 TID 的聚合会话 | **被拦**（cat 3 属 robust） | 吞吐 −99%（非 PMF 链路）✅ |
| 6 | BA 会话劫持 | `delba.cpp` | `BAATTACK` `BAPLANT` `BARPUSH` `BATEST` `BATX` `BARSEQ` | DELBA+ADDBA+BAR 持续 / 只种窗口 / 只推 BAR | mgmt / 13 cat 3 act 0 + ctrl / 8 | Block Ack 重排窗口 | ADDBA 的 SSN → WinStartB | **被拦**（同上） | ESP-IDF 目标 ✅ 冻结；mac80211 未实测 |
| 7 | BTM 强制漫游（steering） | `btm.cpp` | `BTM` `BTMTEST` | Disassociation Imminent + timer；默认不带候选列表，可选用 `cand-bssid` 指定一个真 BSS | mgmt / 13，cat 10 act 7 | 802.11v / 漫游决策 | BTM Request + Extended Capabilities | **被拦**（cat 10 属 robust，需 PMF 关闭） | 端到端 ✅（真实 STA 漫游到我们软 AP，`reason=207`）|
| 8 | TIM 投毒 | `tim.cpp` | `TIM` `TIMTEST` | tim（按 AID 置位）/ clear（清空位图） | mgmt / 8 + IE 5 | 省电（PS）调度 | DTIM/TIM 位图 | **不受保护**（beacon） | 帧字段 ✅，客户端省电行为未实测 |
| 13 | PS 位欺骗（电源管理） | `pspoll.cpp` | `PSPOLL` `PSPOLLREL` `PSPOLLSTOP` `PSPOLLTEST` | 持续伪造 PM=1（每第 6 帧换 PM=0 释放）；帧型可选 null/qosnull/action | data 4 / data 12 / mgmt 13 cat 127 | 省电（PS）状态机 | PM 位声明 + TIM 缓存 | **不受保护**（PM 位与厂商自定义 Action 都不在 robust 集合里） | 三种帧型空口 ✅，吞吐 −21…−38%、零掉线 ✅ |
| 9 | EAPOL-Start/Logoff | `eapol.cpp` | `EAPOL` `EAPOLTEST` | Start 与 Logoff 交替；非 QoS 与 QoS(TID) 交替 | data / 0、8 + LLC/SNAP 0x888E | 802.1X 认证（端口状态机） | EAPOL PDU、受控/非受控端口 | 未加密数据帧可能被丢 | 帧上空气 ✅，该 AP 无回应 |
| 10 | SAE Commit 洪泛 | `sae.cpp` | `SAE` `SAETEST` | point（合法点）/ rand（对照）；身份每 4 帧轮换 | mgmt / 11，alg 3 seq 1 | SAE 握手（WPA3） | ECC 标量乘 + 反 clogging token | 无（认证帧本就不加密） | 帧上空气 ✅，AP 回 status 13（非 WPA3） |
| 11 | Auth/Assoc 洪泛 | `authflood.cpp` | `AUTHFLOOD` `AUTHFLOODTEST` | both（Auth→Assoc→换身份）/ auth / assoc；WPA3 自动升级 SAE | mgmt / 11 alg 0 + mgmt / 0 | 认证 + 关联（station 表） | 每个身份一条状态机 | 无（auth/assoc 从不加密） | AP 回 status 0（接受了伪造身份）✅ |
| 12 | Evil Twin | `evil_twin.cpp` | `EVILTWIN` `EVILTWIN_STOP` `CREDS` | deauth 3 s → 克隆 softAP → DNS 劫持 → HTTP 钓鱼页 | softAP + DNS + HTTP | 上层（钓鱼） | 客户端自动连接 / 用户输入 | 无 | 凭据捕获未量化 |
| 14 | RRM 伪造 Neighbor Report | `rrm.cpp` | `RRM` `RRMTEST` | nbr（幻影邻居，元素 52/13）；count 限次或持续；token/info/opclass/phy 可注入 | mgmt / 13，cat 5 act 5 | 802.11k 邻居表 / 漫游候选 | Neighbor Report element | **被拦**（cat 5 属 robust，需 PMF 关闭） | 帧上空气 ✅（对端解出 cat=5 act=5），客户端采信未实测 |

"PMF 被拦"统一指：客户端**协商了 PMF**（WPA3 强制，WPA2 可选）后，驱动会丢弃未受保护的
robust 管理帧。依据是 Linux 的判定函数 `_ieee80211_is_robust_mgmt_frame()`：
除 Public(4)、HT(7)、Unprotected WNM(11)、Self-protected(15)、VHT(21)、厂商自定义(127)
之外的**所有 Action 类别**都算 robust。

---

## 2. Deauth 洪泛（`deauth.cpp`）

- CLI：`DEAUTH <idx> [reason]`、`DEAUTH_ALL [reason]`、`DEAUTH_ONLY <i,j,..> [reason]`、
  `DEAUTH_EXCEPT <i,j,..> [reason]`、`REASON [1-65535|random]`、`STOP`、`STATS`
- 入口：`deauth.cpp`（帧构造 `build_deauth_ex()` :237，注入 `drain_tx_queue()` :392）

### 2.1 协议层定位

【标准】Deauthentication 是管理帧（type 0, subtype 12），属于 MLME 的关联管理流程
（802.11-2020 里"认证 / 关联 / 去关联 / 去认证"这一族，条款名：*Authentication*、
*Association and reassociation*、*Deauthentication*）。它不是"加密封装"层的东西，而是
**链路状态机**的一环：一个 STA 只有三种状态——未认证、已认证未关联、已关联。Deauth 的作用是
把对端从"已认证"打回"未认证"，并且**不需要经过 4 次握手**，所以它天生没有可加密的密钥上下文。

【标准】这也解释了为什么它是 802.11w（PMF）的第一个靶子：802.11w 把 deauth/disassoc 列入
robust 管理帧，要求用 PTK 加密并带重放保护（单播），或 BIP（广播）。

### 2.2 帧格式

【代码】`deauth.cpp:237`

```
偏移  长度  字段            本固件取值
0     2     Frame Control   0xC0 0x00        ; mgmt(0) / subtype 12 = deauth
2     2     Duration        —               ; 驱动重算，见附录 B
4     6     Addr1 = DA      受害 STA MAC（广播模式 0xFF*6）
10    6     Addr2 = SA      AP 的 BSSID（伪造）
16    6     Addr3 = BSSID   同 Addr2
22    2     Sequence        0xF0FF 固定      ; 不做序号管理，靠"一帧就够"
24    2     Reason Code     1..65535 / random
                                                            → 共 26 字节
```

- `REASON random` 每束从标准定义的集合里重掷（`deauth.cpp:70` 的 `kReasonPool` =
  1–11、13–24；12（"BSS transition management" 触发的去关联）与 25 以上没有为 deauth 定义，
  故意排除，避免发出客户端直接忽略的帧）。
- 一次"命中"发 **3 帧**（`definitions.h:25-30`，`drain_tx_queue()` :392）：
  1 帧 AP→STA 单播、1 帧 STA→AP 反向单播、1 帧广播。反向帧的价值是：AP 收到"客户端说再见"
  会自己把关联拆掉并通知客户端，覆盖那些"只信 AP 发来的 deauth"的过滤实现。
- 嗅探不到客户端时还有一个兜底：每 500 ms 对当前 AP 发一条广播 deauth
  （`BLIND_DEAUTH_PERIOD_MS`，`:918` 起），计数器 `blind=`。

### 2.3 为什么有效 / 何时失效

【标准】有效性来自三点：①Reason Code 是明文且无签名；②STA 收到 deauth 必须立即终止关联
（不能"先验证一下再说"，标准里没有这个余地）；③reason 6/7（"非关联站的 Class 2/3 帧"）
会让状态机直接回到未认证态。

【标准】失效条件只有一条：**PMF**。WPA3 强制 MFPR，WPA2 若 AP 与 STA 都开了 802.11w 也生效。
此时客户端的驱动在网络层就把未受保护的 deauth 丢掉（§1.3），我们的帧"发出去了但没人听"。
所以 `测试报告.md` 反复强调：帧上空气 ≠ 客户端断开。

【代码/实测】另一个失效方向是**收不到**：ESP32 的 11n 射频解不出 Wi-Fi 6（HE）PPDU，
只有 HE 客户端的 BSS 里嗅探不到 client→AP 帧，只能靠 500 ms 广播兜底（`blind=` 增长而
`rev=` 不动就是这个现象）。

### 2.4 实现与实测

【代码】注入不在混杂回调里做。`sniffer()`（`deauth.cpp:447`，`IRAM_ATTR`）只判断"该打谁"
并入队（`queue_deauth()` :327），主循环 `attack_step()` → `drain_tx_queue()` 按 1 ms 节拍出队；
驱动拒收（`ESP_ERR_NO_MEM`）时退避 5 ms 重试（`tx_raw()` :348）。这条结构修掉过
"计数在涨但帧没出去"的缺陷。

【代码】`deauth.cpp` 顶部覆盖了 `ieee80211_raw_frame_sanity_check()`（:22）返回 0，
这是 `esp_wifi_80211_tx()` 接受任意裸帧的前提（链接参数 `-Wl,-z,muldefs` 让重定义不报错）。

【实测】计数器：`txok/txerr/txec/txdrop/rev/blind/eliminated`，`STATS` 给每 AP 帧数。
样例（2026-11，`tests` 用例窗口）：`deauth_frames=14 txok=14 txerr=0 blind=8 rev=2`。
**没有做过"客户端真的掉线"的量化实验**：单板环境里没有可对照的真实客户端，
`测试报告.md §7` 把它列为未覆盖项。

---

## 3. Probe / Beacon 泛洪（`deauth.cpp`）

- CLI：`PROBE_BROADCAST`、`STOP`
- 入口：`deauth.cpp:777`（`attack_probe_broadcast()`）→ `attack_step()` :955 的
  `ATTACK_PROBE_BROADCAST` 分支

### 3.1 协议层定位

【标准】Beacon（mgmt subtype 8）是 AP 周期性宣告自己的帧，Probe Response（subtype 5）是对
Probe Request（subtype 4）的应答。两者都在**扫描**阶段被处理（MLME-scan），而且从不加密：
客户端要能在没有密钥的情况下发现网络，这是协议设计的前提。

【代码】攻击不碰任何状态机，只污染"空口上有什么网络"这个信息面：客户端与 WIDS 的扫描表、
自动选网逻辑、以及人眼看到的 SSID 列表。

### 3.2 帧格式

【代码】`build_beacon_like()`（`deauth.cpp:257`），beacon 与 probe response 共用：

```
0    2   Frame Control   0x80 0x00 (beacon) / 0x50 0x00 (probe response)
2    2   Duration        —
4    6   Addr1 = DA      0xFF*6（广播）
10   6   Addr2 = SA      随机 MAC（random_mac()，本地管理位置 1）
16   6   Addr3 = BSSID   同 Addr2
22   2   Sequence        0x0000
24   8   Timestamp       —（驱动写，见附录 B）
32   2   Beacon interval 100 TU
34   2   Capability      0x0431（ESS | short slot | short preamble）
36   ..  SSID (id 0)     随机 0..15 字符（random_ssid()）
..   ..  Supported rates (id 1) 8 条 legacy 速率 {0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24}
..   ..  DS parameter (id 3) 当前信道
```

【代码】节奏：每轮 4 组"beacon + probe response"（共 8 帧），每 4 ms 一轮，
每 120 ms 换一次信道（1..13，C5 上还含 5 GHz），`attack_step()` :945-973。

### 3.3 为什么有效 / 何时失效

【标准】Beacon/Probe 没有保护机制可用——PMF 明确不覆盖它们（要在密钥建立前就能收）。
所以它对**任何**安全模式的客户端都生效。

【标准/代码】它的"有效性"只到信息面：客户端扫描表被灌满、SSID 列表里出现一堆假网络、
用户手动选网时被误导。它不会让已关联客户端断开，也不会抢走连接（那需要伪造 AP + 更强的信号，
属于 Evil Twin 的范畴）。反过来，任何做了"扫描结果去重/合理性检查"的客户端都只是变慢。

### 3.4 实现与实测

【代码/实测】计数 `probe_frames` 是唯一判据；`tests` 里 3 s 的用例期望它明显增长，
样例 2512 帧/3 s。广播帧不需要 ACK，缓存会被立刻回收，所以它不受附录 B 的 20 帧/s 限制。

---

## 4. CSA 欺骗（`csa.cpp`）

- CLI：`CSA <idx> [ch] [cnt] [secs]`、`CSASTOP`、`CSATEST`
- 入口：`csa.cpp`（动作帧 `build_csa_action()` :133，克隆 beacon `build_beacon()` :151，
  应答 `build_auth_resp()` :221 / `build_assoc_resp()` :240）

### 4.1 协议层定位

【标准】CSA 是 802.11h（频谱管理）的一部分，作用是让 AP 通告"我要换到信道 N，倒计时 count"。
它有两种载体：

1. **Action 帧**（mgmt subtype 13，category 4 = spectrum management，action 4）；
2. **Beacon / Probe Response 里的 CSA IE**（element id 37，长度 3：mode / new channel / count）。

【标准】关键区别：Action 帧属 robust 管理帧类别（会受 PMF 校验），而 beacon 本身不是 robust 帧，
里面的 CSA IE 因此**没有任何完整性保护**。这就是"CSA 还能打、deauth 不能打"的真正原因。

### 4.2 帧格式

【代码】动作帧（`csa.cpp:133`，29 字节）：

```
0    2  FC 0xD0 0x00        ; mgmt / subtype 13 = action
4    6  Addr1 = RA         广播，或每个已知客户端
10   6  Addr2 = SA         AP 的 BSSID（伪造）
16   6  Addr3 = BSSID      同 Addr2
22   2  Sequence           0xF0FF
24   1  Category           4  = spectrum management
25   1  Action             4  = channel switch announcement
26   1  CSA mode           0  = 正常发送（1 = 静默，压制更强）
27   1  New channel        目标信道
28   1  Count              倒计时（TBTT 数）
```

【代码】克隆 beacon 里的 CSA IE 追加在 RSN 之后（`csa.cpp:207-212`）：

```
..  1  Element ID   37
..  1  Length       3
..  1  Mode         0
..  1  New channel  s_new_channel
..  1  Count        count
```

【代码】一轮通报（`send_csa_round()` :198）：3 条广播动作帧 + 每个已知客户端 1 条单播动作帧 +
1 条带 CSA IE 的 beacon；`count` 从 N 递减到 1，每 100 ms 一轮（≈100 TU，模仿真实 AP）。
之后进 HOLD：电台跳到新信道，每 100 ms 发一条同 BSSID/SSID/RSN 的克隆 beacon，
并对找上来的客户端回 Auth success / Assoc status 17（"拒绝，稍后再试"），
让"新信道上的假 AP"看起来存在但不给连（`csa.cpp` 的 `build_auth_resp` / `build_assoc_resp`，
计数器 `csaauth=` / `csarej=`）。循环直到 `CSASTOP`。

### 4.3 为什么有效 / 何时失效

【标准】客户端会按 count 倒数后切信道；切过去之后如果找不到"自己的 AP"，它会扫回原信道。
所以只发通告是不够的——必须在**新信道上维持克隆 beacon**，否则几秒后一切复原。
`csa.cpp:8` 的注释就是这个经验。

【标准】失效条件：①PMF 客户端会丢弃未受保护的 action 帧 → 只剩 beacon IE 这条路径；
②不跟随 beacon CSA 的客户端（部分 IoT 芯片）全程无感；③若目标 AP 同时在原信道继续工作，
客户端很容易找回去（真实环境里 AP 并不会真的搬走）。

【代码/实测】`测试报告.md §4.4.6` 把"客户端真的跳信道"列为未验证：现场没有可对照的客户端，
我们只证明了两种帧都能带着正确字段出空气（`csaf` 计数、`CSATEST` 逐字节）。

### 4.4 实现与实测

【代码】CSA 是**唯一**接入统一整流器 `tx_guard_send()` 的老模块（`csa.cpp:191`）：
广播帧不受限，单播帧与其它模块共享 45 ms 节拍，被挡下的帧在下一轮重发。
`csa_step()` 每 100 ms 推进一步，`csac` 记录已知客户端数，`csch` 是当前（或目标）信道。

【实测】`tests` 用例里 `csa=hold csaf=30 csac=0`、自动模式 `csaauto=1 csch=144 cycles=7`
（跨频段循环：2.4G AP → 5G 信道，反之亦然）。空口字段对照见 `测试报告 §4.4.1` 之外的
`CSATEST` 用例（`cat=4 act=4 mode=0 ch=.. count=..`）。
---

## 5. DELBA 欺骗（`delba.cpp`）

- CLI：`DELBA <idx> [reason]`（reason 只接受 1/32/37/38/39）、`DELBASTOP`、`DELBATEST`
- 入口：`delba.cpp`（构造 `build_delba()` :136，注入 `send_from_ap()` / `send_from_sta()` /
  `send_group()`）

### 5.1 协议层定位

【标准】Block Ack 是 802.11n 的聚合确认机制（条款名：*Block Ack*，802.11-2020 第 10 章的
Block Ack 机制 + 第 9 章的 ADDBA/DELBA Action 帧字段）。协商是 per-TID 的：

```
ADDBA Request  ──►  接收方建立重排窗口（WinStartB、BufferSize、BA agreement）
ADDBA Response ◄──
   ── 数据 ──      A-MPDU，接收方按 bitmap 回 BA
DELBA          ──►  任一方"我不再聚合这个 TID 了"
```

DELBA 的作用是**单方面拆会话**，category 3（Block Ack）action 2，带一个参数集
（Initiator / TID）和一个 reason code。

【标准】它属于 robust 管理帧类别，所以 PMF 客户端会拒收未受保护的 DELBA（§1.3）；
本节所有实测都在**非 PMF** 的链路上完成。

### 5.2 帧格式

【代码】`delba.cpp:136`，30 字节：

```
0    2  FC 0xD0 0x00        ; mgmt / subtype 13 = action
4    6  Addr1 = DA         受害 STA（AP→STA 方向）或 AP（STA→AP 方向）
10   6  Addr2 = SA         AP 的 BSSID / 伪造成 STA
16   6  Addr3 = BSSID      目标 BSS
22   2  Sequence           0xF0FF
24   1  Category           3 = Block Ack
25   1  Action             2 = DELBA
26   2  DELBA Parameter Set
         bit 11 = Initiator（我们置 1：声称"我这一侧要拆"）
         bit 12..15 = TID（0..7）
28   2  Reason Code        1 / 32 / 37 / 38 / 39（37 是真实 AP 最常用的）
```

【代码】触发方式（`delba_step()`）：嗅探到 QoS 数据帧就学 (MAC, TID)；嗅探到 ADDBA
Request/Response 就立刻补一帧定向 DELBA（`delbtr=` 计数）；都还没学到时退化为广播 DELBA
（`delbb`/`blind` 路径）。双向都发：AP→STA（"AP 拆了"）与 STA→AP（"客户端要拆了"）。

### 5.3 为什么有效 / 何时失效

【标准】DELBA 不需要双方同意，也不带序号协商——对端收到就把该 TID 的聚合会话拆掉，
回到"每帧一个 ACK"。这就是攻击面：**一条 30 字节的帧换掉整条链路的聚合能力**。

【标准】失效条件：

1. PMF（上面说了）；
2. 对端在那个 TID 上**没有会话**时会直接丢弃（`delba.cpp:6` 的注释），
   所以盲目扫所有 TID 基本是空动作，必须靠 ADDBA/QoS 帧学到"哪个 TID 真在用"；
3. 客户端立刻重新协商 ADDBA 会恢复——所以要么持续发，要么抢在 rekey/漫游窗口里发。

### 5.4 实现与实测

【实测】三块板、TCP 下载（`lab/rf_throughput`），数字取自 `测试报告.md §4.1`：

| 形态 | 攻击前 | 攻击中 | 结论 |
| --- | --- | --- | --- |
| 只发广播 DELBA（没学到客户端） | 480–550 KiB/s | 0–260 KiB/s | −75%，链路没断 |
| 学到 2 个客户端后按 TID 0–7 双向单播 | 550–600 KiB/s | 0–5 KiB/s | **−99%** |
| 学到 TID（只打 TID 0）后双向单播 | 590–650 KiB/s | 0–5 KiB/s | **−99%**，帧量更少 |

客户端全程**没掉线**（没有 deauth/disassoc，TCP 连接保持），只是吞吐塌了——与
"拆聚合 → 退回单帧确认"的机理一致。第二块板在同一信道被动监听拿到
`RXMIX action=84 delba=82`，说明帧确实在空口上、且第三方芯片按 `cat=3/act=2` 认得出来。
`DELBASTOP` 之后速率会回升，但有一段降速尾巴（AP 侧状态已经不同步）。

计数器：`delba`（开关）、`delbaf`（帧数）、`delbac`（学到的客户端数）、`delbat`（TID 位图）、
`delbab`（收到/发出的 ADDBA 数）、`delbtr`（按 ADDBA 触发的定向 DELBA 数）、`delbar`（BA/BAR 计数）。

---

## 6. BA 会话劫持（`delba.cpp`）

- CLI：`BAATTACK <idx> [step]`、`BAPLANT <idx> [step]`、`BARPUSH <idx> [step]`、
  `BASTOP`、`BATEST`、`BATX`、`BARSEQ <n> [gap]`
- 入口：`delba.cpp`（`build_addba_req()` :242、`build_bar()` :270、`ba_tx()` :288）

### 6.1 协议层定位

【标准】接收方为每个 BA 会话维护一个重排缓冲：`WinStartB` 由 ADDBA Request 里的
**Starting Sequence Number（SSN）** 初始化（条款名：*Block Ack* 的 reordering buffer 规则，
802.11-2020 §10.24 一带）。之后只有落在窗口里的 SN 会被接受，窗口外的帧被当作重复/过期丢弃。

【代码】攻击就是"用一条伪造的 ADDBA 把对方的 WinStartB 种到未来"：
`BAPLANT step=512` 把 SSN 设成"真实 SN + 512"，接收方从此等一个还没发生的序号，
真实流量全部落在窗口之前 → 被丢弃 → 该 TID 冻结，但链路层连接依旧。

### 6.2 帧格式

【代码】伪造 ADDBA Request（`delba.cpp:242`，33 字节）：

```
0    2  FC 0xD0 0x00
4    6  Addr1 = DA        受害 STA
10   6  Addr2 = SA        AP 的 BSSID
16   6  Addr3 = BSSID
22   2  Sequence          0xF0FF
24   1  Category          3
25   1  Action            0 = ADDBA Request
26   1  Dialog token      1
27   2  BA Parameter Set
         bit 0..1 = 0（立即生效）
         bit 2..5 = TID
         bit 6..15 = Buffer Size（kBaBufSize）
29   2  BA Timeout       0
31   2  Starting Sequence Control = (SSN & 0x0FFF) << 4
```

【代码】BAR（`delba.cpp:270`，20 字节，控制帧 subtype 8）：

```
0    2  FC 0x84 0x00        ; control / subtype 8 = Block Ack Request
2    2  Duration           ; 驱动重算
4    6  Addr1 = RA         受害 STA
10   6  Addr2 = TA         AP 的 BSSID
16   2  BAR Control        bit 4..7 = TID，bit 2 = compressed bitmap
18   2  BAR Information    (SSN & 0x0FFF) << 4
```

【代码】三种玩法：`BAATTACK` = DELBA 清场 → 伪造 ADDBA → BAR 循环；
`BAPLANT` = 只种一次窗口就完全静默（用来把"窗口效应"和"持续注入"分开）；
`BARPUSH` = 只发 BAR 不碰 ADDBA（对照组）。`BARSEQ` 是纯诊断（看 BAR 会不会被池子卡住）。

### 6.3 为什么有效 / 何时失效

【标准】有效性来自两个设计事实：①ADDBA Request 可以被任何"看起来是 AP"的帧触发；
②接收方接受 SSN 时不做合理性检查（没有"SSN 不能超过我已经收过的 SN"这类约束）。

【标准/实测】失效/边界：

1. **PMF**：ADDBA/DELBA 都是 robust，强制 PMF 时这条链断掉；
2. `step=0` 的对照组**在 ESP-IDF 目标上也会打死**（见下表）——说明"任何伪造 BA 类帧"
   都能破坏这类实现，**"窗口被推走"这一步无法在该目标上单独证明**。真正把窗口效应分离出来
   的是 Android 那次对照：`BARPUSH 512` 视频卡死，`BARPUSH 0` 正常播放（用户现场观察、单设备、
   无抓包，证据强度按 `测试报告.md` 原样记录）；
3. 目标要能重新关联才恢复（通常要重启 Wi-Fi）。

### 6.4 实现与实测

【实测】`测试报告.md §4.2`（ESP32 AP + C5 STA，ch1，TCP 下载）：

| 条件 | 攻击前 | 静默期 | 停手 8 s | 恢复方式 |
| --- | --- | --- | --- | --- |
| `BAPLANT step=512` | 386 KiB/s | 26–30 KiB/s | 0 | 重新关联后 >380 |
| `BAPLANT step=0`（对照） | 404 KiB/s | 43 / 8 KiB/s | 0 | 同上 |
| `BAATTACK`（持续 15 s） | 302 KiB/s | 22–26 KiB/s | 67 | 同上 |
| `BARPUSH step=512` | 304 KiB/s | 12 KiB/s | 3–16 | 同上 |
| `BARPUSH step=0`（对照） | 340 KiB/s | 0–3 KiB/s | 0 | 同上 |

【实测】注入限速的教训：一次把整个"TID × 方向"矩阵打进 32 个短缓存会让 `baerr` 暴涨
（15 s 内 `baerr=1559`，其中 `bae=257` = `ESP_ERR_NO_MEM`），后来改成"每轮最多 4 帧 + 失败
退避 5 ms"；`BARSEQ 100 30` 证明 BAR 本身会回收缓存（30 ms 节拍 100 帧零失败）。
这段是附录 B 的直接来源。

---

## 7. BTM 强制漫游攻击（BTM steering，`btm.cpp`）

- CLI：`BTM <idx> [timer] [sta-mac] [cand-bssid] [cand-ch] [cand-info]`、`BTMSTOP`、`BTMTEST`
- 同一族的 802.11k 通道（伪造 Neighbor Report Response）见 §14；两者是同一层、同一个 PMF 边界，只有 category 不同
- 入口：`btm.cpp`（构造 `build_btm_request()` :172，能力学习 `learn_capabilities()` :155，
  发送节拍 `btm_step()` :253）

### 7.1 协议层定位

【标准】802.11v 的 WNM 是"网络辅助漫游"的一套管理动作（条款名：*Wireless network management*，
BSS Transition Management 在其中）。AP 可以主动告诉客户端"去连另一个 BSS"，
并给出时间压力：`Disassociation Imminent` + `Disassociation Timer`（单位 TBTT）。

【标准】它走 Action 帧（mgmt subtype 13，category 10 = WNM，action 7 = BTM Request）。
**category 10 属于 robust 管理帧集合**：Linux 的判定是"除 Public/HT/Unprotected WNM/
Self-protected/VHT/厂商自定义之外的所有 category 都算 robust"
（`_ieee80211_is_robust_mgmt_frame()`），802.11-2020 也专门有 category 11
"Unprotected WNM"来给确实要裸发的那几条留口子。也就是说：

- PMF 关闭或可选（绝大多数 WPA2 部署）→ 伪造帧被接受，客户端真的会去扫/漫游；
- PMF 强制（WPA3 / MFPR）→ 客户端驱动按"未受保护的 robust 管理帧"直接丢弃
  （`net/mac80211/rx.c` 的 `ieee80211_drop_unencrypted_mgmt()`），802.11v 代码根本跑不到。

所以这条通道**不是 PMF 绕过**，而是"不需要断开连接也能把客户端推走"的另一条路。
（`btm.cpp` 顶部注释、`btm.h`、GUI 文案都已按这个事实改写；`firmware/README.md §5`
原先写的"PMF 不保护 BTM"是错的，本文为准。）

### 7.2 帧格式

【代码】`build_btm_request()`，固定 **31 字节**（空口 35，含 FCS）。不再带候选列表——理由见 §7.4 的实测：

```
0    2  FC 0xD0 0x00        ; mgmt / subtype 13 = action
4    6  Addr1 = RA        受害 STA（BTM Request 只有单播形式）
10   6  Addr2 = SA        AP 的 BSSID（伪造的 TA）
16   6  Addr3 = BSSID
22   2  Sequence          0xF0FF
24   1  Category          10 = WNM
25   1  Action            7  = BTM Request
26   1  Dialog token      1..255 循环
27   1  Request Mode      bit 0 = Preferred Candidate List Included
                          bit 2 = Disassociation Imminent   → 恒为 0x04（不带候选列表）
28   2  Disassociation Timer（TBTT 数，缺省 10；0 = 客户端不扫）
30   1  Validity Interval 10（请求的新鲜期，单位 beacon interval）
```

整帧 **31 字节**（空口 35，含 4 字节 FCS）；给了 `cand-bssid` 时再追加下面那个元素，变成 **46 字节**
（空口 50）。默认不带候选列表：旧实现里的"带一个随机幻影候选"被实测证明无效，已删除；
现在带候选必须由命令行指定一个**真实存在**的 BSSID，见 §7.4。

【代码】可选候选元素（id 52，长度 13；只在 `cand-bssid` 给出时出现）：

```
..  1  Element ID        52
..  1  Length            13
..  6  Candidate BSSID   随机本地管理地址（`02:..`，一个不存在的 BSS）
..  4  BSSID Information 0x00000003（bit0 AP reachable | bit1 same security policy）
..  1  Operating Class   operating_class(ch)：≤14→81，≤48→115，≤64→116，≤144→117，其余→121
..  1  Channel Number    默认挑一个与目标不同的 2.4G 信道（5G 信道 2.4G-only 客户端扫不到）
..  1  PHY Type          7 = HT
```

【代码】节奏与目标筛选：每 300 ms 对每个客户端重发一次（`kRepeatMs`），全局 50 ms 节拍
（`kGlobalGapMs`）——节拍属于电台而不是每个客户端，八个客户端也不能把注入率乘八。
目标只挑**声明支持 11v** 的 STA：嗅探客户端自己的 Probe Request / (Re)Association Request，
看 Extended Capabilities 元素（id 127）的 **bit 19（BSS Transition）**；不支持的直接跳过
（`btmskip=` 计数）。

### 7.3 为什么有效 / 何时失效

【标准】客户端为什么会听？因为 BTM Request 的语义就是 AP 在"建议"漫游，客户端没有理由
怀疑——它只用 TA == 当前 AP BSSID 这一条来判定来源，而裸注入可以随便填 TA。

【代码】wpa_supplicant 的具体行为（`wpa_supplicant/wnm_sta.c`，参考实现）：

- `Disassociation Imminent` 置位**且** timer ≠ 0 才会触发扫描；timer = 0 表示"没有期限"，
  什么都不做——这就是本模块把 timer 缺省成 10 的原因；
- 带候选列表时只扫那个 BSSID（一个不存在的 BSSID = 每次请求都变成一次"离信道空跑"）；
- 不带列表时客户端回一个 BTM Response（reason = "reject, unspecified"），但仍然会扫。

【标准/代码】失效条件：①PMF 强制（上面）；②客户端不支持 11v（`btmskip` 会涨）；
③客户端把"候选 BSS 不在我扫得到的范围内"当作无效请求（部分实现）；
④客户端设置了 `disable_btm` 之类的策略。

### 7.4 实现与实测

【实测】`测试报告.md §4.4.1`（**旧命令形态**，当时还有 `cand` 模式）：`BTM 2 cand 10 6 02AABBCCDDEE`，
5 s 内 64 帧 BTM Request 上空气，
字段 `cat=10 act=7 req_mode=0x05`、`timer=10`、`validity=10`、
候选 `Neighbor Report eid=52 len=13 op_class=81 ch=6 phy=7`，TA = AP BSSID、RA = 伪造 STA。

【实测】对端反应：2026-11-15 用一台**真的声明了 11v 的 STA**（ESP32-C5 跑
`lab/rf_throughput` 的 `sta` + `btm 1`，`CONFIG_ESP_WIFI_11KV_SUPPORT=y`）做端到端：

```
BTM 0 cand 10 0   -> 8 s 发 23 帧      （旧形态）
   btmc=1       能力判别正确：STA 的 Association Request 里确实有 Extended Capabilities bit 19
   btmresp=0    但 STA 一句也没回（btms=0）
```

ESP-IDF 的 11v 只公开了 `WIFI_EVENT_STA_NEIGHBOR_REP`（11k），**没有 BTM 事件/回调**，
BTM 逻辑全在闭源 wifi 库里——它是否静默扫了一次从计数上看不出来（攻击期间 STA 侧 RATE
没有停顿）。所以**「客户端应答」这种端到端证据在 ESP-IDF STA 上拿不到**；要判它是否真的
处理了 BTM，需要一个会回 BTM Response 的客户端（wpa_supplicant 的 `wnm_sta.c` 会回，
Android / 桌面 Linux 更合适）。

【实测】2026-11-22，用 `lab/victim_btm`（11KV 打开、`ps 0` 一直醒、记录断开 reason 与最终关联 BSS）
在两种受害者上跑：软 AP 和**本机真实的华为 WPA2 AP**（`BE:41:99:0B:20:36`，ch12）。

**带候选列表（旧 `cand` 形态，已从代码删除）：收到、回应、不漫游**

| 场景 | 当时的形态 | 请求/响应 | 结果 |
| --- | --- | --- | --- |
| 软 AP + 11v 开 | 带候选（幻影 BSSID） | 42 / **44** | 不断开 |
| 软 AP + 11v 开 | 不带候选 | 55 / 0 | 不断开 |
| 软 AP，`btm 0` 对照 | 带候选 | 72 / 0 | 不断开（连响应都没有） |
| 真华为 AP | 带候选 | 97 / 50（`btms=7`） | 不断开 |
| 真华为 AP | 不带候选 | 152 / 19 | 不断开 |

带候选时几乎每条请求都回一条 BTM Response —— 只有解析了 dialog token 的 STA 才会回，所以帧确实
被收下并处理了；但候选 BSSID 是随机幻影，扫不到，STA 没有可去的地方。所以那一半代码没有用，
干脆删掉：**现在模块只发不带候选列表的形态**。

**第二 BSS 真实存在时：STA 被拐走**（同 SSID、同 WPA2 口令、ch6，我们自己的软 AP；旧 AP 在 ch12）

- 对照：第二 BSS 开着、`-6 dBm`（比旧 AP 强 29 dB），**90 s 不发 BTM** → victim 一动不动，
  仍在 ch12。
- 发 `BTM <idx> 10 <victim-mac>`（TA = 华为 BSSID；现在只有这一种形态）→
  `EVT sta_disconnected reason=207 ROAMING`（旧 AP `rssi=-36`）→
  `EVT sta_connected bssid=<我们的软 AP> ch=6`，`back_after=0.072s`，随后从我们的 DHCP 拿到 IP。

结论（这条路真实有效，但边界要写清）：
1. **只要攻击者能提供同 SSID、同安全模式、能被扫到的第二个 BSS，一条伪造 BTM 就能把已关联的
   真实 STA 拽过来**，不需要真 AP 的密码，也不需要 deauth。之后就是 Evil Twin 的猎场。
2. ESP-IDF 上报的码是 **`207 WIFI_REASON_ROAMING`**，不是标准里的 12
   （`WIFI_REASON_BSS_TRANSITION_DISASSOC`）。判据要按两个一起 grep。
3. 命中条件是**环境里真的有一个同 SSID、同安全模式、扫得到的 BSS**——凭空造一个候选 BSSID
   （旧 `cand` 形态）只会换来一条 BTM Response。所以这条攻击天然和"造一个同名 BSS"成对使用。
4. 指定候选（`cand-bssid`）能进一步收窄：2026-11-22 实测把候选指向我们 ch6 的软 AP，
   STA 在 0.099 s 内就漫游过去了，且**没有回 BTM Response**——所以"回不回应"不能当判据，
   最终连到哪个 BSS + reason 才是。
4. 这台华为 AP 不强制 PMF（victim 用默认 PMF 配置能关联上，推断），所以未保护的 BTM 没被 PMF 挡掉。

【实测/教训】第一轮 victim 用驱动默认 `WIFI_PS_MIN_MODEM`，空口能看到它发 `NULL ... pm=1`：
睡着的 STA 只在 DTIM 附近开窗，第三方注入的单播帧大部分听不见（那几轮 `btmresp` 只有 0~3）。
**任何"注入进去了但对方没反应"的实验，先确认对方醒着**。详见 `firmware/测试报告.md §4.4.12`。

## 8. TIM 投毒（`tim.cpp`）

- CLI：`TIM <idx> [tim|clear] [aid]`、`TIMSTOP`、`TIMTEST`
- 入口：`tim.cpp`（`build_tim()` :146，`build_beacon()` :197，AID 学习 `note_aid()` :89）

### 8.1 协议层定位

【标准】省电模式（PS）是 MAC 层的一套睡眠调度：客户端按 **DTIM 周期**醒来看 Beacon 里的
**TIM 元素**（element id 5），自己的 AID 位被置位就说明"AP 给你缓存了帧"，于是保持清醒
或发 PS-Poll 取回来。Beacon 不加密、不带完整性保护（PMF 明确不覆盖 beacon），
所以这条通道对开启了 PMF 的网络同样成立。

【标准】**TIM 元素的两个位图概念必须分清**（这是本节的重点）：

1. **Bitmap Control**（1 字节）：
   - **bit 0 = Traffic Indicator**，对应 **AID 0**，也就是"组播/广播有没有缓存"这盏灯；
   - **bit 1..7 = Bitmap Offset**，表示 Partial Virtual Bitmap 从哪个 AID 开始，
     单位是 **2 个字节（16 个 AID）**。
2. **Partial Virtual Bitmap**（变长）：**按 AID 编号索引**——第 i 个字节的第 j 位代表
   `AID = 16 × BitmapOffset + 8i + j`。所以 Offset=0 时 **AID 1 在 bit 1，bit 0 是 AID 0**。

   核对方式：Wireshark 的 TIM 解析就是 `aid = 8*n1 + 8*i + j`，其中
   `n1 = bitmap_control & 0xFE`（= 2 × offset），见 `epan/dissectors/packet-ieee80211.c`
   的 `ieee80211_tag_tim()`；标准条款名是 *TIM element*（802.11-2012 起在 8.4.2.7，2020 版编号位移）。

**这条是本仓库修过的一个真实 bug**：早期实现按"bit (AID−1)"编码，等于把 AID 1 的位写到了
AID 0（组播位）上，把 AID 3 的位写到了 AID 2 上——攻击"打偏一格"。现在按 `AID/8` 字节、
`AID%8` 位编码（`tim.cpp:157` 起），`TIMTEST` 对 AID 3 打印 `bitmap=08`。

### 8.2 帧格式

【代码】克隆 beacon（`tim.cpp:194`），除 TIM 外全部照抄真实 AP：

```
0    2  FC 0x80 0x00        ; mgmt / subtype 8 = beacon
4    6  Addr1 = DA         0xFF*6（广播）
10   6  Addr2 = SA         AP 的 BSSID（与真 AP 相同）
16   6  Addr3 = BSSID
22   2  Sequence           0xF0FF（固定，见下）
24   8  Timestamp          —（驱动写，见附录 B）
32   2  Beacon interval    学自真 AP（真 AP 100 TU）
34   2  Capability         学自真 AP
36   .. SSID (id 0)        学自真 AP
..   .. Supported rates (id 1) legacy 8 条
..   .. DS parameter (id 3) 目标信道
..   4+ TIM (id 5)         见下
..   .. RSN (id 48)        学自真 AP（`tim.cpp:113`）
```

【代码】TIM 元素（`build_tim()`）：

```
..  1  Element ID      5
..  1  Length          3 + bitmap 字节数
..  1  DTIM Count      0（本条 beacon 就是 DTIM → 每个 client 都全醒）
..  1  DTIM Period     学自真 AP（学不到时 2）
..  1  Bitmap Control  0x00 —— bit0（组播灯）清零，offset = 0
..  n  Partial Virtual Bitmap
       tim 模式：按 AID 置位（AID n → byte n/8 的 bit n%8），只发到最高非零字节
       clear 模式：一个字节 0x00（声称"谁都没有缓存"）
```

【代码】节奏：每 20 ms 一帧（真 AP 100 TU ≈ 102 ms，即 5 倍占空比），广播帧不等 ACK，
不占单播缓存池。**必须先从空口学到目标 AP 的真 beacon 才会发第一帧**
（`s_have_beacon`，`tim.cpp:292`）：SSID 为空、interval 缺省的克隆帧对客户端来说是"另一个坏网络"，
不是冒充。

【代码】AID 从哪来：Association / Reassociation Response 里偏移 28..29 的 AID 字段
（掩到 14 位），由混杂回调 `tim_on_rx()` 学成 (MAC, AID) 表（最多 8 个）；
学不到时 `tim` 模式兜底点亮 AID 1（`bitmap[0] = 0x02`）。

### 8.3 为什么有效 / 何时失效

【标准】两种反方向的效果：

- `tim`（置位）：客户端以为"AP 有我的缓存帧"，于是一直醒着、反复发 PS-Poll，空耗电与空口；
  叠加 DTIM Count = 0，等于让所有客户端每个 beacon 都全醒。
- `clear`（清空）：客户端以为"没有我的帧"，于是继续睡；真实下行被它自己忽略，
  表现为"信号满格但丢包"。

【标准/代码】失效条件：

1. 客户端只在**自己关联的 BSS** 里信 TIM，所以克隆帧必须逐字节像真 AP（SSID/RSN/capability/
   interval 全照抄）——做不到就只是一个假网络；
2. 占空比要压过真 AP（20 ms vs 102 ms），但功率/位置仍是物理前提；真 AP 的 beacon 更强时
   客户端可能只信真 AP（`测试报告 §4.4.2` 的抓包里两种 beacon 并存，克隆约 5:1）；
3. 省电有"错过 N 个 beacon 就认为 AP 消失"的阈值（missed beacon / listen interval），
   长时间只收到克隆帧的客户端可能干脆退网重扫——这正是效果"介于省电失效到诱发退网之间"
   的原因，需要 bench 量化；
4. 一直用 CAM（不休眠）的设备完全无感。

### 8.4 实现与实测

【实测】`测试报告.md §4.4.1`：`TIM 2 tim 0`，5 s 内 264 帧克隆 beacon（seq 恒 `0xFFF`），
`interval=100`、`TIM: dtim_count=0 period=1 ctrl=0x00 bmp=0x01`（旧编码下 AID 1 落在 bit 0）、
SSID/RSN/capability 与真 AP 一致，`tsf=0`。

**注意**：那行 `bmp=0x01` 是**修正前**的实测值，保留作为历史记录。修正后的空口复测已经做过
（2026-11-15，`lab/tim_air.py`：COM5 攻击 + COM6 跑 `lab/rf_throughput` 的 `sniff 12`）：

```
BE:41:99:0B:20:36 00010008  x289  bitmap=08 aids=[3]   <- 克隆帧（AID 3 落在 bit 3）
BE:41:99:0B:20:36 00010000  x111  bitmap=00 aids=[]   <- 真 AP（没有缓存帧）
00:5C:C2:DB:EC:58 00010004  x17   bitmap=04 aids=[2]   <- 别的真 AP：AID 2
00:5C:C2:DB:EB:DC 00010020  x7    bitmap=20 aids=[5]   <- 别的真 AP：AID 5
```

那两条**真实 AP** 的位图是编码规则的旁证：AID 5 落在 `0x20`（bit 5），不是 `0x10`。

计数器：`tim`（off/tim/clear）、`timf`（帧数）、`timaid`（学到的 AID 位图，**显示用**：
bit0 = AID 1）、`timreal`（学到的真 beacon 数，为 0 说明一帧都没发）。

【实测】**客户端的省电行为没有被改变**（2026-11-15，`lab/tim_ps.py`，三块板：
ESP32 当 softAP + TCP 打流、ESP32-C5 当 `WIFI_PS_MIN_MODEM` 的 STA、CYD 当攻击板）：

| 阶段 | AP 侧 RATE 均值 | 样本 | STA 掉线 |
| --- | --- | --- | --- |
| baseline（ps 1） | 385 KiB/s | 18 | 0 |
| `TIM clear` | 424（+10%） | 12 | 0 |
| `TIM tim` | 397（+3%） | 12 | 0 |
| baseline（ps 0） | 460 | 17 | 0 |

省电本身是生效的（ps 1 → 385 对 ps 0 → 460，−16%），所以不是"STA 没睡"。
**阳性对照**：同一链路同一位置发 `DEAUTH`，10 s 内掉线 6 次、RATE 333 → 32 KiB/s，
说明伪造帧被采信——null 不是"收不到"。

最可能的解释（未逐条证伪）：①克隆 beacon 的 Timestamp 被 MAC 改成接口自己的 TSF（未关联时为 0），
而省电 STA 的唤醒时刻（TBTT）正是用 beacon 的 TSF 对齐的，20 ms 一拍的克隆与真 AP 的 TBTT 不同相，
睡眠中的 STA 大概率不在那一刻开窗收它——**这条攻击的天花板与附录 A 里"TSF 上不了空口"是同一条**；
②真 AP 每 100 TU 还在发自己的 beacon，它的 TIM 才是权威值。
还有一个实现细节：AID 只在**关联瞬间**的 Association Response 里学到，先关联后开攻击就会 `timaid=0`
（落到 AID 1 兜底）——要精确打某个 AID，得在受害者关联前启动，或用 `TIM <idx> tim <aid>` 指定。

**交叉引用**：§13 的 PS 位欺骗打的是同一个省电机制的**另一端**（伪造 STA 的 PM=1 声明，让 AP
把下行缓存起来）。两者的叠加效果没有做过组合实验，边界各自独立，见 §13.3 末尾。

---

## 9. EAPOL-Start / Logoff 洪泛（`eapol.cpp`）

- CLI：`EAPOL <idx> [tid|-1] [sta-mac]`、`EAPOLSTOP`、`EAPOLTEST`
- 入口：`eapol.cpp`（构造 `build_eapol()` :94，接收侧统计 `eapol_on_rx()` :193）

### 9.1 协议层定位

【标准】EAPOL 不属于 802.11，它是 **802.1X** 的认证协议（IEEE 802.1X，条款名：*EAPOL PDU
format* / *Port-based network access control*），在 802.11 里被封装在**数据帧**里，
用 LLC/SNAP 头声明 EtherType `0x888E`。所以它是"链路层之上的认证控制面"，
802.11 的 PMF 管不到它——但它的**可用性**由 802.11 的加密规则和 AP 的实现决定。

【标准】认证方（AP）为每个端口维护一个状态机：收到 EAPOL-Start → 重新开始认证
（发 EAP-Request/Identity）；收到 EAPOL-Logoff → 把端口打回未授权态。这两个报文
（type 1 / type 2）都是 4 字节头、无载荷。

【代码】这一步决定了攻击形态：**伪造受害 STA 的 MAC** 往 AP 发 Start/Logoff，
让它的端口在"授权/未授权"之间抖动，而不是去破解密钥。

### 9.2 帧格式

【代码】`eapol.cpp:94`，非 QoS 36 字节 / QoS 38 字节（抓包 40 / 42，含 FCS）：

```
0    2  FC 0x08 0x01 (非 QoS) / 0x88 0x01 (QoS data)   ; data / subtype 0 或 8，ToDS=1
2    2  Duration        —
4    6  Addr1 = RA      AP 的 BSSID
10   6  Addr2 = TA      受害 STA MAC（伪造）
16   6  Addr3 = SA      AP 的 BSSID
22   2  Sequence        0xF0FF
24  [2] QoS Control     QoS 变体才有：TID 在 bit 0..3（缺省 6）
     8  LLC/SNAP        AA AA 03 | 00 00 00 | 88 8E
   +4  EAPOL 头         version = 2（802.1X-2004）
                        packet type = 1 (Start) / 2 (Logoff)
                        body length = 0x0000
```

【代码】两种帧交替发：非 QoS 数据帧与 QoS 数据帧（TID 缺省 6，wpa_supplicant 给 EAPOL 用的
语音类 TID），因为有些实现只认其中一种；Start 与 Logoff 也交替（每发一帧翻一次），
每个受害者轮流，50 ms 一帧（`kSendMs`）。

### 9.3 为什么有效 / 何时失效

【标准】有效性依赖两件事：①AP 认为"EAPOL 只看发送方 MAC"，不校验内容真伪；
②Start/Logoff 是"无认证的低成本报文"，重放它不需要任何密钥。

【标准/实测】失效条件（这条要分开写，因为现场同时满足了两条，我们没能区分是哪一个起的作用）：

1. **WPA2-PSK 没有 802.1X 状态机**：PSK 网络不做端口认证，Start/Logoff 没有语义；
2. **已关联 STA 的明文数据帧会被丢弃**：我方伪造的是"已关联的真实 STA"，
   在密钥已建立的情况下，AP 期待该 STA 的数据帧是加密的（未加密的会被当作非法/重复被丢）。
   我们的实验无法把这条与上一条分开——两种原因都指向"AP 不回任何东西"；
3. PMF 与它无关（EAPOL 在 PMF 之外），所以这条通道的瓶颈不在加密强度而在**认证架构**：
   只有 WPA2/WPA3-Enterprise（802.1X）网络才有得打。

### 9.4 实现与实测

【实测】`测试报告.md §4.4.1/§4.4.2`：`EAPOL 2 6 02AABBCCDDEE`，5 s 内 108 帧上空气，
非 QoS `len=40 subtype=0` 与 QoS `len=42 subtype=8 tid=6` 交替，`AAAA03...888E ver=2 type=1/2`，
TA = 受害 STA、RA = AP。对端**完全无回应**：`eaprxreq=0`（AP 没有发 EAP-Request/Identity）、
`eaprxsta=0`（真实 STA 也没有重新认证）。

【代码】判据是接收侧而不是发送侧：`eaprxreq` > 0 才说明"状态机真被踢动了"；
只看 `eapf` 涨是没有意义的。功能面目前只证明"帧格式对、能上空气"。
---

## 10. SAE Commit 洪泛（`sae.cpp`）

- CLI：`SAE <idx> [point|rand] [gap_ms]`、`SAESTOP`、`SAETEST`
- 入口：`sae.cpp`（构造 `build_commit()` :138，token 提取 `store_token()` :188，
  WPA3 判别 `sae_classify()` :211）

### 10.1 协议层定位

【标准】SAE（Simultaneous Authentication of Equals）是 WPA3-Personal 的认证方式
（条款名：*SAE*，属于 RSNA 的 AKM suite `00-0F-AC:8`；另外 `:9` = FT-SAE、`:24` = SAE-EXT-KEY
也算"这个 BSS 跑 SAE"）。握手第一帧是 Authentication（mgmt subtype 11），
algorithm 3、transaction sequence 1 = **Commit**，body 里是：

```
finite cyclic group（2 B） | [anti-clogging token] | scalar（素数长度） | element（2×素数长度）
```

【标准】Commit 里的 element 是一个椭圆曲线点，AP 收到后必须做**点校验 + 标量乘**才能判断
commit 是否有效——这是 AP CPU 上最贵的运算之一，而且**在密钥建立之前**就要做。
这就是攻击面：不需要知道密码、不需要完成握手，就能让对方算一次。

【标准】协议内的缓解是 **anti-clogging token**：AP 用 status 76 回一个 token，要求客户端
"原样带着它再发一次"，把无状态洪泛变成需要收发的往返（反射测试）。所以真正的效果取决于
token 回显做得对不对——本模块把 token 存成"每个身份一份"，并按它出现的两种形状回显。

### 10.2 帧格式

【代码】`sae.cpp:138`，128 字节（P-256，无 token；抓包 132，含 FCS）：

```
0    2  FC 0xB0 0x00        ; mgmt / subtype 11 = authentication
4    6  Addr1 = DA         AP 的 BSSID
10   6  Addr2 = SA         随机本地管理 MAC（每 4 帧换一个身份，最多 8 个在轮转）
16   6  Addr3 = BSSID      AP 的 BSSID
22   2  Sequence           0xF0FF
24   2  Algorithm          3 = SAE
26   2  Transaction seq    1 = Commit
28   2  Status             0
30   2  Group              19 = P-256（2 字节小端）
32   32 Commit scalar      随机
64   64 Commit element     point 模式 = P-256 生成元（合法点）；rand 模式 = 随机字节
                                                        24 + 8 + 32 + 64 = 128
带 token 时（非 H2E）：token 插在 group 之后、scalar 之前，原样字节；
带 token 时（H2E）：element 之后追加 Element 255 / Ext ID 93 容器：FF len 5D <token>
```

【代码】`point` 是缺省：只有**合法点**才会让 AP 走进昂贵的那一步；随机字节会让它在校验阶段
就丢弃（`rand` 是对照组，用来证明"贵在哪一步"）。
身份轮换（`kFramesPerIdentity = 4`）是为了让 AP 每次都要新建 SAE 状态：token 和状态都是
per-station 的。

### 10.3 为什么有效 / 何时失效

【标准】有效性来自"用对称的算力差换对方 CPU"：我们发一个随机 scalar + 一个固定点（几乎零成本），
AP 要做一次标量乘。

【标准】失效条件：

1. **目标不是 WPA3**：SAE 只存在于 AKM 8/9/24 的 BSS。对 WPA2-PSK 的 AP 发 Commit，
   它会回 `status 13`（"authentication algorithm not supported"）——完整解析、直接拒绝，
   零成本。本模块先做 `sae_classify()` 判别，`AUTHFLOOD` 的自动升级也用同一套判别；
2. **anti-clogging 生效**：AP 回 status 76 且不回显就不干活时，我们必须在下一帧带上 token。
   回显做对了才真正买到算力消耗，做错了就只是"制造流量"；
3. **AP 侧限速/黑名单**：企业 AP 通常有 per-MAC 的 auth 速率限制，随机 MAC 轮换是对策。
   （现场没有可信的 WPA3 AP，以上第 2、3 条**未实测**。）

### 10.4 实现与实测

【实测】`测试报告.md §4.4.1`：`SAE 2 point 20`，5 s 内 1076 帧 Commit 上空气，
`alg=3 seq=1 status=0 group=19 len=132`，TA 每 4 帧换一个随机 MAC。
对端（WPA2 华为 AP）回 `len=34 seq=2 status=13` —— **格式对、目的 MAC 对，只是这个 BSS 不吃 SAE**。

【实测】速率：SAE 是单播 + 伪造 TA，属于附录 B 限制最狠的一类。50 帧/s 跑 63 帧就 `0x101`
（`gap_ms` 低于 50 会被固件抬到 50 并打 `INFO`）。

计数器：`sae`（on/off）、`saesec`（嗅探判定的目标安全类型 `wpa2-psk`/`wpa3-sae`/`wpa2/wpa3`）、
`saef`（帧数）、`saec`（身份数）、`saeresp`（AP 回帧数）、`saecode`（最后状态码：76 = 要 token）、
`saetok`（收到 token 数）、`saeecho`（带 token 发出的帧数）。

---

## 11. Auth / Assoc 洪泛（`authflood.cpp`）

- CLI：`AUTHFLOOD <idx> [both|auth|assoc] [noauto]`、`AUTHFLOODSTOP`、`AUTHFLOODTEST`
- 入口：`authflood.cpp`（`build_auth()` :89、`build_assoc()` :109、
  WPA3 自动升级 `authflood_step()` :182）

### 11.1 协议层定位

【标准】每个 STA 接入都要走两步：Authentication（mgmt subtype 11，开放系统 = algorithm 0，
seq 1 请求 / 2 应答）然后 Association Request（mgmt subtype 0）。
AP 为此给每个发射地址维护一条状态机 + 一条 **station 表项**（AID、能力、密钥上下文）。
认证和关联都发生在密钥建立**之前**，因此**不可能加密**——PMF 在这两步上无能为力。

【代码】于是攻击面是"状态与表项是有限资源"：每个新 MAC 都让 AP 分配一次；表项满了，
合法 STA 就被拒（`status 17` = "association denied because AP is unable to handle
currently associated STAs"）。这也是"只发 Auth 不跟 Assoc"能省一半开销但有意义的原因：
不同实现对"认证了但没关联"的过期策略比"关联了"更激进。

### 11.2 帧格式

【代码】Authentication（`authflood.cpp:89`，30 字节）：

```
0    2  FC 0xB0 0x00        ; mgmt / subtype 11
4    6  Addr1 = DA         AP 的 BSSID
10   6  Addr2 = SA         随机本地管理 MAC（每轮一换）
16   6  Addr3 = BSSID      AP 的 BSSID
22   2  Sequence           0xF0FF
24   2  Algorithm          0（开放系统）
26   2  Transaction seq    1（request）
28   2  Status             0
```

【代码】Association Request（`authflood.cpp:109`，长度随 SSID/RSN 变化）：

```
0    2  FC 0x00 0x00        ; mgmt / subtype 0
4    6  Addr1 = DA         AP 的 BSSID
10   6  Addr2 = SA         同一个随机身份
16   6  Addr3 = BSSID
22   2  Sequence           0xF0FF
24   2  Capability         0x0411（ESS | privacy）
26   2  Listen Interval    10
28   1  SSID (id 0)        学自目标 beacon（长度 + 内容）
..   1  Supported rates    8 条 legacy 速率
..   1  RSN (id 48)        学自目标 beacon（逐字节照抄）
```

【代码】SSID 与 RSN 必须照抄目标 AP：否则 AP 在查 station 表**之前**就把帧拒了，
洪泛等于免费（`authflood.cpp:12` 的注释就是这个教训）。`both` 模式下每个身份
"先 Auth 再 Assoc"，然后换新 MAC；`auth`/`assoc` 模式每帧换身份。

### 11.3 为什么有效 / 何时失效

【标准】有效性：认证/关联无需密钥即可发送，且 AP 必须以"这是新客户端"的姿态处理；
随机 MAC 让 AP 无法用"同一个 MAC 又来烦我"来限速。

【标准/代码】失效条件：

1. **WPA3-SAE 的 AP**：它不接受开放系统认证（回 `status 13`），根本不分配状态机，
   洪泛对它是免费的。本模块嗅到 AKM 是 SAE 就自动停手并转 `sae_start()`
   （`afup=1`，打一行 `INFO AUTHFLOOD wpa3-sae -> SAE commit flood`）；
2. **表项老化速度**：打太快只触发反制阈值（有些 AP 会临时拉黑源 MAC），打太慢表项被老化腾出，
   节奏要和 AP 的老化时间赛跑——本模块固定 50 ms 一帧（附录 B 的上限），
   没有做自适应；
3. `auth`/`assoc` 单模式在部分实现上更早触发"关联但无密钥"的清理。

### 11.4 实现与实测

【实测】`测试报告.md §4.4.1/§4.4.2`：`AUTHFLOOD 2 both noauto`，6 s 内 817 帧上空气，
`alg=0 seq=1 status=0 len=34`，TA 是随机本地管理 MAC（`52:9C:0F:93:30:61` 等），66 个身份。
对端（华为 AP）回 `seq=2 status=0` —— **它接受了伪造身份的认证**，`afst=0` 就是"station 表在
被消耗"的直接证据。把表打满（`status 17`）**未实测**：需要把整台 AP 打穿，实验室里没做。

计数器：`af`（on/off）、`aff`（帧数）、`afa`/`afs`（Auth / Assoc 帧数）、`afids`（身份数）、
`afst`（最后一次状态码）、`afup`（是否已升级 SAE）。

---

## 12. Evil Twin（`evil_twin.cpp`）

- CLI：`EVILTWIN <idx>`、`EVILTWIN_STOP`、`CREDS`
- 入口：`evil_twin.cpp`（`start_evil_twin_attack()` :18）

### 12.1 协议层定位

【代码】这个模块**不做 802.11 裸帧注入**（唯一的注入是内部调 `attack_deauth_single()` 打 3 秒
deauth 逼客户端重连），它换了一条路：用 `WiFi.softAP()` 起一个**真的 AP**，
克隆目标的 SSID/信道，开放认证，然后：

```
阶段 1  对目标 AP 发 deauth（3 s）           → 客户端掉线
阶段 2  softAP 起来，同 SSID、开放认证       → 客户端自动重连/用户手选
阶段 3  DNS 服务器（53，通配 * → 本机）      → 所有域名解析到 AP
阶段 4  HTTP 8080 钓鱼页                     → 收用户名/密码，存 RAM（上限 50）
```

### 12.2 帧格式

没有自定义帧：beacon/probe response 由 Wi-Fi 驱动按 softAP 配置生成，认证/关联由协议栈处理。
凭据表是 RAM 里的数组（`captured_creds[50]`），不落盘（`AGENTS.md §10`）。

### 12.3 为什么有效 / 何时失效

【标准/实测】有效性不依赖协议缺陷，依赖三件事：①客户端记着这个 SSID，看到更强的同名信号
会自己连；②开放认证没有密钥协商，客户端不会因为"没有密码"而拒绝；③用户看到
"需要重新登录"的页面会输入密码。

失效条件：①客户端锁定了 BSSID（企业/部分 IoT）→ 不连；②系统提示"网络安全类型改变"
（WPA2 → 开放）时用户取消；③目标用 WPA3/PMF 时客户端对"同名但降级"的网络更敏感；
④DNS/HTTP 走 HTTPS 的场景会看到证书错误。

【实测】**未量化**：没有做"客户端多久连上来、多少比例会输密码"的统计；
`CREDS` 只验证了取表路径与上限。这条在 `测试报告.md §7` 里属于未覆盖项。

---

## 13. PS 位欺骗：伪造电源管理状态（`pspoll.cpp`）

- CLI：`PSPOLL <idx> [sta-mac] [null|qosnull|action]`、`PSPOLLREL`、`PSPOLLSTOP`、`PSPOLLTEST`
- 入口：`pspoll.cpp`（构造 `build_null_data()` / `build_qos_null()` / `build_action()`，
  节拍 `pspoll_step()`，撤销 `pspoll_release()`）
- 与 §8 的 TIM 投毒是同一台机器的两面：**TIM 改的是 AP 的 beacon**（告诉客户端"有你的帧"），
  **这里改的是 STA 的电源管理声明**（告诉 AP"我睡了，别发"）。两者可以叠加（§13.3 末）。
- 这个"我睡了"可以用三种帧承载，各家协议栈认的不是同一种，所以帧型可切（§13.2）。

### 13.1 协议层定位

【标准】802.11 的省电（PS）机制靠一个 bit 声明：STA 在**帧控制**的 bit 12 置 **Power Management**，
AP 收到后把该 STA 视为"在睡觉"，下行帧不再直接发送，而是缓存起来并在 beacon 的 **TIM 元素**里置位
（802.11-2020 第 10 章 *Power management*、第 9 章 *TIM element*）。STA 醒来后取帧：DTIM 模式下
AP 在 DTIM beacon 之后直接发，legacy PS 模式下 STA 发 PS-Poll 取。

【标准】这个 bit 存在于**所有**帧的帧控制里，不只是数据帧——管理帧也有。于是同一件事有三种常见承载：

| 帧型 | 类型/子类型 | 谁在真实世界里这样发 | 为什么选它 |
| --- | --- | --- | --- |
| `null` | data 4（Null Data） | mac80211 `ieee80211_nullfunc_get()` | 规范里的标准省电声明帧；无载荷、无 LLC/SNAP |
| `qosnull` | data 12（QoS Null） | QoS/WMM 关联的站点 | 带 2 字节 QoS Control；只认 QoS 站点的 AP 也认它 |
| `action` | mgmt 13（Action） | 各类管理动作 | 管理帧同样带 PM 位；类别 127（厂商自定义）**不在** robust 集合里，所以仍绕 PMF |

【实现】本模块只做一件事：用受害 STA 的 TA 发 PM=1 的上述帧。AP 于是把该 STA 移入 PS 状态；
受害者本人毫不知情（没有任何帧发给它）。每第 6 帧改成 PM=0，让 AP 把攒下的帧"放"出来（§13.3）。

【历史】这个机制原本还有第四个注入点：伪造 **PS-Poll**（控制子类型 10）让 AP 把缓存帧逐帧交给
一个不在听的站。已实现、已实测、已删除——单播的 PS-Poll 在本 MAC 上根本不发送。证据在附录 A。

### 13.2 帧格式

三种帧型只差帧头，PM 位的位置完全一样（帧控制第二字节 bit 4，即 `0x10`）：

```
null     24B: FC 0x1148 | Dur 2B | Addr1 BSSID | Addr2 受害STA | Addr3 BSSID | Seq 2B
qosnull  26B: FC 0x11C8 | Dur 2B | Addr1 BSSID | Addr2 受害STA | Addr3 BSSID | Seq 2B | QoS 2B
action   29B: FC 0x10D0 | Dur 2B | Addr1 BSSID | Addr2 受害STA | Addr3 BSSID | Seq 2B
              | category=127 | action=0 | OUI 00:11:22
```

| 字段 | `null` | `qosnull` | `action` |
| --- | --- | --- | --- |
| Frame Control 低字节 | `0x48`（data 4） | `0xC8`（data 12） | `0xD0`（mgmt 13） |
| Frame Control 高字节 | `0x11` = ToDS + **PM** | `0x11` = ToDS + **PM** | `0x10` = **PM**（管理帧没有 ToDS/FromDS） |
| Duration/ID | 0（会被 MAC 重算，附录 A） | 同左 | 同左 |
| Addr1 / Addr2 / Addr3 | BSSID / 受害 STA / BSSID | 同左 | 同左 |
| 额外字段 | 无载荷 | QoS Control 2B：TID=0、Normal Ack、无 A-MSDU | category 127 + action 0 + 3B OUI |
| PM=0 版本 | 高字节 `0x01` | 高字节 `0x01` | 高字节 `0x00` |

【实现】`PSPOLLTEST` 把三种帧（PM=1）与 PM=0 版本一次性打出来，例如实测输出：

```
PSPOLLTEST null    hex=4811000002112233445502AABBCCDDEE021122334455F0FF
PSPOLLTEST qosnull hex=C811000002112233445502AABBCCDDEE021122334455F0FF0000
PSPOLLTEST action  hex=D010000002112233445502AABBCCDDEE021122334455F0FF7F00001122
PSPOLLTEST awake   len=24 fc=0x0148 pm=0
```

【实现】本模块**不使用 `ie_util.cpp`**：三种帧都没有元素（Action 的 body 是 category/action/OUI，
不是 IE），见附录 D。

【历史·已删除】PS-Poll 是 16 字节控制帧：`FC 0x00A4 | Duration/ID = 0xC000|AID | Addr1=BSSID |
Addr2=受害 STA`。它的 `Duration/ID` 确实能原样出空气（附录 A 有实测），但**单播**的这种帧本 MAC
一帧都不发，所以整条路径删除。

### 13.3 为什么有效 / 何时失效

【标准】**有效条件**：

1. 受害者已关联、AP 认得这个 MAC（Unknown STA 的帧会被当 Class 3 处理）；
2. AP 实现了 PS 缓存（几乎所有 AP 都实现）；
3. 攻击者与受害者在同一信道（本模块自己锁到目标 AP 的信道，`chset=` 会报出是否成功）。

【标准】**核心边界：受害者自己的上行帧会把状态翻回来。** PM 位是"当前状态"不是"请求"：
受害 STA 只要还在活动模式发数据，它自己发的每个数据帧都是 PM=0，AP 收到就把该 STA 移回"醒着"，
于是我们伪造的 PM=1 只能维持到它下一次上行。这条决定了攻击的真实上限——**是"下行吞吐下降"，
不是"断网"**。实测三种帧型都是这个量级（§13.4）。

【标准】另外两个衰减机制：AP 对缓存帧有**老化超时**，且重传耗尽后会**丢弃**，所以效果是
"延迟 + 丢包"，不是永久阻断；反过来，关联一直保持，`psprxp`（真 PS-Poll 计数）也不会动——
ESP-IDF 站点按 DTIM 收帧，压根不发 PS-Poll。

【实测】每第 6 帧的 PM=0 是**故意**的：它让 AP 把攒下的帧"放"给一个并不在听的站（这些帧被浪费
掉），把"延迟"变成"丢失"；`PSPOLLREL` 就是把这件事手动做一次（撤销）。

【防护】PMF（802.11w）**不覆盖**：数据帧的 PM 位不在保护范围，而 `action` 用的类别 127 是
robust 集合之外的那几个类别之一（§1 脚注）。这是本模块相对 §2 deauth、§5 DELBA、§7 BTM 的差异——
那三条在强制 PMF 的 WPA3 网络上会被客户端驱动丢弃，这里不会。

【失效条件】①受害者的上行帧持续翻盘（实测就是这个，见 §13.4）；②AP 的 PS 状态有很短的超时；
③AP 只认某一种帧型（这就是三种可切的原因，实测这台 softAP 三种都认）；④TA 不属该 BSS；
⑤多 AP/漫游场景里 TA 落到另一个 BSSID；⑥AP 对厂商自定义 Action 直接丢弃时，`action` 只退化成
"一帧普通管理流量"（PM 位是否被读取决于 AP 的 MAC 实现，未单独量化）。

【标准/推测】**与 §8 TIM 投毒的叠加**（组合攻击，**未做双模块实测**）：TIM 让客户端"以为有帧/
以为没帧"，PS 位让 AP"以为客户端睡了"。叠加的直觉效果是"AP 攒着、客户端也不来取"，但两条路径各有
自己的失效条件（TIM 的 TBTT 相位问题见 §8.4），是否线性放大没有测过，不要按乘积估算。

### 13.4 实现与实测

【实现】注入路径与其它帧级模块相同：`tx_guard_send()` → `esp_wifi_80211_tx(WIFI_IF_STA, ...)`，
单播（AP 会 ACK）所以走整流器。

【实测】**三种帧型都上空气，PM 位都是我们写进去的**（2026-11-15，`lab/pspoll_air.py`：
COM6 同时跑 softAP 与 `sniffpoll 6`，COM5 注入，每种 4 s）：

| 帧型 | 抓到的 PM=1 帧 | 抓到的 PM=0 帧 | 空口示例 |
| --- | --- | --- | --- |
| `null` | 32 | 6 | `NULL ta=02:AA:.. ra=88:13:.. pm=1 tods=1 qos=0 len=28` |
| `qosnull` | 29 | 6 | `NULL ta=02:AA:.. ra=88:13:.. pm=1 tods=1 qos=1 len=30` |
| `action` | 27 | 6 | `PMACT ta=02:AA:.. ra=88:13:.. pm=1 cat=127 len=33` |

（`len` 含 4 字节 FCS，所以是 24/26/29 + 4。）

【实测】**三种帧型都能把下行压下去，QoS Null 最强**（2026-11-15，`lab/pspoll_ps.py`：
AP 侧 RATE，每段 10 s，同一个受害者、同一轮）：

| 阶段 | AP 侧 RATE（KiB/s） | 相对 baseline | STA 掉线 |
| --- | --- | --- | --- |
| baseline awake（ps 0） | 351 | — | 0 |
| `null` | 247 | **−29.6%** | 0 |
| `qosnull` | 217 | **−38.2%** | 0 |
| `action` | 280 | **−20.5%** | 0 |
| 每次 `PSPOLLREL` 之后 | 407–449 | +16…+28% | 0 |

所以默认帧型取 `qosnull`（CLI 不写帧型时用它）。`pspdl`（发向受害者的下行数据帧）在整个攻击期间
一直增长——AP 仍在往那个 MAC 发帧，效果是"抢不到/被丢弃"，不是"完全静默"。

【实测】**节拍必须 10 帧/s，不是 20**：20 帧/s 下约 170–400 帧（9–20 s）就 `FATAL tx 0x101 ...
-> restart`；10 帧/s 下 60 s / 600 帧零拒收。机理推测（未证伪）：AP 把该 STA 当"睡了"，这些帧的
应答/重传行为与普通管理帧不同，每个缓存占用更久，池子更早打满。

【实测】**`SCAN` 之后不要立刻开打**：扫描收尾时 STA 会拒绝 `esp_wifi_set_channel()`，模块若不检查
就会把帧发在"扫描停下来的那个信道"上——现象是"计数器在涨、空口一帧没有"。现在回执带
`OK PSPOLL 0 mode=pm frame=qosnull sta=.. ch=6 chset=0 ssid=..`，`chset≠0` 时再打 `WARN`。
复现脚本先用 `MON <ch> 2` 钉住信道。

【实测】计数器（`STATUS`）：`psp`（off/pm）、`pspfrm`（当前帧型）、`pspf`（总帧数）、
`pspnul`（PM=1 帧数）、`pspfl`（PM=0 释放帧数）、`pspc`（学到的受害 MAC 数）、`pspdl`（发向受害者的
下行数据帧数，攻击生效时应停止增长）、`psprxp`（听到的真 PS-Poll 数）、`psprxn`/`psprxpm`
（听到的 Null Data 及其 PM=1 计数）。

【未实测/推测】①强制 PMF 的 WPA3 AP（手上没有可信 WPA3 AP，华为那台实测回 status 13）；
②真实手机/笔电客户端（只测了 ESP32-C5 板）；③多受害者（代码最多 8 个、轮转，未量化）；
④与 §8 TIM 的组合；⑤AP 缓存老化的具体时长（只观察到停手后数秒内恢复）。

---


## 14. RRM 伪造 Neighbor Report Response（`rrm.cpp`）

- CLI：`RRM <idx> nbr <bssid> <ch> [count] [token] [info] [opclass] [phy] [sta-mac]`、`RRMSTOP`、`RRMTEST`
- 入口：`rrm.cpp`（组帧 `build_nbr_response()`，STA 学习与请求/响应计数 `rrm_on_rx()`，
  发送节拍 `rrm_step()`，自检 `rrm_selftest()`）

### 14.1 协议层定位

【标准】802.11k-2008 定义的射频测量（Radio Measurement）在 802.11-2020 里是 §11.11
"Radio measurement"（条款号以你手上的标准版本为准，本文只按 Action 字段编号说话）。
它让 AP 与客户端交换邻居/信道/beacon 测量结果。其中 **Neighbor Report** 是唯一"能指挥客户端
去哪"的那条：AP 回一个邻居列表，客户端把它填进漫游候选表。

【标准】承载帧是 Action 管理帧（mgmt subtype 13）。Action 字段：category = 5（Radio Measurement），
action = 4（Neighbor Report Request）/ 5（Neighbor Report Response）。本模块只伪造 **action 5**，
同时统计嗅到的 action 4（`s_requests`），因为"客户端到底问没问过"是实现行为的关键变量。

【代码】`rrm.cpp` 与 `btm.cpp` 是同一层的东西：都在 net80211 之上直接拼 24 字节 MAC 头 + Action 体，
都只发单播、都由 `tx_guard` 节拍。区别只有一个——category 5 是 802.11k 的通道，category 10 是 802.11v 的。

### 14.2 帧格式

【代码】`build_nbr_response()`，42 字节（+4 FCS），`RRMTEST` 逐字节可见：

```
偏移  长度 字段                    取值（本模块）
0     2   Frame Control           0xD0 0x00   mgmt, subtype 13 = Action
2     2   Duration                0x0000      由驱动重算，写什么都不会上空气（附录 B 第 1 条）
4     6   Addr1 = RA              目标 STA（命令参数的 sta-mac，或嗅探学到的客户端）
10    6   Addr2 = TA              目标 AP 的 BSSID（伪造）
16    6   Addr3 = BSSID           同上
22    2   Sequence                0xF0 0xFF（固定）
24    1   Category                5  = Radio Measurement
25    1   Action                  5  = Neighbor Report Response
26    1   Dialog Token            参数 token，默认 0
27    1   Element ID              52 = Neighbor Report
28    1   Length                  13 = 固定部分，无 optional subelement
29    6   BSSID                   幻影邻居的 BSSID（命令参数 bssid）
35    4   BSSID Information       参数 info，小端，**默认 0**（位含义未核实，不猜）
39    1   Operating Class         参数 opclass，**默认 0**（按真帧回填）
40    1   Channel Number          幻影邻居的信道（命令参数 ch）
41    1   PHY Type                参数 phy，**默认 0**（按真帧回填）
```

- 【代码】组帧是手写偏移（和 `btm.cpp` 一样），没有走 `ie_util.cpp`——那几个函数是**解析**用的
  （遍历 IE / RSN AKM / MFPR / Extended Capabilities），本模块发的是一个固定元素，不需要构造器。
- 【标准】元素固定 13 字节是"最小合法值"：BSSID(6) + BSSID Information(4) + Operating Class(1) +
  Channel(1) + PHY Type(1)。可选子元素整段省略。
- 【实测】空口抓到 `len=46`，即 42 + 4 字节 FCS（硬件加，不由我们写）。

### 14.3 为什么有效 / 失效

**成功条件**（协议层）：
1. TA/Addr3 必须是受害者当前 AP 的 BSSID——客户端只从"自己 AP 发的帧"里读邻居表。
   本模块直接照抄扫描结果里的 BSSID。
2. 链路没有强制 PMF。**category 5 在 robust 管理帧集合里**（Linux `_ieee80211_is_robust_mgmt_frame()`
   的判定是"除 Public/HT/未保护类/Self-protected/VHT/厂商自定义之外所有 Action 类别"），
   所以 PMF required 的客户端会在驱动里直接丢掉未保护的这类帧。这与 deauth、DELBA、CSA、BTM 的
   天花板相同——本模块不是 PMF 绕过。
3. 客户端真的维护 11k 邻居表，并且对"未请求的 response"宽容（见下面的失效条件 3）。

**失效条件**（写全，别只写一半）：
1. 强制 PMF（WPA3）→ 驱动丢弃；
2. 客户端不做 11k。**本模块目前不判能力**：`rrm_on_rx()` 只按 MAC 学 STA，不看 Extended Capabilities。
   实现时留在 `rrm.h` 的 TODO 里——802.11k 的能力位定义本轮没有核实到原文，不猜；
3. 客户端只接受"自己发过 Request 且 dialog token 匹配"的 Response。本模块发的是**未请求**的
   response（token 可配但客户端没请求过），**接受度未实测**，这是本模块最大的未知；
4. 真实 AP 自己的 Neighbor Report 覆盖我们伪造的记录（真实响应更可信、也更频繁）；
5. 客户端对候选做 RSSI/负载阈值判断，而元素里没有"信号强度"字段，只有 BSSID/信道/PHY 类型。

【诚实边界】不要写"可打 WPA3 / PMF 无效"。本模块与 BTM 一样，只在 PMF 关闭或可选的链路上有窗口。

### 14.4 实现与实测

【代码】发射路径：`esp_wifi_80211_tx()` 经 `tx_guard_send()`（`kTxPolicyGuard`：45 ms 单播节拍，
首个 `0x101` 打 `FATAL` 后 `esp_restart()`）。节拍模型与 BTM 完全相同——每客户端 300 ms 一次、
全局 50 ms 一帧、一次 `rrm_step()` 只出一帧。

【代码】`count` 语义：`0` = 一直发到 `RRMSTOP`；`1..16` = 本次总共注入多少帧，发满后
`rrm_step()` 自己把模式切回 `off`（不用手动 STOP）。`STATUS` 的 `rrmleft=` 是剩余帧数，
所以 `rrmleft=0` 有两种含义（无限 / 已发完），要看 `rrm=` 是 `nbr` 还是 `off` 来区分。

【代码】客户端来源：①命令里的 `sta-mac`（`rrm_add_station()`，台架用）；②混杂回调里记下 BSS 内
所有单播管理帧的源地址（上限 8 个，`rrmc=`）。代码不判 11k 能力（见 14.3 失效条件 2）。

【实测】2026-11-21，COM5 = ESP32-2432S028R 注入，COM6 = ESP32 当嗅探器：

| 项 | 结果 |
| --- | --- |
| `RRMTEST` | `len=42 cat=5 act=5 token=0 protected=0`，元素 `eid=52 ie_len=13` |
| 空口 | `MON 3 8` → `RXLOG`：`type=0 sub=13 len=46 dest=02:AA:BB:CC:DD:EE src=CC:08:FB:F6:25:64 cat=5 act=5 nch=52 cnt=13 rate=1M dur=314` |
| 计数 | `count=0` 跑 6 s：`rrmf=45`、`rrmc=2` |
| 限次 | `count=3` → `rrmf=3` 后 `rrm=off` |
| 参数回显 | `rrmtok/rrmch/rrminfo/rrmoc/rrmphy` 与命令行一致 |

【实测/推测】注入窗口里嗅探侧 `RXMIX` 是 `rts=1187 / cts=65`，逐帧可见 `type=1 sub=11`
（RTS，`RA=02:AA:BB:CC:DD:EE`、`TA=目标 AP BSSID`、`dur=1198`），而同期只注入了 45 帧。
RTS 的 TA 与注入帧的 Addr2 相同，**推测**是注入路径给每帧做了 RTS/CTS 保护、没人回 CTS
（RA 是假 STA）导致重传吃空口——与附录 B 的单播 20 帧/s 上限同源，但"是驱动发的 RTS"这一点
本轮没有独立证据。

【实测】2026-11-22，用 `lab/victim_btm`（802.11v/802.11k 打开、`ps 0` 一直醒的 ESP32-C5）当受害者：
伪造 16 帧 NRREP（`token=7`、`info=0x00000001`），空口可见 16 条 `cat=5 len=46`（42+4，AP 板
`sniffpoll` 同时抓的），但 STA 侧**没有** `WIFI_EVENT_STA_NEIGHBOR_REP`，也没有断开。
即"未请求的 Neighbor Report Response"在 ESP-IDF 端点上不产生可观测行为
（`firmware/测试报告.md §4.4.12`）。对比：同一轮里 BTM 是**有**响应的（§7.4），
说明不是"STA 整体不理 action 帧"，而是这一条它在等一个自己发过的请求。

【未实测】①真实 11k 客户端是否采信未请求的 response（ESP-IDF 端点给否定，wpa_supplicant/Android 未测）；
②PMF required 下的空口行为（按标准应被丢弃）；
③C5 抓包管道当时没在运行，`lab/cap_frames.py` 新增的 cat 5 解码分支没有吃到真抓包
（上面的字段来自对端固件 `RXLOG`，它只解出 cat/act 与首个元素的 id/len，不打印帧体）。

---


## 附录 A：已删除、已失效与"做了但没证明"的路径

按仓库现状，下面这些**不再存在**或**明确无效**，列出原因以免被重新"发明"：

| 路径 | 状态 | 原因与证据 |
| --- | --- | --- |
| NAV / Duration 预约信道（`nav.cpp` 及 `NAV*` 全部命令、LVGL/上位机的 NAV 页） | **已删除** | `esp_wifi_80211_tx()` 注入帧的 Duration 由驱动/MAC 重算：单播一律 `SIFS+ACK@1Mbps` = **314 µs**（30/26/20 字节的 action/BAR/data 全是），广播 CF-End 一律 **0**，RTS 随重发速率在 **990–1102 µs** 浮动。设 1 µs 与设 32767 µs 结果完全相同（`测试报告 §4.3.1`，C5 抓包）。所以"覆盖率 = 帧率 × 声明时长"的算法全部作废 |
| CTS 注入 | **不可用** | 每帧永久吃掉一个短缓存：30/200/500 ms 节拍都是 32 帧封顶，静置 10 s 不恢复，之后连 `esp_wifi_set_channel()` 都卡死（`§4.3.3`） |
| TSF 投毒（`TIMTSF ... tsf\|both`、`ttsf=` 状态字段） | **已删除**（本次） | MAC 用接口自己的 TSF 覆盖 beacon 的 24..31 字节（未关联的 STA 接口为 0）：`last_tsf=654632723879` vs 空口 `tsf=0`（`§4.4.3`）。与 Duration 同源的字段重写；乐鑫侧也有公开记录（esp-idf issue #6368 里的示例注释 "Timestamp (GETS OVERWRITTEN TO 0 BY HARDWARE)"） |
| PS-Poll 欺骗（控制子类型 10，`PSPOLL ... poll\|both`） | **已删除**（本次） | 帧本身能发出去，但**单播**的 PS-Poll 一帧都上不了空口：`CTRLTEST 10 broadcast 0xC025` 两轮各 **10/10**（空口 `dur=0xC025 aid=37`，说明 Duration/ID **没有**被改写），把 RA 换成 AP 的 BSSID 后两轮各 **0/10**——同长度、同 TA、同 Duration，只有 RA 不同。PS-Poll 只有单播给 AP 才有意义，所以整条路径删除；探针留在 `CTRLTEST [subtype] [broadcast\|bssid] [dur]`，`测试报告 §4.4.9` |
| TIM 的 AID 位编码 | **已修正**（不是删除） | 旧实现按 `(AID−1)` 落位，等于把 AID 1 写到组播位（AID 0）、AID 3 写到 AID 2。现在按 `AID/8` 字节、`AID%8` 位（见 §8.1）；空口复测已完成：`bitmap=08`（AID 3），见 §8.4 |
| "BA 推窗"在 mac80211 上的证明 | **未证明** | 在 ESP-IDF 目标上 `step=0` 对照组同样冻结，无法把"窗口被推走"单独分离；Android 那次对照（`BARPUSH 512` 卡死 / `0` 正常）是用户现场观察、单设备、无抓包（`§4.2`） |
| "BTM Request 天然绕 PMF" | **说法已改正** | category 10 属 robust 管理帧集合，PMF 强制时会被客户端驱动丢弃（§7.1）。`btm.cpp`/`btm.h`/README/GUI 的旧说法已改 |

---

## 附录 B：注入层的硬约束（所有模块共享）

这一节是跨模块的"物理定律"，写在代码注释里（`tx_guard.h`、`AGENTS.md §11`），也可复现：

1. **必须 STA 模式**：`esp_wifi_80211_tx()` 在 AP 模式下会返回 `ESP_OK` 但帧不上空口
   （esp-idf issue #6368）。本固件固定 `WIFI_MODE_STA` + 不关联。
2. **需要覆盖 `ieee80211_raw_frame_sanity_check()`**：`deauth.cpp:22` 返回 0 才能发任意裸帧
   （链接参数 `-Wl,-z,muldefs`）。
3. **共享的 32 个短缓存**：池空即 `esp_wifi_80211_tx()` 返回 `ESP_ERR_NO_MEM`（`0x101`）。
   这是**我们自己**的驱动拒发，与 AP 无关。
4. **单播可持续约 20 帧/s**（实测边界，`测试报告 §4.4.4`）：

   | 节拍 | 结果 |
   | --- | --- |
   | 50 帧/s（20 ms） | 第 **63** 帧 `0x101`（1.26 s） |
   | 40 帧/s（25 ms） | 第 **117** 帧（2.93 s） |
   | 30 帧/s（33 ms） | 45 s / 1350 帧，零拒收 |
   | 20 帧/s（50 ms） | 45 s / 900 帧、60 s / 1200 帧，零拒收 |
   | 广播克隆 beacon 50 帧/s | 60 s / 3000 帧，零拒收 |
   | **PM 位帧（Null/QoS Null/Action）20 帧/s** | **约 170–400 帧后 `0x101`**（9–20 s）——帧类相关，见 §13.4 |
   | **PM 位帧 10 帧/s** | 60 s / 600 帧，零拒收（`pspoll.cpp` 的默认节拍） |

   机理：伪造 TA 的单播帧拿不到属于本机的 ACK，硬件重传到上限才放缓存；我们也不 ACK
   AP 的回复，AP 同样重发（实测每条 SAE commit 对应 **12.7** 个 AP 回复帧）。
   20 帧/s 的注入在空口上≈**220 帧/s** 的实际负载。广播帧不等 ACK，缓存立刻回收。
5. **守卫规则**：`tx_guard_send()`（`tx_guard.cpp`）对单播强制 45 ms 间隔
   （`TX_GUARD_UNICAST_GAP_MS`），第一次 `0x101` 立即 `esp_restart()` 并先打
   `FATAL tx 0x101 ... -> restart`。覆盖五个新模块 + `CSA`；`DELBA`/BA/deauth 仍用自己的封装
   （长跑 19–25 帧/s，在排水速率以下，遇 `0x101` 计一次错下轮重试），`BARSEQ` 这类诊断探针
   故意留在守卫外。
6. **Duration 与 beacon Timestamp 由 MAC 写**（附录 A）。
7. **`tx_cb` 对注入帧不回调**：`esp_wifi_register_80211_tx_cb()` 一次都不触发，
   所以"这一帧发完了没有"在应用层不可观测——所有速率结论都是"驱动接受了 N 帧"，
   不是"N 帧上了空口"。
8. **混杂模式两级过滤**：`esp_wifi_set_promiscuous_filter()` 的 CTRL 位只是第一级，
   `esp_wifi_set_promiscuous_ctrl_filter()` 默认丢弃全部控制帧，必须设成 `MASK_ALL`
   （`start_promiscuous()`）。漏掉第二级时 `RXMIX ctrl=0`，看起来像"硬件收不到"。
9. **11n 射频解不出 HE PPDU**：只有 Wi-Fi 6 客户端的 BSS 里嗅探不到 client→AP 帧，
   只能靠广播兜底。

---

## 附录 C：诊断探针（不是攻击，但共用注入通道）

| 命令 | 作用 | 为什么留在这里 |
| --- | --- | --- |
| `CTRLTEST [subtype] [broadcast\|bssid] [dur]` | 发 10 帧指定子类型的控制帧（默认 RTS=11，RA=广播，TA=`02:00:00:AA:BB:CC`，Duration 默认 0） | 验证控制帧能不能注入、能不能被第二块板收到。子类型/Duration 参数是 §13.4 判定"PS-Poll 单播发不出去"的探针；NAV 删除后它仍是控制帧通道唯一的活证据 |
| `PSPOLLTEST` | 打印三种帧型（Null Data / QoS Null / 单播 Action）与 PM=0 版本的字段与十六进制 | 帧构造错了先看这里（PM=1 与 PM=0 只差 `frame[1]` 的 0x10 位） |
| `PSPOLLREL` | 给每个受害者补一帧 PM=0 后停止 | 撤销/对照：证明"AP 攒下的帧被放出来"（§13.3） |
| `BARSEQ <n> [gap]` | 按固定节拍只发 BAR | 证明"BAR 会回收缓存"（30 ms 节拍 100 帧零失败），这是附录 B 第 4 条的来源 |
| `BATX` | 发一帧 DELBA/ADDBA/BAR 并打印驱动返回值 | 帧构造错了先看这里 |
| `MON <ch> [sec]` | 被动监听（可跳信道） | 观测 `RXMIX`：帧真的上了空口吗 |
| `STATIONS [sec]` | 扫客户端 | deauth/DELBA/BTM 的目标来源 |
| `RXLOG` / `RXMIX` / `CTRLFILTER` | 收帧明细 / 分类计数 / 控制帧过滤掩码 | 混杂模式两级过滤的现场诊断 |

这些命令**故意不接整流器**：它们要测的就是"池子什么时候空、驱动什么时候拒"。

---

## 附录 D：`ie_util.cpp` 与各模块的对应关系

组帧/解帧的公共小工具只有 5 个函数，全部在 `firmware/src/ie_util.cpp`（约 97 行）。它们不构造帧，
只负责"在字节流里找元素"和"从 RSN 元素里判 AKM"，所以每个模块的帧构造仍然是各自手写的
（这也是为什么本文每节的帧结构图能对到具体偏移）。对照如下：

| 函数（`ie_util.cpp`） | 作用 | 谁在用（`path:line`） | 用在帧的哪一部分 |
| --- | --- | --- | --- |
| `ie_find(start, end, id, *len)` | 顺序遍历元素（id+len+body），返回 body 指针；遇到截断就停 | `tim.cpp:120/126/133`、`authflood.cpp:246/252`、`sae.cpp:219`、`btm.cpp:157` | 解析真 AP / 客户端的帧：SSID(0)、RSN(48)、TIM(5)、Extended Capabilities(127) |
| `rsn_has_akm_sae(rsn, len)` | 在 RSN 的 AKM 列表里找 `00-0F-AC:8/9/24` | `sae.cpp:223`（`AUTHFLOOD` 通过 `sae_classify()` 间接用） | 判定目标是不是 WPA3（决定是否启动/升级 SAE 洪泛） |
| `rsn_has_akm_psk(rsn, len)` | 找 `00-0F-AC:2/4/6` | `sae.cpp:224` | 区分 `wpa2-psk` / `wpa2/wpa3` transition |
| `rsn_mfpr_required(rsn, len)` | 读 RSN Capabilities 的 MFPR 位（bit 6） | **当前无人调用**（定义了、备着） | 原计划给"要不要提示 PMF 会挡"用；现在文档里靠静态判断，不靠运行时 |
| `extcap_has_bss_transition(extcap, len)` | 判 Extended Capabilities 的 bit 19 | `btm.cpp:165` | 客户端能力学习：不支持的 STA 被 `btmskip` 跳过 |

两点现状值得记一下（与"以代码为准"有关）：

- `csa.cpp` 解析真 AP 的 RSN 时用的是自己的 `while` 循环（`csa.cpp` 的 `learn_beacon()`），
  没走 `ie_find()`。行为等价，但属于重复实现；将来统一时改这一处即可。
- `rsn_mfpr_required()` 定义了却没有调用点。写代码时不要以为"PMF 判别已经自动做了"——
  模块里没有任何运行时 MFPR 判断，PMF 这条边界只在文档/注释里说明（§1 总表、§2.3、§7.1、§5.1）。
- `pspoll.cpp` **不在**这张表里：Null Data 帧没有元素（也没走 AP 的 beacon），它不需要
  任何解析工具，只用 `WiFi.BSSID()/channel()` 拿目标。

---

## 附录 E：与 `firmware/README.md` 的说法冲突（以代码与实测为准）

写这份文档时按代码和实测逐条核过仓库里的说法，下面几处原来是**错的**，已在同一次改动里改掉
（README/注释/GUI 文案都同步了）。留在这里是为了让后来者不要再按旧说法"修正"回去。

| 旧说法（出处） | 事实（依据） | 现在的写法 |
| --- | --- | --- |
| "BTM Request 不在 PMF 的 robust 集合里，PMF 不校验"（`btm.cpp` 头注释、`btm.h`、`firmware/README §5`、GUI 文案） | Action 帧里只有 Public(4)/HT(7)/Unprotected WNM(11)/Self-protected(15)/VHT(21)/厂商自定义(127) 不算 robust；category 10 **在**集合里。Linux 的 `_ieee80211_is_robust_mgmt_frame()` + `net/mac80211/rx.c` 会在协商了 PMF 时丢弃未保护的这类帧 | "PMF 关闭或可选（大多数 WPA2）时有效；强制 PMF 时被驱动丢弃"，见 §7.1 |
| "CSA 不受 802.11w/PMF 保护"（`csa.cpp` 头注释、`firmware/README §5`、GUI 文案） | Spectrum Management action 帧**是** robust；真正不受保护的是 **beacon 里的 CSA IE** | 两条路径分开写，见 §4.1 |
| "DELBA 不是 robust 管理帧，PMF 不校验"（`delba.cpp` 头注释、`delba.h`） | category 3（Block Ack）**在** robust 集合里 | "实测的 −99% 属于非 PMF 链路"，见 §5.1 |
| `TIMTSF ... tsf|both` 可用（有效部分只有 TIM） | beacon 的 timestamp 被 MAC 用自己的 TSF 覆盖（未关联时为 0），写字无效 | 模块改名 `TIM`，TSF 那半删除，见附录 A 与 §11 第 8 条 |
| TIM 位图按 `AID-1` 落位（代码与其注释） | Partial Virtual Bitmap 按 AID 编号索引（bit 0 = AID 0 = 组播） | 改 `AID/8`+`AID%8`，空口复测 `bitmap=08`，见 §8.1 与 `测试报告 §4.4.7` |
| "五个新模块只有 CLI，没有 LVGL 页面"（`AGENTS §11`） | 现在有了，而且六个帧级模块**共用一个页面**（`SCR_FRAME`） | 见 `firmware/README §7.2`；`UISCREEN` 认 `btm/tim/eapol/pspoll/sae/authflood` |
| "帧级模块一律 20 帧/s"（`firmware/README §5`、`AGENTS §11`） | 只对管理帧/数据帧成立。**PM 位帧在 20 帧/s 下会在几百帧后打满缓存池并重启** | `pspoll.cpp` 自降到 10 帧/s（`kSendMs=100`），见 §13.4 与附录 B |
| "PS 位欺骗只能用 Null Data"（上一版 §13、`firmware/README §5`） | 同一 bit 还能装在 QoS Null 与单播 Action(127) 里，三种实测都上空气、都能压吞吐 | 三种帧型可切（默认 `qosnull`），见 §13.2/§13.4 |

另外两条"不是冲突，但容易误读"的：

- `STATUS timaid=` 是**显示用**位图（bit0 = AID 1），不是空口编码；空口编码见 §8.1。
- `TIMTEST` 打印的 `bmp_mask=` 是"从 TIM 元素里读回来的位图字节"，`bitmap=08` 是同一份数据的十六进制；
  两者和 `timaid` 不是同一个东西。

---

## 参考文献

**标准**

1. IEEE Std 802.11-2020 —— 条款名：*Frame formats*（第 9 章，含 *Reason Code*、
   *Capability Information*、*TIM element*、*Action frame format*）、
   *MAC sublayer functional description*（第 10 章，含 *Block Ack*）、
   *MLME*（第 11 章，含 *Authentication*、*Association and reassociation*、
   *Deauthentication*、*Spectrum management*、*Wireless network management*）、
   *Security*（第 12 章，含 *RSNA*、*SAE*、*Protected management frames*）。
   注：本文只给出条款名称；编号在 2016→2020 之间发生位移，按名称检索更可靠。
2. IEEE Std 802.11w-2009 —— 受保护管理帧（robust management frame）的原定义与保护方式
   （单播用 PTK，广播用 BIP/IGTK）。
3. IEEE Std 802.11h-2003 —— 频谱管理、CSA（channel switch announcement）。
4. IEEE Std 802.11v-2011 —— WNM、BSS Transition Management。
5. IEEE Std 802.1X-2010 —— 基于端口的网络访问控制、EAPOL PDU 格式。

**实现（用于确认"标准怎么被落地的"）**

6. Linux `include/linux/ieee80211.h` 的 `_ieee80211_is_robust_mgmt_frame()` ——
   "除 Public(4)/HT(7)/Unprotected WNM(11)/Self-protected(15)/VHT(21)/厂商自定义(127)
   之外所有 Action 类别都算 robust"。
7. Linux `net/mac80211/rx.c` 的 `ieee80211_drop_unencrypted_mgmt()` ——
   协商了 PMF（`WLAN_STA_MFP`）时丢弃未受保护的 robust 管理帧。
8. Wireshark `epan/dissectors/packet-ieee80211.c` 的 `ieee80211_tag_tim()` ——
   TIM 的 AID 解码 `aid = 8*n1 + 8*i + j`（`n1 = bitmap_control & 0xFE`）。
9. wpa_supplicant `wpa_supplicant/wnm_sta.c` —— BTM Request 的处理分支
   （Disassociation Imminent + 非零 timer 才扫描）。

**乐鑫 / ESP-IDF**

10. `esp_wifi_80211_tx()` —— ESP-IDF Wi-Fi 非公开 API 的声明与用法（`esp_wifi.h`，
    原始声明在 `libnet80211.a`）；四个参数：接口、帧缓冲、长度、是否由系统分配序号。
11. `esp_idf` issue #6368 "esp_wifi_80211_tx() does not work in AP mode (IDFGH-4550)" ——
    AP 模式下返回 `ESP_OK` 但帧不上空口；示例代码里明确标注 beacon 的 timestamp
    "GETS OVERWRITTEN TO 0 BY HARDWARE"。
12. `esp_wifi_get_tsf_time()` —— 读接口自身 TSF 的 API；本固件没有用它（未关联时为 0），
    但它是理解"为什么 beacon timestamp 写到空口上变成 0"的钥匙。
13. ESP-IDF 文档 `esp_wifi_80211_tx` / `esp_wifi_set_promiscuous_ctrl_filter` /
    `esp_wifi_register_80211_tx_cb` —— 注入、控制帧过滤、发送回调的官方说明。
