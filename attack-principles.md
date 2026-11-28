# 攻击原理 —— 802.11 协议层攻击全量梳理

本文件逐个说明 `firmware/src/` 下**每一个**会向空口发帧的模块：它站在 802.11 协议栈的哪一层、
帧长什么样、为什么有效、什么情况下失效、在 ESP32 上落地时被硬件约束成什么样。

## 0. 读法、事实分层与合规

**三类事实分开标注**

| 标注   | 含义                       | 怎么核对                                                 |
| ---- | ------------------------ | ---------------------------------------------------- |
| 【标准】 | 802.11 / 802.1X 等标准文本的规定 | 给出条款名（和能确认的条款号），可全文检索                                |
| 【代码】 | 本仓库实现的事实                 | 给 `path:line`，与 `firmware/README.md §5` 冲突时**以代码为准** |
| 【实测】 | 空口 / 串口测到的数字             | 给脚本与日期；未测的一律写"未实测"                                   |

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

| 节   | 模块                 | 入口文件            | CLI                                                          | 工作模式                                                | 帧（类型/子类型/类别）                       | 协议层位置               | 依赖的协议机制                             | PMF 等防护                                    | 实测状态                          |
| --- | ------------------ | --------------- | ------------------------------------------------------------ | --------------------------------------------------- | ---------------------------------- | ------------------- | ----------------------------------- | ------------------------------------------ | ----------------------------- |
| 2   | Deauth 洪泛          | `deauth.cpp`    | `DEAUTH` `DEAUTH_ALL` `DEAUTH_ONLY` `DEAUTH_EXCEPT` `REASON` | 单个 AP / 全部 AP / 白名单 / 黑名单；reason 固定或每束随机            | mgmt / 12                          | MLME 关联状态机          | Class 2/3 帧状态机、Reason Code          | **被拦**（deauth 是 robust 帧，MFPR 下无效）         | 帧上空气 ✅，计数器 ✅，断连未量化            |
| 3   | Probe/Beacon 泛洪    | `deauth.cpp`    | `PROBE_BROADCAST`                                            | 单模式（广播泛洪），每 120 ms 跳信道                              | mgmt / 8、5                         | 扫描（MLME-scan）       | 客户端扫描表                              | 无（beacon/probe 从不加密）                       | 帧数 ✅（3 s 2512 帧）              |
| 4.1 | CSA（Action 帧）      | `csa.cpp`       | `CSA`                                                        | announce（倒计时）→ hold（新信道克隆 beacon）→ 循环               | mgmt / 13，cat 4 act 4              | 信道管理（802.11h）       | CSA 通告 + 倒计时                        | **被拦**（spectrum mgmt action 属 robust）      | 帧上空气 ✅                        |
| 4.2 | CSA（Beacon IE）     | `csa.cpp`       | `CSA`                                                        | 同上，两条路径同一轮发出                                        | mgmt / 8 + IE 37                   | 信道管理                | beacon 里的 CSA 元素                    | **不受保护**（beacon 不是 robust 帧）               | 帧上空气 ✅，客户端是否跟随未实测             |
| 5   | DELBA 欺骗           | `delba.cpp`     | `DELBA` `DELBATEST`                                          | 双向单播（学了 TID）或广播兜底                                   | mgmt / 13，cat 3 act 2              | Block Ack 会话管理      | 每个 TID 的聚合会话                        | **被拦**（cat 3 属 robust）                     | 吞吐 −99%（非 PMF 链路）✅            |
| 6   | BA 会话劫持            | `delba.cpp`     | `BAATTACK` `BAPLANT` `BARPUSH` `BATEST` `BATX` `BARSEQ`      | DELBA+ADDBA+BAR 持续 / 只种窗口 / 只推 BAR                  | mgmt / 13 cat 3 act 0 + ctrl / 8   | Block Ack 重排窗口      | ADDBA 的 SSN → WinStartB             | **被拦**（同上）                                 | ESP-IDF 目标 ✅ 冻结；mac80211 未实测  |
| 7   | WNM BTM Request    | `btm.cpp`       | `BTM` `BTMTEST`                                              | 单播请求；可选指定候选 BSS                                        | mgmt / 13，cat 10 act 7             | WNM / 漫游决策（802.11v） | BTM Request + Extended Capabilities | **被拦**（cat 10 属 robust，需 PMF 关闭）           | 端到端有效 ✅（真实 STA 切至同 SSID 软 AP，reason=207） |
| 8   | HE Trigger 轮询     | `bsrp.cpp`      | `BSRP` `BSRPFIELD` `BSRPSTOP`                               | BSRP / MU-BAR / Basic 参数实验                                  | ctrl / 2                           | UL OFDMA 调度（802.11ax） | Trigger Common/User Info           | 不适用 PMF；字段中仍有占位值                       | 帧上空气 ✅，实验 STA 有回应；端到端效果为零 |
| 13  | QoS Null PM 位欺骗 | `qosnull.cpp`   | `QOSNULL` `QOSNULLREL` `QOSNULLSTOP` `QOSNULLTEST`           | 单播 QoS Null，PM=1 刷新、PM=0 撤销                              | data / subtype 12                  | 省电（PS）状态机           | PM 位声明 + AP 下行缓存                  | 帧上空气；端到端有效 ✅（吞吐下降，零掉线，撤销恢复） |
| 9   | EAPOL-Start/Logoff | `eapol.cpp`     | `EAPOL` `EAPOLTEST`                                          | Start 与 Logoff 交替；非 QoS 与 QoS(TID) 交替               | data / 0、8 + LLC/SNAP 0x888E       | 802.1X 认证（端口状态机）    | EAPOL PDU、受控/非受控端口                  | 未加密数据帧可能被丢                                 | 帧上空气 ✅，该 AP 无回应               |
| 10  | SAE Commit 洪泛      | `sae.cpp`       | `SAE` `SAETEST`                                              | point（合法点）/ rand（对照）；身份每 4 帧轮换                      | mgmt / 11，alg 3 seq 1              | SAE 握手（WPA3）        | ECC 标量乘 + 反 clogging token          | 无（认证帧本就不加密）                                | 帧上空气 ✅，AP 回 status 13（非 WPA3） |
| 11  | Auth/Assoc 洪泛      | `authflood.cpp` | `AUTHFLOOD` `AUTHFLOODTEST`                                  | both（Auth→Assoc→换身份）/ auth / assoc；WPA3 自动升级 SAE    | mgmt / 11 alg 0 + mgmt / 0         | 认证 + 关联（station 表）  | 每个身份一条状态机                           | 无（auth/assoc 从不加密）                         | AP 回 status 0（接受了伪造身份）✅       |
| 12  | Evil Twin          | `evil_twin.cpp` | `EVILTWIN` `EVILTWIN_STOP` `CREDS`                           | deauth 3 s → 克隆 softAP → DNS 劫持 → HTTP 钓鱼页          | softAP + DNS + HTTP                | 上层（钓鱼）              | 客户端自动连接 / 用户输入                      | 无                                          | 凭据捕获未量化                       |
| —   | BTM 诱饵 AP         | `baitap.cpp`    | `BAITAP` `BAITAPSTOP` `BAITAPSTAT`                           | 从扫描结果启动同 SSID/口令 SoftAP，供 BTM 候选指向              | AP beacon / association             | 漫游落点与连接事件          | 候选 BSS 可见且安全策略匹配                    | 自有隔离测试环境；STA 可能漫游                    | 板端闭环 ✅（BTM 后关联诱饵 AP，关闭后回连） |

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

| 形态                       | 攻击前           | 攻击中         | 结论            |
| ------------------------ | ------------- | ----------- | ------------- |
| 只发广播 DELBA（没学到客户端）       | 480–550 KiB/s | 0–260 KiB/s | −75%，链路没断     |
| 学到 2 个客户端后按 TID 0–7 双向单播 | 550–600 KiB/s | 0–5 KiB/s   | **−99%**      |
| 学到 TID（只打 TID 0）后双向单播    | 590–650 KiB/s | 0–5 KiB/s   | **−99%**，帧量更少 |

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

| 条件                   | 攻击前       | 静默期          | 停手 8 s | 恢复方式       |
| -------------------- | --------- | ------------ | ------ | ---------- |
| `BAPLANT step=512`   | 386 KiB/s | 26–30 KiB/s  | 0      | 重新关联后 >380 |
| `BAPLANT step=0`（对照） | 404 KiB/s | 43 / 8 KiB/s | 0      | 同上         |
| `BAATTACK`（持续 15 s）  | 302 KiB/s | 22–26 KiB/s  | 67     | 同上         |
| `BARPUSH step=512`   | 304 KiB/s | 12 KiB/s     | 3–16   | 同上         |
| `BARPUSH step=0`（对照） | 340 KiB/s | 0–3 KiB/s    | 0      | 同上         |

【实测】注入限速的教训：一次把整个"TID × 方向"矩阵打进 32 个短缓存会让 `baerr` 暴涨
（15 s 内 `baerr=1559`，其中 `bae=257` = `ESP_ERR_NO_MEM`），后来改成"每轮最多 4 帧 + 失败
退避 5 ms"；`BARSEQ 100 30` 证明 BAR 本身会回收缓存（30 ms 节拍 100 帧零失败）。
这段是附录 B 的直接来源。

---

## 7. 802.11v BTM Request 欺骗（`btm.cpp`）

- CLI：`BTM <idx> [timer] [sta-mac] [cand-bssid] [cand-ch] [cand-info]`、`BTMSTOP`、`BTMTEST`
- 入口：`btm.cpp`（构造 `build_btm_request()`、能力学习 `learn_capabilities()`、周期发送 `btm_step()`）

### 7.1 协议位置

【标准】BSS Transition Management 属于 802.11v WNM。BTM Request 是管理 Action 帧（category 10、action 7）。category 10 属 robust 管理帧；协商了 PMF 的客户端可能丢弃未保护请求，因此本机制不是 PMF 绕过。

### 7.2 帧格式

【代码】`btm.cpp` 当前构造长度为无候选 31 B、带候选 46 B（空口记录另含 FCS）：

```
0..23  24 B  管理 Action 帧头；FC 0x00D0，RA=STA，TA/BSSID=目标 AP
24     1 B   Category=10（WNM）
25     1 B   Action=7（BTM Request）
26     1 B   Dialog Token
27     1 B   Request Mode：bit 2=Disassociation Imminent；bit 0=候选列表存在
28..29 2 B   Disassociation Timer（小端；传 0 时固件改用 10）
30     1 B   Validity Interval=10
31..45 15 B  可选 Neighbor Report：EID 52 / len 13 / BSSID / BSSID Info / Op Class / Channel / PHY
```

BSSID Information 由调用者提供并按小端写入，位含义当前未核实；PHY Type 固定写 0（unknown）。候选信道可从最近一次扫描结果解析。准确字节以 `BTMTEST` 与 `btm.cpp` 构造器为准，不沿用已删除的随机幻影候选描述。

目标客户端通过 Extended Capabilities（IE 127、BSS Transition bit 19）识别；模块对已知不支持者跳过。发送入口使用 `tx_guard_send()`，并受单播节拍限制。

### 7.3 有效边界与失效机制

【实测】客户端是否漫游取决于候选 BSS 是否真实可见且策略/安全配置可接受。幻影候选可能收到 Response 但不触发切换；实测有效情形要求目标附近存在同 SSID、同口令的第二个 BSS。当前可先用 `BAITAP` 从扫描结果创建该落点，BTM 会自动指向它。PMF 强制、11v 不支持、目标 STA 睡眠或候选字段无法映射到扫描结果都会阻止或削弱效果。

### 7.4 三层判据与实测

- **帧上空气**：BTM Request 字段由 `BTMTEST` 检查，空口与请求计数见 `firmware/测试报告.md §4.4.8/§4.4.12`。
- **对端有回应**：`btmresp`/`btms` 可记录 Response，但 Response 不是漫游成功的必要条件；指定候选成功的实验中 Response 为 0。
- **端到端有效**：2026-11-22 的 `lab/victim_btm` 实验中，真实 STA 切到可见的同 SSID/同口令软 AP，断开 reason 为 207 `ROAMING`，切换约 0.099 s；`BAITAP` 单板闭环记录见 `测试报告.md §4.4.13`。幻影候选则不切换。该结论只适用于受测配置。
- **STATUS 契约**：`btm`、`btmf`、`btmc`、`btmskip`、`btmresp`、`btms`。

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

### 12.4 BTM 诱饵 AP（`baitap.cpp`）

- CLI：`BAITAP <idx> [pass] [ch] [max]`、`BAITAPSTOP`、`BAITAPSTAT`
- **① 协议位置与载体**：显式命令启动临时 `WIFI_MODE_APSTA` SoftAP，作为 BTM 候选列表指向的真实可见 BSS；平时固件仍以 STA 静默运行。
- **② 帧格式与关键字段**：由 ESP-IDF SoftAP 生成 Beacon、处理关联并提供 DHCP；SSID 与信道取自扫描目标，口令由用户运行时提供（省略则开放网络），信道限 1–13，最多 4 个客户端。它不自行伪造 BTM 帧，BTM 由 `btm.cpp` 的唯一实现发送。
- **③ 有效边界与失效机制**：单射频要求 AP 与当前射频使用同一信道；STA 只有在候选可见且已有相符凭据时才可能切换。启动会消耗约 7.2 KB 堆（本次台架），停止后驱动 netif 缓冲不完全回收；这是显式实验态，须用 `BAITAPSTOP` 收尾。
- **④ 三层判据与实测**：2026-11-22 `测试报告.md §4.4.13` 记录 Beacon 可见、BTM 后受测 STA 关联诱饵 AP 并获得 DHCP 地址；停止诱饵后 STA 回连原 AP。静默对照未观察到 STA 自行漫游。该闭环只适用于自有/授权测试网，不等同于对任意客户端的效果保证。

---

## 13. QoS Null PM 位欺骗（`qosnull.cpp`）

- CLI：`QOSNULL <idx> [sta-mac]`、`QOSNULLREL`、`QOSNULLSTOP`、`QOSNULLTEST`
- 入口：`qosnull.cpp`（构造 `build_qos_null()`，周期发送 `qosnull_step()`，撤销 `qosnull_release()`）
- 当前固件只保留单播 QoS Null 这一种 PM 位承载帧。

### 13.1 协议位置

【标准】802.11 帧控制字段中的 Power Management（PM）位表示发送 STA 的电源管理状态。关联 AP 可据此缓存下行数据，并通过真实 beacon 的 TIM 通告缓存状态。伪造 PM 位不会直接改变受害 STA 的状态；本模块通过发出看似来自目标 STA 的帧，测试 AP 对该状态声明的处理。

### 13.2 帧格式

【代码】`qosnull.cpp` 构造 26 字节的 ToDS QoS Null 数据帧：Frame Control subtype 12，ToDS=1，PM 位按发送阶段置 1 或清 0；Addr1 为 AP BSSID，Addr2 为受害 STA，Addr3 为 BSSID；末尾是 TID 0 的 QoS Control。驱动附加 FCS。PM=1 与 PM=0 仅改变 Frame Control 的 PM 位。Duration 由 MAC 重算（附录 A）。

【代码】周期路径每 100 ms 至多发一帧，每六帧中有一帧为 PM=0。单播发包经过 `tx_guard_send()`；`QOSNULLREL` 尝试给已记录客户端发送 PM=0 后停止。信道设置错误通过状态/回执可见，避免扫描刚结束时误在其它信道发送。

### 13.3 有效边界与失效机制

【实测】在已关联的实验 AP 上，伪造 PM=1 帧会使下行吞吐下降，但 STA 保持关联；受害 STA 自己发出的活动数据帧会把 AP 的电源管理状态更新回活动态，因此效果受刷新竞争影响。PM=0 撤销后吞吐恢复。

【边界】AP 必须接受目标 BSSID 下的该 STA 地址和 QoS Null 状态更新；受害者上行活动、AP 缓存/重传策略及无线环境都会改变结果。该结果不能外推到其它 AP 或客户端。该实验只支持当前 QoS Null 实现的结论。

### 13.4 三层验证与实测

- **帧上空气**：`firmware/测试报告.md §4.4.9` 记录 PM 位帧空口抓取；当前实现只保留 QoS Null。
- **对端有回应**：AP 侧下行 RATE 变化及 `qndl` 计数提供实验观测；不同环境仍需复测。
- **端到端有效**：同一测试报告记录吞吐下降、零掉线及 PM=0 后恢复。历史承载帧对比仅作为当时实验记录，不代表现行固件仍保留那些旧实现。
- **状态字段**：保留 `STATUS` 中现有 `qn`、`qnf`、`qn1`、`qn0`、`qnc`、`qndl`、`qnrn`、`qnrp` 名称，不以文档整理为由改名。

---
## 五、Wi-Fi 6/7 注入扩展候选

本节筛选的是候选研究方向，不代表固件已经实现这些功能。`[双平台可行]` 仅表示存在由 `esp_wifi_80211_tx()` 支持的 legacy 管理帧载体，且可沿 `tx_guard_send()` 路径尝试；除 HE Trigger 已有明确抓包结果外，候选的空口字段、对端反应和端到端效果均为**未验证**。ESP32/C5 不因此获得 HE/EHT PHY 注入能力。官方 ESP-IDF 文档列出的注入类型为 Beacon、Probe Request/Response、Action 和非 QoS Data，并明确不支持 QoS 或加密帧；自定义 IE 的驱动接受及空口保留仍须逐项抓包验证。

### 1. HE/EHT 管理元素候选 `[双平台可行]`

- **① 协议位置与载体**：802.11ax/be 的 BSS 能力和操作信息，候选载体是 Beacon、Probe Response 等管理帧，以 legacy PPDU 承载。两平台均有对应管理帧注入入口；具体 IE 是否被保留尚未测。
- **② 帧格式与关键字段**：在已有管理帧 IE 列表中增加 HE Operation（Element ID 255，Extension ID 36）或 EHT Operation（Element ID 255，Extension ID 106）结构。需按标准版本构造完整长度与字段，不能只插入 tag 声称有效。候选原语目前没有实现，也没有既定帧长；若原型化应使用 `tx_guard_send()` 的 Guard 策略并记录驱动返回值。
- **③ 有效边界与失效机制**：接收端可能忽略格式不完整、与能力 IE/信道参数矛盾或不适用于当前频段的 Operation IE。Beacon/Probe 的 IE 未受 PMF 保护，但客户端的关联选择、扫描去重和信道合法性校验各异。帧内声明更宽带宽不等于发射端实际提供该带宽。
- **④ 当前验证层级与下一步最小实验**：当前定性：**未验证**。最小实验：仅在隔离自有测试网发送单帧；Layer 1 用 `cap_frames.py` 对照完整 IE 字节、长度与 FCS；Layer 2 记录测试 STA 的扫描/关联事件；Layer 3 用受控吞吐基线比较，结果若无差异就标为“帧上空气、端到端效果未观察到”。

### 2. EHT Multi-Link Element 候选 `[双平台可行]`

- **① 协议位置与载体**：802.11be MLO 的发现/协商信息，候选放在支持相应 IE 的 Beacon、Probe Response 或关联管理帧中，由 legacy PPDU 承载。
- **② 帧格式与关键字段**：Multi-Link Element 使用 Element ID 255 及其扩展标识，内部包含 Multi-Link Control、Common Info 和按 variant 定义的子字段。长度取决于 Link Info；当前固件没有构造器，未定义可确认的帧长或候选字节串。候选实现应先只用 `tx_guard_send()` 发送标准格式帧，不改驱动 PHY 设置。
- **③ 有效边界与失效机制**：MLO 需要对端支持 EHT/MLO，且元素内容需满足链路标识、地址和关联上下文的一致性。未声明真实可用链路的元素很可能被忽略或仅触发扫描解析，不足以证明链路建立。PMF、驱动解析策略和跨频段硬件能力会限制后续状态转换。
- **④ 当前验证层级与下一步最小实验**：当前定性：**未验证**。最小实验：Layer 1 抓包核对 MLE 的扩展 ID、variant 与长度；Layer 2 在 Wi-Fi 7 测试客户端记录扫描/关联日志；Layer 3 仅在真实 MLO AP/STA 都可观测时比较单链路与多链路吞吐。没有 MLO 设备时停在 Layer 1，不推断端到端结果。

### 3. Trigger 参数边界研究 `[双平台可行]`

- **① 协议位置与载体**：802.11ax Trigger 控制帧（BSRP、MU-BAR、Basic），Trigger 本身走 legacy PPDU，目标 STA 的响应才使用 HE-TB。现有 BSRP 构造器已通过 `tx_guard_send()`，ESP32 与 C5 均可作帧级研究平台。
- **② 帧格式与关键字段**：现有 `bsrp.cpp` 构造 32 B BSRP；MU-BAR 路径为 36 B，但报告注明 BAR 字段布局尚未由参考抓包核实。AID12、RU Allocation、UL Length、GI/LTF、Target RSSI 等字段中有占位值；不得将 `BSRPFIELD` 可改写等同于字段语义已验证。沿用 Guard 策略，单播约 45 ms 的守卫间隔会限制速率。
- **③ 有效边界与失效机制**：已有实验显示 AID 匹配且 UL Length 达门槛时实验 STA 有回应；当前端到端吞吐效果为零。测试 AP 的 Trigger 活性对照为 `trig=0`，这限制了真实协议状态机推断。特殊 AID/RU 组合可能被 STA/AP 丢弃，不能将响应变化直接解释为功耗或吞吐变化。
- **④ 当前验证层级与下一步最小实验**：当前定性：**帧级成立；实验 STA 有回应；端到端效果为零**（`测试报告.md §4.4.14–§4.4.16`）。下一步每轮只变一个字段，Layer 1 抓包核字节；Layer 2 用 `trigstat`、次板 RXLOG 与 STA 日志确认响应类型；Layer 3 交替进行不注入/注入吞吐对照并报告波动范围。未完成对照前不提高效果等级。

### 4. MU-RTS / CTS-to-self 预约研究 `[平台不支持 / 理论受限]`

- **① 协议位置与载体**：候选属于控制帧与虚拟/物理载波侦听。控制帧的 PPDU 载体、驱动允许的子类型与普通管理帧注入路径不同，当前没有可确认的通用发射路径。
- **② 帧格式与关键字段**：Duration/ID、RA/TA 及相关带宽信令都必须按各自控制帧格式处理。当前没有 MU-RTS 或 CTS-to-self 原型，不能给出“已可注入”的长度或速率。即便构造字节，也不能绕过 MAC 对 Duration 的重算；本仓库实测显示多类注入帧的 Duration 被 MAC 覆写。
- **③ 有效边界与失效机制**：NAV 预约首先受 Duration 覆写这一已证实限制；另外，控制帧 subtype 白名单、PHY 前导、带宽信令和目标设备处理均未证实。该候选不得作为恢复 NAV 攻击的依据。
- **④ 当前验证层级与下一步最小实验**：当前定性：**理论受限，未验证**。最小实验先不发高负载：只用现有诊断环境验证一帧受控样本能否由驱动接受并被抓包端识别，再比较写入与空口 Duration；只有字段未被覆写且 subtype 可用，才继续做屏蔽箱/隔离环境中的 CCA/NAV 观测。Layer 3 暂无可定义的吞吐实验，不能提前声称有效。

### 5. 6 GHz 邻居字段级研究 `[平台不支持 / 理论受限]`

- **① 协议位置与载体**：C5 板卡无 6 GHz 射频前端，因此不具备 6 GHz 空口发射条件。可研究 2.4/5 GHz 管理帧中的 RNR 或 HE 6 GHz Operation 信息字段，但它们只表达邻居信息，不构成 6 GHz 发射。
- **② 帧格式与关键字段**：候选元素需按标准定义的 RNR Neighbor AP Information 或 HE 6 GHz Operation 子结构编码。当前无构造代码、无受验证的长度及字段样本；legacy Beacon/Probe 管理帧的普通注入入口不证明客户端会接受这些跨频段信息。
- **③ 有效边界与失效机制**：客户端可能要求多个一致的 AP/SSID/信道字段、扫描策略或安全参数；缺少 6 GHz 实际 BSS 时，最多测试解析/扫描提示，不能验证 6 GHz 关联或业务。射频限制是硬边界。
- **④ 当前验证层级与下一步最小实验**：当前定性：**仅字段级理论研究，未验证**。最小实验在隔离环境中向 2.4/5 GHz 抓包端发单帧，Layer 1 核对 IE；Layer 2 使用支持对应频段的 STA 扫描日志观察是否发现候选；没有真实 6 GHz AP/STA 时不做 Layer 3 关联/吞吐结论。

### 6. C5 HE20 SU PPDU 管理帧注入 `[C5-only 扩展]`

- **① 协议位置与载体**：候选是用 C5 的 `EmitterPhy::He20` 发送管理帧。仓库/已知实现只在 CSI 发射路径出现此 PHY 选择，不能推定它可承载 Beacon/Probe Response 等任意管理帧。
- **② 帧格式与关键字段**：若做原型，需先确定 API 接受的帧缓冲、PHY 配置与 FCS/序号归属，再验证标准管理帧在 HE20 SU PPDU 下的接收结果。当前没有通用构造长度、调用路径或字段记录；不得写成已存在的 `tx_guard_send()` 通用 HE PPDU 能力。
- **③ 有效边界与失效机制**：通用性未验证；设备可能只接受 CSI 专用载荷，或驱动限制帧型、信道、带宽和发射时机。即便抓到 HE 前导，也要确认 MAC 管理帧内容正确；不能预设其绕过 legacy 注入节拍或缓存限制。
- **④ 当前验证层级与下一步最小实验**：当前定性：**未验证（仅有 CSI 发射端相关实现线索）**。最小实验先查明受支持 API/实现契约，然后发送单个非 CSI Beacon 样本；Layer 1 用能解 HE PPDU 的独立接收设备核对 PHY 与管理帧；Layer 2 观察 STA 扫描结果；Layer 3 只有前两层稳定后再做隔离吞吐对照。不得以 `EmitterPhy::He20` 名称本身作为成功证据。

---

## 附录 A：已删除、已失效与“做了但没证明”的路径

按仓库现状，下面这些**不再存在**或**明确无效**，列出原因以免被重新"发明"：

| 路径                                                           | 状态            | 原因与证据                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------------ | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NAV / Duration 预约信道（`nav.cpp` 及 `NAV*` 全部命令、LVGL/上位机的 NAV 页） | **已删除**       | `esp_wifi_80211_tx()` 注入帧的 Duration 由驱动/MAC 重算：单播一律 `SIFS+ACK@1Mbps` = **314 µs**（30/26/20 字节的 action/BAR/data 全是），广播 CF-End 一律 **0**，RTS 随重发速率在 **990–1102 µs** 浮动。设 1 µs 与设 32767 µs 结果完全相同（`测试报告 §4.3.1`，C5 抓包）。所以"覆盖率 = 帧率 × 声明时长"的算法全部作废                                                  |
| CTS 注入                                                       | **不可用**       | 每帧永久吃掉一个短缓存：30/200/500 ms 节拍都是 32 帧封顶，静置 10 s 不恢复，之后连 `esp_wifi_set_channel()` 都卡死（`§4.3.3`）                                                                                                                                                                                                   |
| TSF 投毒（`TIMTSF ... tsf\|both`、`ttsf=` 状态字段）                  | **已删除**（本次）   | MAC 用接口自己的 TSF 覆盖 beacon 的 24..31 字节（未关联的 STA 接口为 0）：`last_tsf=654632723879` vs 空口 `tsf=0`（`§4.4.3`）。与 Duration 同源的字段重写；乐鑫侧也有公开记录（esp-idf issue #6368 里的示例注释 "Timestamp (GETS OVERWRITTEN TO 0 BY HARDWARE)"）                                                                                  |
| TIM beacon 投毒                                                   | **已删除(已下线)** | TIM 投毒已下线；仅归档其实现曾因 MAC TSF/空口时序边界而未产生端到端效果。 |
| PS-Poll 欺骗                                                      | **已删除(已下线)** | 单播 PS-Poll 在本 MAC 上未能上空口，因此整条路径已删除。 |
| "BA 推窗"在 mac80211 上的证明                                       | **未证明**       | 在 ESP-IDF 目标上 `step=0` 对照组同样冻结，无法把"窗口被推走"单独分离；Android 那次对照（`BARPUSH 512` 卡死 / `0` 正常）是用户现场观察、单设备、无抓包（`§4.2`）                                                                                                                                                                                   |
| “BTM Request 天然绕 PMF”                                          | **说法已改正**     | category 10 属 robust 管理帧集合，PMF 强制时会被客户端驱动丢弃（§7.1）；现行模块为 `btm.cpp`。 |

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

   | 节拍                                    | 结果                                             |
   | ------------------------------------- | ---------------------------------------------- |
   | 50 帧/s（20 ms）                         | 第 **63** 帧 `0x101`（1.26 s）                     |
   | 40 帧/s（25 ms）                         | 第 **117** 帧（2.93 s）                            |
   | 30 帧/s（33 ms）                         | 45 s / 1350 帧，零拒收                              |
   | 20 帧/s（50 ms）                         | 45 s / 900 帧、60 s / 1200 帧，零拒收                 |
   | 广播克隆 beacon 50 帧/s                    | 60 s / 3000 帧，零拒收                              |
   | **现行 QoS Null PM 位帧 20 帧/s** | **约 170–400 帧后 `0x101`**（9–20 s）——历史 PM 位实验的缓存池边界，现行默认节拍为 10 帧/s |
   | **PM 位帧 10 帧/s**                      | 60 s / 600 帧，零拒收（现行 `qosnull.cpp` 的默认节拍）           |

   机理：伪造 TA 的单播帧拿不到属于本机的 ACK，硬件重传到上限才放缓存；我们也不 ACK
   AP 的回复，AP 同样重发（实测每条 SAE commit 对应 **12.7** 个 AP 回复帧）。
   20 帧/s 的注入在空口上≈**220 帧/s** 的实际负载。广播帧不等 ACK，缓存立刻回收。

5. **守卫规则**：`tx_guard_send()`（`tx_guard.cpp`）对单播强制 45 ms 间隔
   （`TX_GUARD_UNICAST_GAP_MS`），第一次 `0x101` 立即 `esp_restart()` 并先打
   `FATAL tx 0x101 ... -> restart`。覆盖 CSA 与采用 Guard 策略的帧级模块；`DELBA`/BA/deauth 仍用自己的封装
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

| 命令                                            | 作用                                                                    | 为什么留在这里                                                                                  |
| --------------------------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `CTRLTEST [subtype] [broadcast\|bssid] [dur]` | 发 10 帧指定子类型的控制帧（默认 RTS=11，RA=广播，TA=`02:00:00:AA:BB:CC`，Duration 默认 0） | 验证控制帧能不能注入、能不能被第二块板收到；也可用于检查 Duration 是否与空口抓包一致 |
| `BARSEQ <n> [gap]`                            | 按固定节拍只发 BAR                                                           | 证明"BAR 会回收缓存"（30 ms 节拍 100 帧零失败），这是附录 B 第 4 条的来源                                         |
| `BATX`                                        | 发一帧 DELBA/ADDBA/BAR 并打印驱动返回值                                          | 帧构造错了先看这里                                                                                |
| `MON <ch> [sec]`                              | 被动监听（可跳信道）                                                            | 观测 `RXMIX`：帧真的上了空口吗                                                                      |
| `STATIONS [sec]`                              | 扫客户端                                                                  | deauth/DELBA/BTM 的目标来源                                                                   |
| `RXLOG` / `RXMIX` / `CTRLFILTER`              | 收帧明细 / 分类计数 / 控制帧过滤掩码                                                 | 混杂模式两级过滤的现场诊断                                                                            |

这些命令**故意不接整流器**：它们要测的就是"池子什么时候空、驱动什么时候拒"。

---

## 附录 D：`ie_util.cpp` 与各模块的对应关系

组帧/解帧的公共小工具只有 5 个函数，全部在 `firmware/src/ie_util.cpp`（约 97 行）。它们不构造帧，
只负责"在字节流里找元素"和"从 RSN 元素里判 AKM"，所以每个模块的帧构造仍然是各自手写的
（这也是为什么本文每节的帧结构图能对到具体偏移）。对照如下：

| 函数（`ie_util.cpp`）                        | 作用                                    | 谁在用（`path:line`）                                                          | 用在帧的哪一部分                                                         |
| ---------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `ie_find(start, end, id, *len)`          | 顺序遍历元素（id+len+body），返回 body 指针；遇到截断就停 | `authflood.cpp:246/252`、`sae.cpp:219`、`btm.cpp` | 解析真 AP / 客户端的帧：SSID(0)、RSN(48)、Extended Capabilities(127) |
| `rsn_has_akm_sae(rsn, len)`              | 在 RSN 的 AKM 列表里找 `00-0F-AC:8/9/24`    | `sae.cpp:223`（`AUTHFLOOD` 通过 `sae_classify()` 间接用）                        | 判定目标是不是 WPA3（决定是否启动/升级 SAE 洪泛）                                   |
| `rsn_has_akm_psk(rsn, len)`              | 找 `00-0F-AC:2/4/6`                    | `sae.cpp:224`                                                             | 区分 `wpa2-psk` / `wpa2/wpa3` transition                           |
| `rsn_mfpr_required(rsn, len)`            | 读 RSN Capabilities 的 MFPR 位（bit 6）    | **当前无人调用**（定义了、备着）                                                        | 原计划给"要不要提示 PMF 会挡"用；现在文档里靠静态判断，不靠运行时                             |
| `extcap_has_bss_transition(extcap, len)` | 判 Extended Capabilities 的 bit 19      | `btm.cpp:165`                                                             | 客户端能力学习：不支持的 STA 被 `btmskip` 跳过                                  |

两点现状值得记一下（与"以代码为准"有关）：

- `csa.cpp` 解析真 AP 的 RSN 时用的是自己的 `while` 循环（`csa.cpp` 的 `learn_beacon()`），
  没走 `ie_find()`。行为等价，但属于重复实现；将来统一时改这一处即可。
- `rsn_mfpr_required()` 定义了却没有调用点。写代码时不要以为"PMF 判别已经自动做了"——
  模块里没有任何运行时 MFPR 判断，PMF 这条边界只在文档/注释里说明（§1 总表、§2.3、§7.1、§5.1）。

---

## 附录 E：文档与当前实现的核对点

本文件以当前 `firmware/` 实现及 `firmware/测试报告.md` 的三层证据为准。历史测量只说明对应日期、固件和实验对象，不自动代表当前模块仍保留全部旧帧型。`STATUS` 机器可读字段按源码原名记录；本次文档整理不改变回执契约。

- BTM 现行实现为 `btm.cpp`，BTM Action 属 robust 管理帧；PMF 强制时未保护帧可能被对端丢弃。
- 旧实验条目见附录 A。
- PM 位实验当前实现仅为 `qosnull.cpp` 的单播 QoS Null；旧 Null Data / Action 帧对比属于历史实验，不能描述为现行可选模式。
- BSRP 既有结果限于帧级与指定实验 STA 的回应；吞吐对照未显示 Trigger 语义带来的端到端增益。

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
13. ESP-IDF v6.1 — [`ESP32 Wi-Fi API`](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/network/esp_wifi.html)
    与 [`ESP32-C5 Wi-Fi API`](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-reference/network/esp_wifi.html)：
    `esp_wifi_80211_tx()` 的支持帧型说明列出 Beacon、Probe Request/Response、Action、非 QoS Data，且注明不支持 QoS/加密帧；
    用作平台公开接口边界，不替代本仓库的空口实测。
14. IEEE Std 802.11be-2024 — [标准预览目录](https://store.accuristech.com/ieee/products/preview/2524517)：
    用于核对 EHT Operation 与 Multi-Link element 的定义条目；元素内容和字段编码以正式标准文本为准。
