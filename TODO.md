# TODO / 路线图

状态标记：`[x]` 已完成 · `[~]` 进行中 · `[ ]` 未开始

> 固件的定位是**素材采集器**：负责把可离线验证的哈希/凭据从空口上"拿下来"，
> 密码猜测本身交给 PC 上的 hashcat 之类工具。固件里不做在线爆破。

---

## 1. 抓包与破解素材

| 状态 | 条目 | 交付物 | 怎么算完成 |
| --- | --- | --- | --- |
| `[~]` | **PMKID 主动捕获（WPA/WPA2）**：混杂模式抓 EAPOL msg1 里的 KDE，或主动发 Association Request 让 AP 回 PMKID | `src/pmkid.c`、命令 `PMKID [idx]` | `PMKID` 后有 `PMKID_FOUND <bssid> <pmkid>` 行，同 `(BSSID,PMKID)` 不重复 |
| `[ ]` | **PMKID 导出**：hashcat 22000 + pcap | 命令 `EXPORT pmkid`、`STATUS` 加 `pmkid=` | 导出的 `.22000` 丢给 hashcat，用已知密码能命中 |
| `[x]` | **CSA 注入（WPA3/PMF 的替代路线）**：伪造 CSA/ECSA 帧，把客户端从被 PMF 保护的信道"请"到克隆 AP 所在信道 | `src/csa.c`、命令 `CSA <idx> <ch> [sec]` | 目标客户端在抓包里出现于克隆 AP 的信道 |
| `[x]` | **CSA 现场验证**：真实客户端上确认攻击生效（人工观察），帧格式/上空气由 `CSATEST`、`RXCSA`、`csaauth`/`csarej` 佐证 |
| `[x]` | **CSA 假 AP 接应**：新信道上伪装 AP，Auth 回成功、Assoc 回 status 17，每轮 500 ms |
| `[x]` | **CSA 自动信道 + 循环**：2.4G AP 通告随机 5G 信道、5G AP 反之，每轮重掷，循环到 CSASTOP |
| `[x]` | **DELBA 注入（拆 Block Ack 会话）**：伪造 Category 3 / Action 2 的 DELBA，按 TID 拆聚合 | `src/delba.cpp`、命令 `DELBA <idx> [reason]` / `DELBASTOP` / `DELBATEST` | 帧格式逐字节校验；实验室链路（ESP32 AP ↔ C5 STA）吞吐量 480→5 KiB/s（-99%）且客户端不掉线 |
| `[x]` | **DELBA 的 TID 学习**：从 QoS 数据帧的 QoS Control、BA/BAR 控制帧的 BA Control、ADDBA 参数集三路识别 TID | `delba_on_rx()` | `STATUS` 的 `delbat` 位图随真实流量变化，帧量比"0–7 全打"更低 |
| `[ ]` | **DELBA 对手机/PC 客户端的逐型号实测**：不同驱动的 BA 重建策略差别很大 | 实验室脚本扩展 | 至少两种手机 + Windows 客户端的吞吐量曲线 |
| `[~]` | **BA 会话劫持（Bl0ck / CVE-2022-32666 方向）**：DELBA 清场 + 伪造 ADDBA 种 WinStartB + BAR 推窗 | `src/delba.cpp`、命令 `BAATTACK` / `BAPLANT` / `BATEST` | 会话级 DoS 已复现（2 帧 ADDBA 就冻结，需重连才恢复）；**窗口技巧本身未单独证明**，缺 mac80211 类目标 |
| `[x]` | **BA 窗口机制的单独验证**（Bl0ck 的核心那一步）：**Android 客户端上成立**——`BARPUSH 512` 视频卡死（且仍显示已连接、需关开 Wi-Fi 恢复），`BARPUSH 0` 无影响；两次只差 SSN、都在静默期观察 | — | 已由用户现场确认（单设备单次、无抓包） |
| `[x]` | ↳ 复现步骤（手机客户端自测，已执行） | 手机 + 攻击板，不需要额外设备 | 步骤：① 手机连自家 Wi-Fi 并播放视频/跑测速（要持续有下载流量）；② 攻击板 `SCAN` 找到该 AP 的序号；③ `BARPUSH <idx> 512`，静默后看手机是否卡住、Wi-Fi 图标是否仍显示已连接；④ 手机 Wi-Fi 关开恢复后重复 `BARPUSH <idx> 0` 做对照。判据：`step=512` 卡死而 `step=0` 不影响 → 窗口机制成立；两者都卡死 → 只是会话被打断（与 ESP-IDF 目标的结论一致）。记录 `STATUS` 的 `delbac/bassn/baplant` 与手机型号、系统版本 |
| `[ ]` | （备选）用 Linux 目标复现：MT7601U/RTL8188EU USB 网卡 + VirtualBox 直通，或树莓派/旧笔记本当 AP/客户端 | 实验台 | 与上一条同一判据；mac80211 是标准实现，最适合证明"推窗"这一步 |
| `[x]` | **NAV 攻击不可实现（已确认并删除）**：`esp_wifi_80211_tx()` 注入的帧，Duration 字段被驱动/MAC 重算——单播一律 `SIFS+ACK@1Mbps`（314 µs），广播 CF-End 一律 0，RTS 恒 990–1102 µs；设 1 µs 与设 32767 µs 结果相同（C5 抓包实测，`测试报告 §4.3.4`） | `NAVDUR` 探针（已随模块删除）、`lab/cap_pipe.py` | 六种帧型（RTS/CF-End/action/BAR/BA/QoS data）全部不带出我们写的值。乐鑫文档同结论。**模块已删除**，历史数据留在测试报告里 |
| `[x]` | **控制帧短缓存池的机制与边界**：32 帧共享池（`mgmt_sbuf_num`）、错误码 `0x101`、CTS 单独会泄漏、RTS/CF-End/BAR 会回收 | `NAVSEQ`/`NAVPACE`/`BARSEQ`（探针随 NAV 模块删除，BARSEQ 保留） | 紧循环 32 帧封顶；30 ms 节拍下 RTS/CF-End/BAR 过 100 帧、CTS 30/200/500 ms 都是 32 帧且 10 s 不自愈 |
| `[ ]` | **CSA 跟随**：解析目标 AP 的 CSA/ECSA IE，提前跳信道，注入与抓包不丢帧 | 复用 `deauth.cpp` 的信道调度 | 目标 AP 切信道后 200 ms 内仍能收到它的帧 |
| `[ ]` | **WPA-Enterprise**：EAP-Identity 明文 + MSCHAPv2 响应哈希 | 命令 `EAP`、导出 hashcat 5500 | 抓到 `EAP_IDENTITY <user>` 与 `MSCHAPV2` 哈希对 |

### 设计要点

- **PMKID 不需要客户端在线。** PMKID 在 AP 发出的 EAPOL msg1 的 RSN IE（KDE）里，本身已经包含
  "用密码可验证"的哈希。所以可以主动发一个带 RSN IE 的 Association Request 触发 AP 回 msg1，
  也可以在有人正常连网时被动抓。两者都要按 `(BSSID, PMKID)` 去重，否则同一个值会刷屏。
- **WPA3(SAE) 没有 PMKID。** SAE 走 commit/confirm，没有可离线爆破的字段。WPA3 的突破口是
  **CSA 注入 → 客户端被引到克隆 AP**，属于"绕开 PMF 拿条件"，不是"抓哈希"。纯 SAE 网络
  不要指望 PMKID 那一套。
- **CSA 为什么能绕过 PMF。** PMF（802.11w）保护的是去认证/去关联这类管理帧；CSA 走的是
  Beacon/Probe Response 的 IE 或 Action 帧，很多部署没开 beacon protection，
  客户端就照单全收，主动切到指定信道去找"同名 AP"。
- **Enterprise 抓的是凭据不是 PSK。** EAP-Identity 常常是明文用户名；MSCHAPv2 的
  Challenge/Response 可以离线做字典/彩虹表。导出成 hashcat 5500 格式。

---

### DELBA 设计要点

- **盲发无效**：对没有该 TID 会话的对端发 DELBA，mac80211 直接丢。所以顺序是"先听 TID → 再按 TID 单播"，
  一个客户端都没听到时才退化成广播 DELBA（`delbb=` 计数）。
- **两个方向都发**：AP→STA（客户端以为 AP 拆的）与 STA→AP（AP 自己拆发送会话）。一侧拆掉就够。
- **不踢人**：链路一直连着，只是丢了 A-MPDU，退回单帧确认——这是它比 deauth 隐蔽的原因，
  也是它不能代替 deauth 的原因。
- **混杂模式的两级过滤**：类型 mask 里加 `WIFI_PROMIS_FILTER_MASK_CTRL` 只是第一级；
  第二级 `esp_wifi_set_promiscuous_ctrl_filter()` 不设就一帧控制帧都收不到（默认全丢）。
  两级都开之后 `rts/ack/ba/bar` 都能计数（实测 `ctrl=37 rts=10 ba=2 ack=24`），deauth 的控制帧触发
  也才真正可用。

---

## 2. 管理/控制帧攻击（2026-11 完成）

| 状态 | 条目 | 交付物 | 怎么算完成 |
| --- | --- | --- | --- |
| `[x]` | **802.11v BTM Request 欺骗**（PMF 不保护，等同 deauth 但"合法"）：`cand` 带幻影候选 BSS、`bare` 不带；11v 能力从客户端的 Extended Capabilities bit19 学习，不支持的跳过；`sta-mac` 可指定目标 | `src/wnm.cpp`、`WNM <idx> [cand\|bare] [timer] [ch] [sta-mac]` / `WNMSTOP` / `WNMTEST` | 空口抓包 `cat=10 act=7 req_mode=0x05 timer=10` + Neighbor Report 候选（`测试报告 §4.4.1`）；端到端已试（§4.4.8）：真实 11v STA 会声明能力（`wnmc=1`）但**不回 BTM Response**（`wnmresp=0`），ESP-IDF 没有公开 BTM 事件，换客户端才能继续 |
| `[x]` | **TIM 投毒**（克隆 beacon 按 AID 置位/清空 bitmap、DTIM count 归 0） | `src/tim.cpp`、`TIM <idx> [tim\|clear] [aid]` / `TIMSTOP` / `TIMTEST` | 空口抓包 TIM 元素逐字节正确、克隆频率 5×真 AP（§4.4.1）；AID 位编码已修正并在空口复测（`bitmap=08`，§4.4.7）；端到端已做（§4.4.8）：**对真实省电 STA 的吞吐无影响**（变化在噪声内：+10%/+3%，样本 12–18 个；deauth 阳性对照成立） |
| `[x]` | ~~**TSF 投毒**~~ —— 结论：**本硬件不可实现，已删除**。MAC 用接口自己的 TSF 覆盖 beacon 的 timestamp（未关联时报 0），与 Duration 同源的字段重写 | —（`tsf`/`both` 模式与 `ttsf=` 字段已移除） | `last_tsf=654632723879` vs 空口 `tsf=0`（§4.4.3） |
| `[x]` | **EAPOL-Start/Logoff 洪泛**：ToDS 数据帧 + LLC/SNAP 0x888E，伪造受害 STA，Start/Logoff 交替，QoS(TID6)/非 QoS 两种形态 | `src/eapol.cpp`、`EAPOL <idx> [tid\|-1] [sta-mac]` / `EAPOLSTOP` / `EAPOLTEST` | 空口抓包 `ver=2 type=1/2` 双向交替（§4.4.1）；**WPA2-PSK 的华为 AP 完全忽略，`eaprxreq` 为 0**，需要 802.1X/WPA-Enterprise 环境才能验证效果 |
| `[x]` | **SAE Commit 洪泛**（WPA3 DoS）：group 19 + 合法 P-256 生成元（`rand` 为对照组）、身份每 4 帧轮换、**反 clogging token 回显**（Element 255 / Ext 93 容器与裸 token 两种形态） | `src/sae.cpp`、`SAE <idx> [point\|rand] [gap_ms]` / `SAESTOP` / `SAETEST` | 空口抓包 `alg=3 seq=1 group=19`、AP 回 `status=13`（该 AP 不吃 SAE，见 §4.4.2）；**token 回显只到"代码 + 自检字节"层，缺 WPA3 AP 实测** |
| `[x]` | **Auth/Assoc 洪泛 + WPA3 自动升级**：随机身份轮换、Assoc Request 带目标 SSID/RSN IE、嗅到 AKM 含 SAE 自动转 SAE 洪泛 | `src/authflood.cpp` + `sae.cpp` 的 `sae_classify()`，`AUTHFLOOD <idx> [both\|auth\|assoc] [noauto]` / `AUTHFLOODSTOP` / `AUTHFLOODTEST` | 空口 817 帧、AP 回 `status=0`（接受了伪造身份，§4.4.2）；**未压到表满（status 17）** |
| `[x]` | **单播注入的速率上限与"永不 NOMEM"**：50 帧/s → 63 帧 `0x101`、40 帧/s → 117 帧、30/20 帧/s → 45 s 各 1350/900 帧零拒收、广播 50 帧/s → 3000 帧零拒收；固件改成由整流器强制单播 45 ms 间隔，`SAE` 的 `gap_ms` 低于 50 自动抬高，CSA 也接入 | `tx_guard.h`/`tx_guard.cpp` + `lab/pool_limit.py` + `lab/soak.py` | 数据见 §4.4.4/§4.4.5；判据 = 长跑 `STATUS` 的 `txgerr` 恒 0 且无 `FATAL tx 0x101` |
| `[ ]` | **WPA3 AP 上的 SAE 量化**：需要真 WPA3-SAE AP，看 `status 76 → token 回显 → saetok/saeecho`，并用合法 STA 的往返时延劣化做效果判据 | 实验台 | `saetok>0`、`saeecho>0`，且合法 STA 的 ping RTT 明显上升 |
| `[~]` | **BTM 的端到端验证** —— 已做（§4.4.8）：ESP32-C5 STA 开 11v 后 `wnmc=1`（能力对）但 `wnmresp=0`（不回 BTM Response），ESP-IDF 无 BTM 事件可观察 | `lab/btm_sta.py` | **结论：需要 wpa_supplicant/Android 类客户端才能判「是否处理」** |
| `[~]` | **TIM 投毒的效果量化** —— 已做（§4.4.8）：PS STA（−16% 基线差）+ 三阶段吞吐对比，**无可测影响**；deauth 阳性对照成立（6 次掉线 / −90% 速率） | `lab/tim_ps.py` | 结论：克隆 beacon 缺 TSF 时间基准，睡眠 STA 大概率不按它调度 |

## 3. 界面

| 状态 | 条目 | 交付物 | 怎么算完成 |
| --- | --- | --- | --- |
| `[ ]` | **Android 上位机**：USB OTG 串口复用现有行协议 + 三级菜单/目标弹窗，与 Windows GUI 同构 | `android/`（Kotlin，`usb-serial-for-android`） | 手机上能完成 `SCAN → 选目标 → 攻击 → STATS`，协议层与 Windows 版共用一份解析测试 |

> 协议层先行：行协议不变，Android 只做"串口 + 解析 + 界面"，固件侧零改动。
> 如果 OTG 兼容性出问题，再考虑 BLE 串口桥（需要固件加 GATT 服务，属于另一条路）。

## 4. BLE

| 状态 | 条目 | 交付物 | 怎么算完成 |
| --- | --- | --- | --- |
| `[ ]` | **BLE 广播泛洪**：NimBLE 非连接广播，随机 MAC/名称，限速与计数可观测 | `src/ble_flood.c`、命令 `BLE_FLOOD [on/off]` | `STATUS` 有 `ble=` 计数；另一台手机扫描时列表被刷满 |
| `[ ]` | **共存评估**：Wi-Fi 与 BLE 共用射频，洪泛时 Wi-Fi 扫描/攻击的掉帧率 | 测试报告一节 | 给出"BLE 洪泛开着时 Wi-Fi 攻击帧率下降 X%"的实测数字 |

## 5. 已完成的修复

| 状态 | 条目 | 说明 |
| --- | --- | --- |
| `[x]` | deauth 发送路径修复（`b6fd81b`） | 注入从混杂回调移到主循环、加退避、束改 2 单播 + 1 广播、新增 `txok/txerr/txec/blind`；双板验证 `RXMIX deauth=69` |
| `[x]` | 目标选择弹窗（LVGL + Windows GUI） | 模态卡片/窗口，过滤、全选/反选、快照撤销 |
| `[x]` | UART RX 缓冲 256 B → 4 KB | 300 条 PING 洪泛从 233–255 提升到 300/300 |

## 6. 建议顺序

1. **PMKID 抓 + 导出**（第 1 节前两条）——唯一能离线闭环验证的一条，先把它跑通：
   抓到的 `.22000` 用已知密码喂 hashcat，命中即证明"帧解析 → 去重 → 导出格式"全对。
2. **CSA 注入 + 跟随**——需要实机对端才能验证，依赖第 1 步的信道调度代码。
3. **Android 上位机**——协议层无风险，可以并行。
4. **BLE 广播泛洪**——最后做，它会影响 Wi-Fi 侧帧率，要在共存评估之后调参数。

---

## 免责声明

以上能力仅用于**自有网络**与书面授权的测试环境。对未授权网络抓取哈希、注入管理帧、
洪泛广播，在多数国家和地区均属违法行为。详见 [README 的免责声明](README.md#8-免责声明)。
