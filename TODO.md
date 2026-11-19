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
| `[x]` | **电源管理（PM 位）欺骗**：用受害 STA 的 MAC 发 PM=1 的帧，让 AP 把下行缓存进 TIM；每第 6 帧换 PM=0 释放。三种承载帧 `null`/`qosnull`/`action` 可切 | `src/pspoll.cpp`、命令 `PSPOLL` / `PSPOLLREL` / `PSPOLLSTOP` / `PSPOLLTEST` | 三种帧型空口都带 `pm=1`；同一链路吞吐 −29.6% / −38.2% / −20.5%、零掉线，撤销后立刻恢复（`测试报告 §4.4.9`/`§4.4.10`） |
| `[x]` | **PS-Poll 欺骗不可用（已确认并删除）**：单播的控制子类型 10 在本 MAC 上不发帧——`CTRLTEST 10 broadcast 0xC025` 空口 10/10（`dur=0xC025 aid=37` 原样），换 RA=BSSID 后两轮 0/10 | `CTRLTEST` 探针（保留） | 结论：只剩 PM 位那一半；真 PS 站点（ESP-IDF `WIFI_PS_MIN_MODEM`）也从不发 PS-Poll，没有可模仿对象 |
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

## 5. 架构重构：wbus 总线（提案，待批）

**问题**：攻击模块本身是自包含的，耦合全在"注册表"这一层，而且硬编码在模块**之外**，一共六处：

| 注册表 | 位置 | 加一个攻击要改 |
| --- | --- | --- |
| 命令分发 | `firmware/src/serial_console.cpp:1488` 起 63 处 `strcmp` + 52 处 `strtok` | 加分支、加 include |
| 计数器聚合 | `do_status()`（`serial_console.cpp:311`）手工 print 每个模块 | 加 8 个 `Serial.print` |
| 能力串 | `capabilities()`（`serial_console.cpp:75`）硬编码字符串 | 手改字符串 |
| LVGL 屏表 | `components/wireless_ui/src/ui.c` 的 kind 表 | 加一页 |
| GUI 菜单 | `gui/main.py` 18 个手写 `_build_*` 页面 | 加一页 |
| 混杂回调 | `firmware/src/deauth.cpp:475-482` 八个 `X_on_rx()` | 加一行 |

PSPOLL 那一次的实测成本：`serial_console.cpp` +200 行、`deauth.cpp` 3 个 hook、`CMakeLists`、
`ui.c`、`gui/main.py`、`tests/`。

**目标**：把这几张表变成数据。运输层（串口 / LVGL / GUI）只认 `<obj>.<method> k=v` 与
`EVT <topic> k=v` 两种句子，不知道攻击的存在；新增攻击 = 一个 `.cpp`（描述表 + handler）
+ 注册表一行。

**四条兼容铁律**（每一步都要守）：

1. 回执文案字节级保持——`firmware/tests/` 51 项与 `lab/*.py` 全靠它解析，所以参数策略表带
   `err` 字段，把错误文案也数据化（例：`ERR reason must be 1..65535, or 'random'`）。
2. 策略校验不得比旧 handler 更严，否则"旧代码能跑的命令"开始报错：`CSA 3 auto 99` 旧代码静默
   把 count 强制成 5、`CSA 3 -5` 旧代码当 auto、`DEAUTH 3x` 前缀解析得 3。`INT` 沿用前缀数字
   语义，范围检查留给 handler。
3. 换行不能混：`Serial.println` 出 `\r\n`，`Serial.printf("...\n")` 只出 `\n`，回复层必须区分
   line / raw 两种写法。
4. 未迁移的命令原样落回旧 `strcmp` 链：`dispatch()` 只把行复制到本地 `work[128]` 再 `strtok`，
   不要动调用方传进来的 `line`。

### P1 总线核心 + deauth/csa 试点（2026-11-18 完成）

- [x] `components/wbus/`：对象注册表、`wb_arg_spec_t` 参数策略（`INT / REASON / MAC / ENUM / STR`）、
      `wb_reply_t` 注入式 sink（**不依赖 Arduino 与 esp_\***）、`wbus_register/call/call_named/list/describe`、事件订阅
- [x] `include/console_commands.h`：暴露 `console_scan_count()`、`console_apply_reason()`、`console_ui_log()`，
      让对象层能回调控制台而不反向依赖
- [x] `src/bus_objects.cpp`：`deauth`（`start` / `stop`）与 `csa`（`start` / `stop` / `test`）两张对象表，
      handler 从 `do_deauth()` / `do_csa()` 原样搬入（含 `CSA_AUTO_HOLD_MS` 常量下沉到 `csa.h`）
- [x] `dispatch()` 加别名表：`DEAUTH`→`deauth.start`、`CSA`→`csa.start`、`CSASTOP`→`csa.stop`、`CSATEST`→`csa.test`，
      未命中就原样落回旧链；`dispatch()` 改为在 `work[128]` 副本上 `strtok`，旧链的 `strtok(nullptr,…)` 不受影响
- [x] 新命令 `WBUS`（列对象）/ `DESCRIBE <obj>`（GUI 建菜单用）/ `CALL <obj>.<method> k=v`（关键字调用）/
      `EVTSUB [pattern]`（默认不订阅 → 老输出零变化）
- [x] 验收：`idf.py build` 0 警告（bin `0x164070`，比 P1 前 +5.7 KB）；`Ran 56 tests, OK`（新增 5 项 wbus 用例）；
      11 条回执与旧文本逐字节一致（`ERR index out of range, run SCAN first`、
      `ERR reason must be 1..65535, or 'random'`、`ERR new channel must differ from the AP channel`、
      `OK CSA 0 auto(opposite-band) count=5 hold=500ms loop=1 ssid=…`、`OK CSASTOP frames=24`…）；
      旧宽容行为保留：`DEAUTH 5x` 前缀解析成 5、`CSA 0 auto 99` 静默忽略 count；
      `EVT deauth.state active=1` 只在 `EVTSUB` 之后出现，`EVTSUB` 取消后立刻消失

### P2 radio 对象：信道仲裁 + TX 收口（2026-11-18 完成）

- [x] 注入策略化：`tx_policy_t{name, min_gap_ms, on_nomem}` + `tx_guard_send_as()`，节拍与 0x101 处置都变成数据。
      **实际是两个策略而不是三个**：`kTxPolicyGuard`（45 ms、重启）与 `kTxPolicyBurst`（0 ms、退避）。
      deauth 的 30 fps 不能变成 33 ms 间隔——它在同一 tick 里发 2 单播 + 1 广播，加了间隔会静默丢掉第二帧；
      BA 的 DELBA→ADDBA→BAR 也必须连发（40 ms 节拍在 `attack_step()` 里，是 −99% 吞吐那个实验的前提）
- [x] 0x101 处置单点化：只剩 `tx_guard.cpp` 一处判断 `ESP_ERR_NO_MEM`，`FATAL tx 0x101 ... policy=<name> -> restart`
      只对 `on_nomem=RESTART` 的策略生效；deauth 与 BA 保持"计一次错、下轮重试"，与 §11 第 7 条原结论一致
- [x] 单播注入收口：`deauth.cpp` 的 `tx_raw()`、`delba.cpp` 的 `tx()` / `ba_tx()` 改走 `kTxPolicyBurst`，
      六个帧级模块与 CSA 继续走 `kTxPolicyGuard`。三类**故意不进守卫**：`PROBE_BROADCAST` 的广播泛洪
      （8 帧/4 ms、无需 ACK，进守卫会把 `txgok` 刷成没意义的数字）、`BARSEQ`/`BATX`/`CTRLTEST` 诊断探针
      （它们存在的目的就是打空池）
- [x] 信道仲裁：新增 `src/radio.cpp` + `include/radio.h`，20 处 `esp_wifi_set_channel()` 全部改走
      `radio_set_channel(owner, ch)`；两个 owner 在 2 s 内抢同一信道时打一条限速 `WARN radio: …`，
      `RADIO` 行新增 `owner=` / `rtake=`
- [ ] `radio.channel.request/release` 的 wbus 对象封装：暂缓到 P4（仲裁本身已生效，现在缺的只是一个方法外壳）
- [ ] 两套 TX 账本合并：**没做，也不建议现在做**。`STATUS` 的 `txok/txerr/...`（deauth/CSA 视角）与
      `txg/txgok/txgerr`（守卫视角）是 GUI、测试和 `lab/*.py` 的契约字段，改口径等于破坏它们。
      真要合并得先给 GUI/测试加一层兼容映射，放到界面数据驱动（P3）之后更省事
- [ ] 混杂回调扇出（`deauth.cpp` 里手写的 `csa_on_rx` / `delba_on_rx` / … 调用链）改成订阅数组：
      P2 未动，它不影响注入路径；等 P4 搬这些模块时一起改
- [x] 验收：`idf.py build` 0 警告（`0x164260`）；`Ran 56 tests, OK`；60 s deauth 浸泡 `txok 7→188`、
      `txerr=0`、`txerr_nomem=0`、零 `FATAL`；`CSA 0 auto` 期间启动 `DEAUTH` 会打出
      `WARN radio: deauth took ch1 from csa (chset=0)` 且 `rtake=2`——两个攻击本来就在抢信道，现在看得见了

### P3 界面数据驱动（估 3–4 天）

- [ ] `DESCRIBE` 补齐 `label / enums / default`，`gui/main.py` 从 18 个手写页面退化成页面工厂
- [ ] `ui.c` 消费同一份元数据生成页面；保留 `ui_commands_drain()` 的"手势只回投主循环"模型
- [ ] 验收：GUI 全功能回归 + 触屏回归；中文页仍由 `tools/gen_cjk_font.py` 子集生成

### P4 余下 8 个模块（估 3–5 天）

- [ ] `delba` / `ba` / `wnm` / `tim` / `eapol` / `pspoll` / `sae` / `authflood` 逐个搬进对象表，
      补齐 `scan` / `targets` / `system` 三个基础对象
- [ ] `serial_console.cpp` 降到 ~400 行，`print_help()` 由描述表生成
- [ ] 验收：每搬一个跑全量测试；`HELP` / `STATUS` 行不变；两个 target（`esp32` / `esp32-c5`）都编过

### 明确不做

- **链接器 section 自动注册**：ESP-IDF 链接脚本没有该 section，要 `KEEP()` 才不被 `--gc-sections`
  吃掉，失败方式是运行期"对象静默消失"。用显式指针数组，编译期就能查重名。
- **JSON + TCP 传输**：CYD 无 PSRAM、空闲堆实测 ~107 KB，lwIP + cJSON 会吃掉一半余量；
  要做得先论证 PSRAM 板型并做成 Kconfig 开关。
- **`attack_step()` 迁到 `wb_tick()`**：它持有跳信道 / 探针 / STA 发现的共享射频状态，
  必须等 P2 的仲裁落地，否则双板时序回归成本远超收益。
- **严格化参数校验**：见铁律 2。

### 风险

- 51 项测试走真串口（`DEAUTHER_PORT=COM5`），**回归必须占用物理板子**，这是主要成本，且空口复测还要一台 AP。
- 别名表必须覆盖动词变体（`DEAUTH_ONLY` / `DEAUTH_EXCEPT` / `BAATTACK` / `BAPLANT` / `BARPUSH` 一族），
  漏一个测试立刻抓出来——这是好事，也是必须每个阶段都跑全量的原因。
- 事件与回复缓冲一律静态分配，不能进 LVGL 任务里 `malloc`。

---

## 6. 已完成的修复

| 状态 | 条目 | 说明 |
| --- | --- | --- |
| `[x]` | deauth 发送路径修复（`b6fd81b`） | 注入从混杂回调移到主循环、加退避、束改 2 单播 + 1 广播、新增 `txok/txerr/txec/blind`；双板验证 `RXMIX deauth=69` |
| `[x]` | 目标选择弹窗（LVGL + Windows GUI） | 模态卡片/窗口，过滤、全选/反选、快照撤销 |
| `[x]` | UART RX 缓冲 256 B → 4 KB | 300 条 PING 洪泛从 233–255 提升到 300/300 |

## 7. 建议顺序

1. **PMKID 抓 + 导出**（第 1 节前两条）——唯一能离线闭环验证的一条，先把它跑通：
   抓到的 `.22000` 用已知密码喂 hashcat，命中即证明"帧解析 → 去重 → 导出格式"全对。
2. **CSA 注入 + 跟随**——需要实机对端才能验证，依赖第 1 步的信道调度代码。
3. **Android 上位机**——协议层无风险，可以并行。
4. **BLE 广播泛洪**——最后做，它会影响 Wi-Fi 侧帧率，要在共存评估之后调参数。

> 第 5 节的架构重构与上面四条互不阻塞，但 **P1 应先于任何新增攻击模块**：
> 否则新模块又要按老办法接七处线，重构的收益被抵消一次。

---

## 免责声明

以上能力仅用于**自有网络**与书面授权的测试环境。对未授权网络抓取哈希、注入管理帧、
洪泛广播，在多数国家和地区均属违法行为。详见 [README 的免责声明](README.md#8-免责声明)。
