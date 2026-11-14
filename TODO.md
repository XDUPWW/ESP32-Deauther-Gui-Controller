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
| `[ ]` | **BA 窗口机制的单独验证**（Bl0ck 的核心那一步）：需要按 802.11-2020 10.25.6.6.3 更新 WinStartB 的目标 | 实验台建设 | 可选路线：① 买一块 MT7601U/RTL8188EU USB 网卡 + VirtualBox 直通，Linux 里 hostapd 起 AP、另一台设备当客户端，ESP32 攻击；② 树莓派/旧笔记本当 AP；③ 双系统/Ubuntu Live 用本机的 AX1650i（iwlwifi/mac80211）。判据：`step=512` 把吞吐打到 0 而 `step=0` 不受影响 |
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

## 2. 界面

| 状态 | 条目 | 交付物 | 怎么算完成 |
| --- | --- | --- | --- |
| `[ ]` | **Android 上位机**：USB OTG 串口复用现有行协议 + 三级菜单/目标弹窗，与 Windows GUI 同构 | `android/`（Kotlin，`usb-serial-for-android`） | 手机上能完成 `SCAN → 选目标 → 攻击 → STATS`，协议层与 Windows 版共用一份解析测试 |

> 协议层先行：行协议不变，Android 只做"串口 + 解析 + 界面"，固件侧零改动。
> 如果 OTG 兼容性出问题，再考虑 BLE 串口桥（需要固件加 GATT 服务，属于另一条路）。

## 3. BLE

| 状态 | 条目 | 交付物 | 怎么算完成 |
| --- | --- | --- | --- |
| `[ ]` | **BLE 广播泛洪**：NimBLE 非连接广播，随机 MAC/名称，限速与计数可观测 | `src/ble_flood.c`、命令 `BLE_FLOOD [on/off]` | `STATUS` 有 `ble=` 计数；另一台手机扫描时列表被刷满 |
| `[ ]` | **共存评估**：Wi-Fi 与 BLE 共用射频，洪泛时 Wi-Fi 扫描/攻击的掉帧率 | 测试报告一节 | 给出"BLE 洪泛开着时 Wi-Fi 攻击帧率下降 X%"的实测数字 |

## 4. 已完成的修复

| 状态 | 条目 | 说明 |
| --- | --- | --- |
| `[x]` | deauth 发送路径修复（`b6fd81b`） | 注入从混杂回调移到主循环、加退避、束改 2 单播 + 1 广播、新增 `txok/txerr/txec/blind`；双板验证 `RXMIX deauth=69` |
| `[x]` | 目标选择弹窗（LVGL + Windows GUI） | 模态卡片/窗口，过滤、全选/反选、快照撤销 |
| `[x]` | UART RX 缓冲 256 B → 4 KB | 300 条 PING 洪泛从 233–255 提升到 300/300 |

## 5. 建议顺序

1. **PMKID 抓 + 导出**（第 1 节前两条）——唯一能离线闭环验证的一条，先把它跑通：
   抓到的 `.22000` 用已知密码喂 hashcat，命中即证明"帧解析 → 去重 → 导出格式"全对。
2. **CSA 注入 + 跟随**——需要实机对端才能验证，依赖第 1 步的信道调度代码。
3. **Android 上位机**——协议层无风险，可以并行。
4. **BLE 广播泛洪**——最后做，它会影响 Wi-Fi 侧帧率，要在共存评估之后调参数。

---

## 免责声明

以上能力仅用于**自有网络**与书面授权的测试环境。对未授权网络抓取哈希、注入管理帧、
洪泛广播，在多数国家和地区均属违法行为。详见 [README 的免责声明](README.md#8-免责声明)。
