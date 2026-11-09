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
