# ESP32 Android 快连弹窗研究任务（交给研究型 Agent）

> 这是一份**研究简报 + 委托提示词**，不是代码补丁。目标是给 `firmware-v2` 的 BLE 广播模块
> 补上 Android 侧可复现的“附近设备/配对”卡片载荷，并给出可验证的字节与来源。
>
> 适用边界：自有设备、隔离实验环境。不要写成对他人设备的操作指南，也不要写入真实
> 设备 MAC、账号或个人信息。

---

## 1. 当前目标

在经典 ESP32（legacy 广播，AD 数据 ≤31 字节）上，用已有的 `blespam` 模块发出**一条
Android 会认的广播**，让测试机弹出 Google Fast Pair 的“附近有新设备”卡片（首选），
或给出小米/三星通道的等价载荷（备选）。

判定标准不是“帧发出去了”，而是**目标机侧出现可观测的 UI/通知变化**，且同长度对照
载荷不产生同样变化。

---

## 2. 已有实现（不要重做）

仓库：`firmware-v2`，模块：`components/attacks/blespam/`。

命令面（串口）：

```
blespam.start mode=popup template=<名字> [rotate=addr|data|both] [cycle=50] [itvl=20]
blespam.start mode=popup raw=<完整 AD 十六进制，≤31 字节> ...
blespam.test  ...        # 只渲染并打印 hex，不上空口
blespam.list             # 模板清单
blespam.stop
ble.info                 # 计数：cycles / cycle_err / addr_rot / data_rot / conn_refused / owner
ble.scan action=start duration=N
ble.scan action=list     # 打印观察到的广播原始 hex
```

实现边界：

- 广播是 legacy（ADV_IND / ADV_NONCONN_IND），**单条 AD 数据上限 31 字节**
- 每 `cycle` 毫秒做一次“停广播 → 换随机地址 → 换载荷 → 再开”
- 攻击广播被连接时会立即拆链（`conn_refused` 计数），这是有意设计
- 观察端是另一块 ESP32-C5，跑 `ble.scan`，能给出原始 hex
- 页面上的 `raw=` 直接吃完整 AD Structure，不需要改代码就能试任意载荷

当前模板表：

| 名称 | 平台 | 完整帧（31B） | 状态 |
| --- | --- | --- | --- |
| `microsoft_swiftpair` | Windows | `1eff06000303` + 25×`00` | **已验证** |
| `apple_airpods` | iOS/macOS | `1eff4c0007190120020c0e0a0c0e0a` + 16×`00` | UNVERIFIED（无 iPhone 实测） |

---

## 3. 已完成的实验结果（截至 2026-11-28）

### 3.1 Windows SwiftPair：成立

- 环境：Windows 11 25H2，build 26200，Intel 蓝牙
- 载荷：`1eff06000303` + 25×`00`（31 字节）
- 判据：通知库 `HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.BthQuickPair`
  的 `LastNotificationAddedTime` 前进
- 结果：连续发送 10–12 秒，时间戳前进；重复一次再前进；同长度 Apple 载荷对照组不动
- 结论：SwiftPair 是**纯广播触发**，不需要连接

### 3.2 Android 泛洪可见性：成立

- 环境：Redmi K60（23013RK75C），Android 15（SDK 35），HyperOS 3.0（V816）
- 方法：打开蓝牙设置页，`adb shell uiautomator dump` 抓屏幕文本
- 结果：泛洪前 `BLE-` 命中 0；泛洪 12 秒并点一次“刷新”后命中 3 个（`BLE-207D` 等）
- 备注：列表只保留少量结果，不代表空口只发了 3 帧（同轮 `cycles=211`）

### 3.3 Google Fast Pair：缺一个真实 model ID

- 手机上 GMS 26.45.31 与 `com.google.android.gms/.nearby.discovery.fastpair` 组件都在
- 30 秒被动扫描，`0xFE2C` 零命中——环境里没有 Fast Pair 设备在广播
- 没有可进配对模式的耳机，无法抓真机 model ID
- **没有硬试随机 ID**：Fast Pair 只认 Google 注册过的 3 字节 model ID

### 3.4 小米手环 MiBeacon：0x17 帧无效，0x33 眼镜帧回放成功

抓到的小米手环 10 广播（18 字节，尾部 6 字节是设备 MAC 反序，此处已脱敏）：

```
0201080e1695fe1759fa595aAA BB CC DD EE FF
```

- `02 01 08`：Flags
- `0e 16 95 fe`：Service Data 16-bit，UUID **0xFE95**（小米 MiBeacon）
- 手机上的 nRF Connect 显示同一台设备、同一串 Service Data，逐字节对得上
- 两次抓包里第 5 个服务数据字节从 `5a` 变成 `03`，疑似计数器/状态位

在 Redmi K60 / HyperOS 3.0 上回放两组，各 10–14 秒：

| 组 | 载荷 | `conn_refused` | 通知事件 | 弹窗聚焦 |
| --- | --- | --- | --- | --- |
| A | 原样（真实设备 MAC） | 0 | 0 | 无 |
| B | 尾部换随机 MAC | 0 | 0 | 无 |

判据：`adb logcat -b events`（`notification_enqueue` / `mi_connect`）与
`adb shell dumpsys window` 的焦点变化。

结论（当时）：这条 11 字节的 `0x17` 帧不足以触发卡片；手机连连接尝试都没有。
后续证明这是**帧类型选错**，不是 MAC 或 GATT 的问题——手环还有一条 12 字节的 `0x33`
帧，弹窗走的是那条。

**2026-11-28 追加（替换 MAC + 固定广播地址）**：给 `blespam` 加了 `addr=` 参数后，
用新地址 `D2:11:22:33:44:55`、载荷尾部填同一个 MAC 的反序回放，手机侧日志显示：

- `BtGatt.ScanHelper` 收到 `address=D2:11:22:33:44:55`（RSSI −50）
- `MiuiConfigNetConnectController`：`parse config net scan res device: 00:00:00:33:44:55`
- `getDeviceTimes D2:11:22:33:44:55` → `deviceTimes: -1`
- 紧接着 `device has bonded with app89`，没有弹卡

同一时段真手环的日志是 `deviceTimes: 3` + `ignore the device pop-uo 3 times`，坐实了
“同一设备弹 3 次后不再弹”的计数。也就是说：**MAC 替换和帧格式已经被小米蓝牙组件接受**；
当时以为拦截点在绑定/产品 ID，真正原因是帧类型选错（见追加四）。

**2026-11-28 追加二（取消配对后复测）**：把手环在手机端取消配对后，用同一个 `D2:11:22:33:44:55`
再回放，结果完全不变：`deviceTimes: -1` + `device has bonded with app89`，仍无卡片。
换一个无关地址 `D3:AA:BB:CC:DD:EE` 也是同样两行。结论修正：

- `device has bonded with app89` 是**通用日志**，不是针对某个设备的绑定判断，不能当作门槛
- `deviceTimes: -1` 更像是“这台设备不在小米的弹窗资格表里”，而不是“从没弹过”
- 取消本地配对不改变结果，说明门槛不在本地 bond，而在小米蓝牙组件的设备资格/云端记录
- 目前只回放了 18 字节的 Service Data 帧；手环在扫描 App 里还带 **Complete Local Name**，
  可能是另一条 ADV_IND 或扫描响应。下一步应抓完整的 ADV_IND + SCAN_RSP 成对回放，
  或清 `com.xiaomi.bluetooth` 数据/重启手机后再试；该判断后被追加四推翻（换 MAC 有效，
  前提是 `0x33` 帧且地址与载荷 MAC 一致）

**2026-11-28 追加四（成功）**：手环日志里还有一条 12 字节的 `0x33` 帧
（`parseGlassesScanRes`），弹窗走的是这条。用新地址 `D2:11:22:33:44:55`，载荷：

```
0201080e1695fe3358fa59015544332211d208
```

广播地址固定为同一个 `D2:11:22:33:44:55`（`blespam.start ... addr=D2:11:22:33:44:55`）。
结果：

- Redmi K60 立即弹出 **「发现小米手环10」** 卡片（取消 / 连接），焦点
  `com.xiaomi.bluetooth/...confignet.MiuiConfigNetActivity`，连续 8 次采样都在
- 日志：`parseGlassesScanRes device: 00:00:00:33:44:55, data: 3358FA59015544332211D2`
- `deviceTimes: -1` 后 `MiuiWearableDownload` 拉取 `com.mi.health` 的设备信息，卡片出现
- 截图为证（本机保留，不入库）

**换 MAC 会持续弹**：`blespam.start mode=xiaomi cycle=50` 每轮换一个新地址，
20 秒内手动关掉卡片 **5 次，5 次都重新弹**；日志里 67 次 `parseGlassesScanRes`、
8 个不同地址、114 条 `ignore`（同一地址超过 3 次后的计数）。说明限流是**按地址**的，
换地址就能重置；`mode=xiaomi` 已把“广播地址 = 载荷 MAC”自动化，帧长 19 字节。

**帧控制与能力位**：服务数据的前两字节是 **16 位帧控制**（`frctrl = data[0] + (data[1] << 8)`，
`xiaomi-ble/parser.py:2204`），不是两个独立字段。我们的帧是 `0x5833`：version 5、auth mode 2、
capability include=1、MAC include=1、未加密（`:2206-2216`）。尾部 `08` 是 **capability 字节**
（`:2296-2315`），公开代码只把它拼进日志，**没有定义任何 bit 的含义**；ESPHome 的
`xiaomi_ble.cpp` 完全不解析 capability。

实测改动这些字段不影响卡片：帧控制高字节改 `38/48/58/68`、capability 改
`00/08/28/48/20`，八组都仍然弹「发现小米手环10」，标题不变。**这张卡片由 PID 决定，
不由 capability 或帧控制版本决定**（至少在这条 `0x33` 帧上）。

PID `0x59FA` 在 `devices.py:378` 就是 **Smart Band 10 / M2457B1**；同一族的四个 PID 与
HyperOS 卡片标题一一对应：

| PID | `xiaomi-ble` 名称 | HyperOS 卡片 |
| --- | --- | --- |
| `59FA` | Smart Band 10 | 发现小米手环10 |
| `59FB` | Smart Band 10 NFC | 发现小米手环10 NFC版 |
| `59FC` | Smart Band 10 Ceramic Edition | 发现小米手环10 陶瓷版 |
| `6188` | Smart Band 10 Glimmer Edition | 发现小米手环10 耀影金特别版 |

四个变体都能弹；2026-11-28 复测（每个变体用新地址、6 秒窗口）全部成功，
`MiuiConfigNetActivity onCreate` 的 Address 与注入地址逐条一致，时延 1.2–1.7 秒
（轮询粒度 0.25 秒；个别轮次 `59FB` 约 4 秒，1.3 秒批量窗口会漏检）。
其余 92 个 PID（传感器/开关/门锁/水壶/体脂秤等）在批量 1.3 秒窗口和 6 类 6 秒抽样中
都没有卡片——它们会被 `parse config net scan res` 解析，但进不了手环卡片这条链路。

**PID 表里有耳机/其他手环吗**：没有。`devices.py` 的 96 个条目里，可穿戴只有 4 个
Band 10 变体（`59FA/59FB/59FC/6188`），其余是温湿度、门磁、开关、门锁、水壶、体脂秤等；
没有耳机、没有其他代手环、没有手表。要测耳机只能抓真实小米耳机的广播，或找另一份
厂商 PID 表，这个库帮不上。
将 PID 改成 `3412`（随机）或 `59CF`（体脂秤）后，帧仍被
`parse config net scan res device` 解析，但没有卡片；日志出现
`DeviceBlackList` / `GlassBlackList` 与 `Ignore the device pop-up less than 5 mins`。
所以**设备类型可以换，但只能换成手机设备库认识的 PID**；任意 PID 不会出卡。

**限流有两层，且键很窄**：同一地址最多 3 次；弹出后 5 分钟内再次出现会被
`Ignore the device pop-up less than 5 mins` 挡掉。日志里的地址被掩成
`00:00:00:XX:XX:XX`，实验中发现**复用相同后 3 字节**（例如都叫 `33:44:55`）会互相
触发黑名单，换完整 MAC 时也要换后缀。这一点解释了早期“换 MAC 仍不弹”的假阴性。

**2026-11-28 追加三（计数是否随取消配对重置）**：取消配对后回放真手环原帧，日志仍是
`getDeviceTimes AA:BB:CC:DD:EE:FF`（手环 MAC，已脱敏）→ `deviceTimes: 3` → `ignore the device pop-uo 3 times`。
**取消配对不会重置该计数**，计数是按设备地址持久化的；要重置只能清小米蓝牙组件数据、
换地址（但新地址会落入 `deviceTimes: -1` 的资格问题），或等它自己过期（周期未确认）。

### 3.5 已确认的通道差异

| 通道 | 触发方式 | 现有证据 |
| --- | --- | --- |
| Windows SwiftPair | 纯广播 | 已验证 |
| Apple 邻近配对 | 纯广播（公开资料 + 参考帧） | 未做 iOS 实测 |
| 小米 MiBeacon（0x33 眼镜帧） | 纯广播，广播地址必须与载荷 MAC 一致 | 已验证（Redmi K60，换 MAC 可重复弹） |
| Google Fast Pair | 纯广播（官方设计） | 缺 model ID |

---

## 4. 委托研究的问题

### 4.1 Google Fast Pair（最高优先级）

请给出**一到三个在 Android 15 + GMS 上仍可能被识别的已注册 model ID**，并回答：

1. 完整 31 字节 legacy 广播串：是否要 Flags、Service Data 16-bit（`0x16`）+ UUID `0xFE2C`
   的字节序、3 字节 model ID 的字节序、后面有没有保留字节
2. 广播类型：ADV_IND 可连接、ADV_NONCONN_IND，还是 ADV_SCAN_IND；载荷放广播还是扫描响应
3. Android 侧门槛：GMS 版本、Fast Pair 模块版本、附近设备权限、屏幕状态、通知开关、
   是否要求 Google 账号；中国版 HyperOS 是否有额外限制
4. 已知失效或限流的系统版本；“能被扫描到”与“会弹通知”之间的差别
5. model ID 的公开来源（Google 文档、Android 源码、公开逆向工程仓库、开源广播研究项目）

找不到公开的已注册 ID 就明确写“找不到”，**不要编造，也不要用随机 ID 硬试**。

### 4.2 小米 Mi Connect（格式补充，已部分闭环）

`0x33` 帧已能在 Redmi K60 上稳定触发「发现小米手环10」卡片（换 MAC 可重复弹）。
仍请补充：

1. `0x33 58 FA 59 01 <MAC 6 字节反序> 08` 各字段的语义：`0x33` 帧类型、`58 FA` 产品 ID、
   `01` 计数器/状态、尾部 `08`；计数器是否参与校验
2. 限流规则：同一地址 3 次的上限是持久化在哪个组件、何时重置；是否存在**全局**冷却
   （换地址后仍有短时抑制）
3. 除手环外的产品 ID（体脂秤、耳机等）是否也能触发同类卡片
4. 来源与证据等级；没有公开资料就写“无公开资料”

### 4.3 三星 Galaxy Buds（可选，补齐模板表）

公司 ID `0x0075` 的载荷格式、完整 hex、适用机型与系统版本、来源。

---

## 5. 硬约束

- 只能产出 **≤31 字节** 的 legacy 广播串；放不下的方案要标出来，不要硬塞
- 每条结论必须带来源 URL + 文件路径/行号或文档章节
- 每个字节都要能解释；解释不了的地方标 `UNVERIFIED`
- 区分三类证据：
  - `verified`：官方文档或可复现的真机抓包
  - `inferred`：多份资料交叉推断
  - `unverified`：单一非权威来源
- 不写真实设备 MAC、账号、个人信息
- 不写对他人设备的操作建议；这是自有设备的协议行为验证

---

## 6. 建议的验证步骤（写进结果，供执行方使用）

对每条候选载荷：

1. `blespam.test mode=popup raw=<hex>` 确认长度和字节
2. `blespam.start mode=popup raw=<hex> rotate=addr cycle=50`，持续 10–15 秒
3. 手机侧：
   - `adb shell dumpsys notification --noredact` 前后对比
   - `adb shell uiautomator dump /sdcard/u.xml && adb shell cat /sdcard/u.xml` 抓屏幕文本
   - `adb logcat -b events` 看 `notification_enqueue`
   - `adb shell dumpsys window` 看焦点是否被弹窗抢走
4. 对照：同长度随机载荷、同长度 Apple 载荷各跑一次；只有候选组变化才算成立
5. 记录：手机型号、系统版本、GMS 版本、屏幕状态、通知开关、距离/RSSI

---

## 7. 输出格式

先给一张总表：

| 通道 | 平台 | 标识（model ID / 公司 ID） | 完整 31B hex | 类型 | 证据等级 | 来源 |
| --- | --- | --- | --- | --- | --- | --- |

然后每个通道一节，逐字段解析 hex，附来源；最后单列：

- 找不到 / 存疑 / 需要真机抓包的清单
- 建议的下一轮实验（含对照设计）
- 与本简报中已有结论冲突的地方（如果有）

---

## 8. 当前可用硬件（2026-11-28）

| 角色 | 硬件 | 端口 | 当前固件 | 备注 |
| --- | --- | --- | --- | --- |
| 广播板 | ESP32-2432S028R（CYD，经典 ESP32，CH340） | COM5 | `firmware-v2`（含 `blespam`、触摸屏） | BLE 4.2，legacy 广播；屏幕可手动触发 Spam Flood / Win Popup |
| 观察板 | ESP32-C5（CH343） | COM8 | legacy 抓包固件（已从 4MB 备份还原） | 要当 BLE 观察端需临时刷 `firmware-v2` 的 `build_c5`，跑完还原 |
| 备用 | 无 | COM7 不在位 | — | COM6 存在但角色未确认（疑似 C5 的 USB-Serial/JTAG），不要盲刷 |
| 测试手机 | Redmi K60（23013RK75C） | ADB | Android 15 / HyperOS 3.0 / GMS 26.45.31 | ADB 已授权；当前没有可进配对模式的耳机 |
| 主机 | Windows 11 25H2 build 26200，Intel 蓝牙 | — | — | SwiftPair 通知可用 |

限制：

- 没有 iPhone，`apple_airpods` 模板无法实测
- 没有可进配对模式的 TWS 耳机，Fast Pair / 小米真机抓包暂时做不了
- C5 的 BLE 5.0 扩展广播未开（`sdkconfig.c5` 里 `CONFIG_BT_NIMBLE_EXT_ADV` 未设置）
- COM3/COM4 是主机自带串口，不属于本台架

---

## 9. 构建、刷写与验证命令

### 9.1 环境

- ESP-IDF v6.1：`D:\esp\.espressif\v6.1\esp-idf`；工具目录：`C:\Espressif\tools`
- 激活脚本：`C:\Espressif\tools\Microsoft.v6.1.PowerShell_profile.ps1`
- 必须在 PowerShell 或 cmd 里跑 `idf.py`；Git Bash 里 IDF 6.1 会因 `MSYSTEM` 直接退出
- 工程根：`firmware-v2/`（纯 ESP-IDF，无 Arduino）；串口 115200 8N1，命令以 `\r\n` 结尾

### 9.2 ESP32 广播板（COM5）

```powershell
cd firmware-v2
idf.py build
idf.py -p COM5 flash
```

### 9.3 ESP32-C5 观察板（COM8，独立 build 目录）

```powershell
cd firmware-v2
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 build
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 -p COM8 flash
```

C5 刷 v2 之前先备份，跑完务必还原：

```powershell
# 备份 4MB 整片
& 'C:\Espressif\tools\python\v6.1\venv\Scripts\python.exe' -m esptool `
  --chip esp32c5 -p COM8 -b 460800 read_flash 0 0x400000 firmware-v2\build_c5\c5_backup.bin

# 还原
& 'C:\Espressif\tools\python\v6.1\venv\Scripts\python.exe' -m esptool `
  --chip esp32c5 -p COM8 -b 460800 write_flash 0x0 firmware-v2\build_c5\c5_backup.bin
```

当前工作区里已有一份 2026-11-28 的还原点：`firmware-v2/build_c5/c5_backup_before_blecheck.bin`
（当时 C5 上跑的 legacy 抓包固件）。要回到那个状态直接写这份即可；该文件在 `build_c5/` 下，
已被 `.gitignore` 排除，换机器需要重新备份。

### 9.4 脱机与板端测试

```powershell
cd firmware-v2
sh host_tests/run.sh                 # 纯逻辑，系统 gcc，不需要板子
python tools/selftest.py COM5        # 板端 64 项：命令、参数校验、BLE 攻击、稳定性
python tools/blecheck.py COM5 COM8   # 两块板：一块泛洪、一块扫描，核对空口字节
```

### 9.5 手机侧取证

```powershell
$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
& $adb devices
& $adb shell dumpsys notification --noredact
& $adb shell uiautomator dump /sdcard/u.xml
& $adb shell cat /sdcard/u.xml
& $adb shell logcat -b events -d
```

### 9.6 两个已知操作坑

- 打开 COM5 时 CH340 会拉 DTR，板子复位；`ble.info` 的计数每次打开串口都从零开始，
  计数必须在同一个串口会话里读完
- 刷 C5 会覆盖当前 legacy 抓包固件；实验结束不还原，下一次 Wi-Fi 抓包实验会找不到串口功能
