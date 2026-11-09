# 固件 firmware（ESP-IDF）

ESP32 / ESP32-C5 的无线攻击测试固件。默认**静默**：不建 AP、不发 BEACON、不开网页；
攻击与扫描全部由串口命令驱动，ESP32-2432S028R 上可选带 LVGL 触摸屏界面。

- 总览与硬件/免责：[../README.md](../README.md)
- 攻击原理与代码框架：[代码框架与攻击原理.md](代码框架与攻击原理.md)
- 测试数据与已修缺陷：[测试报告.md](测试报告.md)

---

## 1. 目标与非目标

**目标**

1. 一套代码跑 ESP32（2.4G）与 ESP32-C5（2.4G + 5G），按目标信道运行时切频段/国家码。
2. 默认静默，控制面与攻击面解耦：串口协议是唯一权威接口。
3. 本地触摸屏界面可选（宏控），关掉后固件退回纯串口形态且不链接 LVGL。
4. 攻击效果可观测：总帧数、逐 AP 帧数、命中轮数、监听帧计数都能从串口读出来。

**非目标**

- 不做 Web 控制台（已移除，避免固件自带 AP）。
- 不做"盲发"式 deauth：只在监听到目标 AP 的流量时回敬，减少空放。
- 不做终端扫描/密码破解之外的东西：Evil Twin 只负责克隆与收凭据。

---

## 2. 目录与模块

```
firmware/
├── CMakeLists.txt            响应文件、-Wno-error=missing-field-initializers、-Wl,-z,muldefs
├── sdkconfig.defaults        ESP32 默认配置（tick、分区、WDT、日志、LVGL 开关）
├── sdkconfig.c5              ESP32-C5 覆盖配置
├── partitions.csv            4 MB：nvs 24K / phy / factory 3M / spiffs 960K
├── include/
│   ├── deauth.h              攻击接口、计数器、扫描/射频预设
│   ├── evil_twin.h           钓鱼热点与凭据
│   ├── serial_console.h      命令分发入口
│   ├── definitions.h         宏：信道上限、每轮帧数、reason、LED、调试开关
│   ├── types.h               802.11 帧结构体（空口序）
│   └── storage.h             NVS 注入接口（给 UI 用）
├── src/
│   ├── main.cpp              启动：STA 静默、初始化各模块、主循环 tick
│   ├── serial_console.cpp    串口解析 + 命令实现（SCAN/DEAUTH/...）
│   ├── deauth.cpp            deauth 攻击 + 嗅探触发 + 逐 AP 计数 + STA 嗅探
│   ├── evil_twin.cpp         克隆 AP、DNS 劫持、登录页、凭据表
│   ├── general.cpp           公共工具（信道、国家码、随机 SSID/MAC）
│   └── storage.cpp           用 nvs_flash 实现 UI 的 load/save/clear
├── components/wireless_ui/   可选 LVGL 界面（见 §7）
├── tests/test_wireless_attack.py   36 项自动化用例
└── tools/gen_cjk_font.py     生成界面 CJK 子集字库
```

调用关系（由下往上依赖）：

```
serial_console ──► deauth ──► general
      │            evil_twin
      │
      └──► wireless_ui（可选，只 include 纯 C 头文件）
                │
                └── 回调把按钮变成协议行 → wireless_console_execute()
```

---

## 3. 构建

### 3.1 环境

| 项 | 版本 |
| --- | --- |
| ESP-IDF | **v6.1**（EIM 安装） |
| arduino-esp32 | **4.0.0-rc1**（组件，首次构建自动下载） |
| Python | IDF 自带 venv |
| 主机 | Windows 10/11（Linux/macOS 同样可编，命令去掉 PowerShell 激活即可） |

> Windows 上请用 **PowerShell**（或 cmd）执行 `idf.py`。Git Bash 里 `idf.py` 会因为 `MSYSTEM`
> 环境变量直接退出（IDF 6.1 的行为），不是工程问题。

### 3.2 ESP32（含触摸屏界面）

```powershell
& 'C:\Espressif\tools\Microsoft.v6.1.PowerShell_profile.ps1'
cd firmware
idf.py set-target esp32
idf.py build
idf.py -p COM5 flash
```

### 3.3 ESP32-C5（双频，无触摸屏界面）

切 target 会重写工程级 `sdkconfig`，所以给 C5 单独一套 build 目录和配置文件：

```powershell
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 set-target esp32c5
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 build
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 -p COM8 flash
```

之后切回 ESP32 用普通 `idf.py build` 即可；两套互不覆盖。
（首次切换 target 时组件管理器会重新下载非当前目标的 `managed_components`，属正常现象。）

### 3.4 产物大小

| 目标 | 镜像 | 分区占用 |
| --- | --- | --- |
| ESP32（含 LVGL） | 1.37 MB | 3 MB 分区的 45% |
| ESP32-C5（无 LVGL） | 1.13 MB | 3 MB 分区的 38% |

---

## 4. 串口协议

115200 8N1，每行一条命令，`\r\n` 结尾，命令大小写不敏感。
所有输出都是行式纯文本，便于脚本解析。

### 4.1 命令

| 命令 | 作用 | 典型返回 |
| --- | --- | --- |
| `PING` | 探活 | `OK PONG` |
| `HELP` | 命令帮助 | 多行 `INFO ...` |
| `SCAN` | 双频扫描（异步任务，约 4–10 s） | `SCAN_BEGIN` / `NET ...` / `SCAN_END <n>` |
| `STATUS` | 状态 | `STATUS mode=.. eliminated=.. deauth_frames=.. probe_frames=.. ch=.. rx=.. rxm=.. txok=.. txerr=.. txerr_nomem=.. txec=.. txdrop=.. blind=.. rev=.. reason=.. rlast=.. networks=.. creds=.. heap=.. ui=.. caps=..` |
| `DEAUTH <idx> [reason\|random]` | 单目标 deauth | `OK DEAUTH <idx> <ssid>` / `ERR ...` |
| `DEAUTH_ALL [reason]` | 扫描到的全部 AP 轮流打 | `OK DEAUTH_ALL ...` |
| `DEAUTH_ONLY <i,j,..> [reason]` | 白名单 | `OK DEAUTH_ONLY <n> aps` |
| `DEAUTH_EXCEPT <i,j,..> [reason]` | 黑名单 | `OK DEAUTH_EXCEPT <n> aps` |
| `REASON [1-65535\|random]` | reason code：数字=固定值，`random`=每束随机，不带参数=查询当前值 | `OK REASON 7` / `OK REASON random` / `REASON 7` |
| `PROBE_BROADCAST` | 随机 SSID/BSSID 泛洪 Beacon + Probe Response | `OK PROBE_BROADCAST` |
| `STATIONS [sec]` | 跳信道嗅探 STA（默认 5 s） | `STA_BEGIN` / `STA ...` / `STA_END <n>` |
| `STATS` | 逐 AP deauth 帧计数 | `STATS_BEGIN ...` / `AP ...` / `STATS_END` |
| `STOP` | 停止一切攻击 | `OK STOP eliminated=<n>` |
| `EVILTWIN <idx>` | 克隆 SSID 开钓鱼热点 | `OK EVILTWIN <idx> <ssid>` |
| `EVILTWIN_STOP` | 关闭钓鱼热点 | `OK EVILTWIN_STOP` |
| `CREDS` | 导出捕获凭据（RAM） | `CREDS_BEGIN` / `CRED ...` / `CREDS_END <n>` |
| `TOUCH` | 触摸原始值 + 映射结果 | `TOUCH raw_x=.. raw_y=.. x=.. y=.. pressed=.. irq=..` |
| `CALIBRATE` | 清校准并重启 | `OK CALIBRATE, restarting` |
| `UITARGETS` | 打开屏上目标弹窗（等价点 `Targets`） | `OK UITARGETS` |
| `UI` | 屏状态 | `UI screen=.. popup=.. items=.. nets=..` |
| `RXLOG` | 打印监听到的 802.11 帧（诊断） | `RXLOG_BEGIN <n>` / `RX i type=.. ...` / `RXLOG_END` |
| `RXMIX` | 收到的帧按类别计数（beacon/probe resp/deauth/auth/assoc/ctrl/data），用来验证"帧真的上了空口" | `RXMIX beacon=.. proberesp=.. deauth=.. ctrl=.. data=..` |

`reason` 缺省 1：

- **固定值** `1…65535`。标准明确定义的是 1–11、13–24；用其它值仍会发送，但会打印
  `INFO reason N is outside the defined set ...`（多数客户端会忽略未定义 reason）。
- **`random`**：每一束（每次命中）从这 23 个标准值里重掷一个，`STATUS` 的 `rlast=` 是最近一次用的值。
- **非法输入**（`0`、负数、`>65535`、非数字）→ `ERR reason must be 1..65535, or 'random'`，
  不再像以前那样静默退化成 1。

`<idx>` 只在最近一次 `SCAN` 内有效（重扫后旧索引无意义）。

### 4.2 输出行

```
NET  <idx> <rssi> <信道> <加密> <BSSID> <SSID>      # 信道 >14 即 5 GHz，SSID 在最后（可含空格）
AP   <idx> <bssid> ch<信道> frames=<该 AP 已发 deauth 帧数>
STA  <i> <mac> <所属AP> ch<信道> <rssi>dB frames=<n>
CRED <idx> <用户名> <密码> <时间戳ms>
RX   <i> type=<0..3> sub=<n> len=<n> dest=<mac> src=<mac> bssid=<mac>
```

`caps` 取值：`deauth`、`eviltwin`、`probe`，C5 额外带 `5g`。

### 4.3 用脚本驱动

```python
import serial
ser = serial.Serial("COM5", 115200, timeout=0.2)
ser.write(b"SCAN\r\n")
while True:
    line = ser.readline().decode().strip()
    if line.startswith("SCAN_END"):
        break
```

---

## 5. 攻击命令的行为

| 模式 | 目标集合 | 信道策略 | 触发条件 |
| --- | --- | --- | --- |
| `DEAUTH <idx>` | 1 个 AP | 固定该 AP 信道 | 见到该 AP 的 client→AP 流量、或 AP 的管理帧、或控制帧 |
| `DEAUTH_ALL` | 扫描到的全部 AP | 每 250 ms 跳下一个 AP 的信道 | 同上，任意目标命中即回敬 |
| `DEAUTH_ONLY i,j` | 白名单 | 只在名单内轮询 | 同上 |
| `DEAUTH_EXCEPT i,j` | 全部 − 名单 | 跳过名单 | 同上 |

- 每命中一轮发 **3 帧**，两个方向都伪造（reason code 取当前设置，`random` 模式下每束重掷）：

  | 帧 | Addr1 (dest) | Addr2 (src) | Addr3 (BSSID) | 谁"说"的 |
  | --- | --- | --- | --- | --- |
  | 1 帧单播 | 客户端 MAC | 目标 AP BSSID | 目标 AP BSSID | 伪装成 AP 踢客户端 |
  | 1 帧反向 | 目标 AP BSSID | 客户端 MAC | 目标 AP BSSID | 伪装成客户端"我要走了"，AP 会拆关联并通常自己再通知客户端 |
  | 1 帧广播 | `FF:FF:FF:FF:FF:FF` | 目标 AP BSSID | 目标 AP BSSID | 照顾只认广播 deauth 的廉价设备 |

  单播帧占比压到 2/3 是有原因的：单播要等 ACK，发多了会撞满 TX 缓冲（见 §11）；
  反向帧是新增的一路，专治"过滤 AP 发来的 deauth"的客户端。
  `deauth_frames`、`txok` 与 `STATS` 里的 per-AP `frames` 同步累加。
- 除此之外还有**盲发兜底**：每 `BLIND_DEAUTH_PERIOD_MS = 500 ms` 给当前 AP 发一帧广播 deauth，
  不需要嗅探到任何客户端帧。这样即使目标 BSS 里的客户端完全静默（或者它只会说 802.11ax，
  11n 射频根本解不出来），攻击仍然有效果可打。`STATUS` 里的 `blind=` 就是这个计数。
- 注入不在混杂回调里做：回调只把"该踢谁"塞进队列，主循环按 1 ms 节奏出队、失败退避 5 ms 重试。
  这是修掉"`deauth_frames` 在涨但帧没出去"那个 bug 的关键（见 §11）。
- `PROBE_BROADCAST` 不需要目标也不需要扫描：4 帧/4 ms，SSID/BSSID 每帧随机，120 ms 换信道。
- `STOP` 立即停一切（含 Evil Twin），回到静默。
- 原理与帧结构见 [代码框架与攻击原理.md](代码框架与攻击原理.md)。

---

## 6. 双频与国家码

固件按**目标信道**临时设国家码，否则 12/13 与 5 GHz 会被 `esp_wifi_set_channel()` 拒绝（返回 258）：

| 目标信道 | 国家码 | 说明 |
| --- | --- | --- |
| 1–11 | `01` | 保守，全球通用 |
| 12–13 | `CN` | 需要 `CN` 才允许 |
| ≥ 15（5 GHz） | `CN` + `wifi_5g_channel_mask` | 显式允许 36…165 |

C5 额外调 `esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO)`，之后 `esp_wifi_set_channel()` 自己决定射频落哪个频段。
**不需要**为 2.4G / 5G 准备两套 sdkconfig——频段是运行时切的。

---

## 7. 触摸屏界面（可选）

### 7.1 开关

```powershell
idf.py menuconfig      # Wireless Attack UI (LVGL) -> Enable LVGL touch UI
```

或直接改 `sdkconfig.defaults` 里的 `CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT=y/n`。
宏 `depends on IDF_TARGET_ESP32`，所以 C5 目标自动没有这个界面；
关掉时 `components/wireless_ui/` 只注册成空组件，固件不链接 LVGL。

### 7.2 菜单

```
一级  [Deauth] [Probe]
      [Evil]
二级  Deauth -> [One] [All] / [Only] [Except] / [Back]
三级  模式页：[Scan] [Targets] [Start] / [R:7] [Stop] [Back]
      `R:7` 按钮循环 1 → 7 → 15 → rnd(随机) → 1，每次点击发 `REASON <值>` / `REASON random`
      点 Targets → 模态弹窗（lv_layer_top 上的卡片）
         pick targets (N) - multi
          [x] 0. HomeWiFi | 8C:AA:.. ch1 -40dB
           >  1. Guest    | 8C:AA:.. ch6 -55dB
         [All] [None] [Back] [OK]
```

- 弹窗里 `One/All` 是单选（`>`），`Only/Except` 是勾选（`[x]`）；`OK` 保存、`Back` 撤销（快照还原）。
- `Start` 按当前模式发 `DEAUTH` / `DEAUTH_ALL` / `DEAUTH_ONLY` / `DEAUTH_EXCEPT`。
- `Probe` 页只有 `Start/Stop/Back`（广播泛洪不需要目标）。
- 重扫会清空勾选与单选；弹窗开着也会就地重建列表。
- 诊断：`UITARGETS`（开弹窗）+ `UI`（回报 `screen/popup/items/nets`），不需要用手指点。

### 7.3 触摸校准

首次上电或执行 `CALIBRATE` 后进入校准：依次点**左上 → 右上 → 右下 → 左下**。
判据是"800 ms 静置后连续 3 次采样稳定（±80 原始单位）"，记录后锁存到松手。
解算轴序与增益（可为负），结果写 NVS（命名空间 `wui`，键 `calib`），之后每次启动直接加载。

该板 XPT2046 的 **PENIRQ（GPIO36）没有引到排针**，实测恒为高，所以判"按下"只能靠原始值窗口
`120…3975` + 稳定判据，不要指望中断引脚。

### 7.4 资源占用（ESP32 无 PSRAM）

| 项 | 值 |
| --- | --- |
| LVGL 堆 | 64 KB（默认 32 KB 装不下 30+ 列表行，会卡死主循环） |
| 绘制缓冲 | 320 × 20 × 2 B ≈ 12.8 KB，单缓冲 + DMA |
| 列表行上限 | 30 行/弹窗（扫描数据上限 64 条，可滚动） |
| 中文字库 | 自带子集约 57 KB（LVGL 内置 CJK 子集要 191 KB） |
| UI 就绪后空闲堆 | 107–110 KB |

需要更多空间时可调小 `LIST_ROWS`（`components/wireless_ui/src/ui.c`）、
或关掉 `WIRELESS_UI_CJK_CUSTOM`、或降低 `CONFIG_LV_MEM_SIZE_KILOBYTES`。

字库重生成（需要 Node + `lv_font_conv`，生成文件已入库，平时构建不需要 Node）：

```powershell
npm install -g lv_font_conv
python tools\gen_cjk_font.py     # MAX_CJK_CHARS 控制收录字数
```

---

## 8. 运行模型

```
LVGL 任务 (esp_lvgl_port, prio 4)  lv_timer_handler / flush / indev 读取
主循环 (Arduino loopTask, prio 1)  串口解析、UI 命令队列消费、UI 待更新应用
扫描任务 (scan_task, prio 2)       阻塞式 WiFi.scanNetworks，避免卡住主循环
Wi-Fi 任务                         promiscuous 回调 sniffer()（只做判断 + 发包，不做打印）
```

- 界面回调**不直接碰攻击逻辑**：按钮只把命令投进 FreeRTOS 队列，由主循环执行。
- 界面更新也不跨任务直接调 LVGL：`scan_begin/scan_end/status/log` 只置标志，
  由 `wireless_ui_tick()` 在主循环里加锁应用。
- 触摸 SPI 有互斥锁（LVGL indev 与校准轮询会并发）。

---

## 9. 配置项

`sdkconfig.defaults` 里几个"不这么设就出问题"的项：

| 配置 | 为什么 |
| --- | --- |
| `CONFIG_FREERTOS_HZ=1000` | arduino-esp32 作为 IDF 组件要求 1000 Hz tick |
| `CONFIG_ESP_TASK_WDT_CHECK_IDLE_TASK_*` = n | 阻塞扫描期间 idle 任务不跑，不关会把 WDT backtrace 打进协议流 |
| `CONFIG_LOG_DEFAULT_LEVEL_WARN` | 保证串口协议流干净（只留 WARN 及以上） |
| `CONFIG_MBEDTLS_PSK_MODES` / `KEY_EXCHANGE_PSK` | arduino-esp32 的 NetworkClientSecure 缺这个会 `#warning` 编译失败 |
| `CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM=16` / `DYNAMIC=64` | promiscuous 抓包 + 注入时的缓冲余量 |
| `CONFIG_LV_MEM_SIZE_KILOBYTES=64` | 默认 32 KB 装不下列表，会卡死主循环 |
| `CONFIG_WIRELESS_UI_CJK_CUSTOM=y` | 用自带 57 KB 中文字库替代 LVGL 的 191 KB 合集 |

`include/definitions.h` 里的运行参数：

| 宏 | 值 | 说明 |
| --- | --- | --- |
| `SERIAL_RX_BUFFER_SIZE` | 4096 | UART 接收环形缓冲（默认 256 B，指令洪泛会丢整行） |
| `NUM_FRAMES_PER_DEAUTH` | 1 | 每次命中的 AP→STA 单播帧数（单播要等 ACK，多则撞满 TX 缓冲） |
| `NUM_REVERSE_PER_DEAUTH` | 1 | 每次命中的 STA→AP 反向帧数（让 AP 拆关联） |
| `NUM_BROADCAST_PER_DEAUTH` | 1 | 每次命中追加的广播帧数 |
| `BLIND_DEAUTH_PERIOD_MS` | 500 | 盲发兜底周期（对当前 AP 发广播 deauth） |
| `CHANNEL_MAX` | 13 | 2.4G 上界 |

`CMakeLists.txt` 里两处链接/编译开关：

- `-Wno-error=missing-field-initializers`：arduino-esp32 4.0.0-rc1 与 IDF 6.1 的结构体新增字段冲突。
- `-Wl,-z,muldefs`：`src/deauth.cpp` 覆盖 `ieee80211_raw_frame_sanity_check`（`libnet80211.a` 里同名符号）。

---

## 10. 故障排查

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| `idf.py` 在 Git Bash 里什么都不干就退出 | IDF 6.1 检测到 `MSYSTEM` | 用 PowerShell / cmd，或 `unset MSYSTEM` |
| 编译报 `struct has no member` / `-Werror` | arduino-esp32 版本与 IDF 不匹配 | 确认 arduino-esp32 是 4.0.0-rc1、IDF 6.1 |
| 烧写后串口没输出 | 波特率/端口不对，或 CH340 的 DTR/RTS 把板子按进下载模式 | 115200 8N1；串口工具里关掉 DTR/RTS 自动复位 |
| 屏幕全黑 | 背光/极性/显示参数 | 检查 GPIO21 背光、`invert_color(true)`、`mirror_x/y` |
| 屏幕花屏/上下颠倒 | ILI9341 面板装反 180° | `invert_color(true)` + `mirror_x` + `mirror_y` 同时为真 |
| 点屏幕没反应 | 触摸未校准 / PENIRQ 未接被误当门控 | 先 `CALIBRATE`；确认判据只用原始值窗口 |
| 扫描时界面卡住 | 扫描跑在主循环里 | 扫描必须在 `scan_task` 里跑 |
| 扫到几十个 AP 后死机 | LVGL 堆不足 | 看 §7.4，必要时调小 `LIST_ROWS` |
| `DEAUTH` 一直 `d=0` | 目标信道没有可解码的客户端流量 | 看 `blind=` 是否在涨；`RXLOG` / `RXMIX` 看抓到的帧类型；见 §11 |
| `txerr` 很大、`txok` 很小 | TX 缓冲被打满（束太大 / 重试太急） | 调小 `NUM_FRAMES_PER_DEAUTH`，别在混杂回调里发包；`txec` 会给出驱动错误码 |
| `blind=0` 但已经开始攻击 | 说明卡在信道设置或注入前的环节 | 看 `ch=` 是否是目标信道、`txec` 是否为 0 |
| 5 GHz 扫描不到 | 国家码/5G 掩码没设 | 见 §6 |
| 中文字显示方块 | 字库没有该字 | `tools/gen_cjk_font.py` 扩字表后重新生成 |
| 一串命令只执行了一部分 | UART RX 缓冲被突发打爆 | 已默认 4 KB（`SERIAL_RX_BUFFER_SIZE`）；若仍丢，检查发送端是否有 `\r\n` 或降速 |

---

## 11. 已知限制

1. **deauth 的可见性**：ESP32 是 11n 射频，**解不出 Wi-Fi 6（HE）PPDU**。目标 AP 下只有 Wi-Fi 6 客户端时
   抓不到 client→AP 帧，`rxm` 不动。现在靠 `blind=` 广播兜底保住"仍有帧在发"，
   但客户端是否真的断开还取决于对端是否强制 PMF（WPA3 或开了 802.11w 的客户端会忽略未认证 deauth）。
2. **Evil Twin 未全链路验证**：命令接线 OK，克隆热点在 5G 能否开、凭据回传全流程未实测；
   已保存 WPA2 密码的设备通常不会自动连同名开放热点，真 AP 若开 802.11w/PMF 还会丢 deauth。
3. **C5 没有触摸屏界面**：Kconfig `depends on IDF_TARGET_ESP32`。
4. ~~屏上弹窗的观感~~：已人工确认（描边/圆角/字号/行高/滑动/点击都正常）。

第 1、2 条已记入[待修清单](测试报告.md#71-待修清单已记录尚未动手)（当前只记录，未动手）。
UART 丢行已修复：`Serial.setRxBufferSize(4096)`（`SERIAL_RX_BUFFER_SIZE`），300 条 PING 洪泛实测 300/300 响应。

