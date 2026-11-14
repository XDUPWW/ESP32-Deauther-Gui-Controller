# ESP32 Wireless Attack —— 串口控制 + 触摸屏版 deauth / 泛洪 / Evil Twin

一套可以自己编译、自己验证的 ESP32 / ESP32-C5 无线安全测试工具：

- **固件** `firmware/`：ESP-IDF 工程，默认**完全静默**（不建 AP、不发 BEACON、不开网页），
  所有动作由串口命令驱动；ESP32 上可选带 LVGL 触摸屏界面。
- **上位机** `gui/`：Windows 桌面程序（tkinter + pyserial），把串口协议包装成三级菜单。

两块代码是一体的：上位机和触摸屏都只是"发协议行"，固件是唯一的权威控制面。

本项目是 [tesa-klebeband/ESP32-Deauther](https://github.com/tesa-klebeband/ESP32-Deauther)
的改造版（GPLv3），改动明细见文末[许可与致谢](#9-许可与致谢)。

> **仅限自有网络与授权测试。** 详见文末[免责声明](#免责声明)。

---

## 1. 能力矩阵

| 功能 | 串口命令 | ESP32 | C5 2.4G | C5 5G | 验证状态 |
| --- | --- | --- | --- | --- | --- |
| 双频扫描 | `SCAN` | ✅ | ✅ | ✅ | 实测（ESP32 21–44 个 AP，C5 一次上百个） |
| 单目标 deauth | `DEAUTH <idx>` | ✅ | ✅ | ✅ | 帧上空气已双板验证；客户端是否断开会受对端 PMF/PHY 影响（见 §7） |
| 全部 AP deauth | `DEAUTH_ALL` | ✅ | ✅ | ✅ | 十秒 `txok=359`、第二块板收到 `deauth=69` |
| 白名单 deauth | `DEAUTH_ONLY i,j` | ✅ | ✅ | ✅ | 命令/参数校验验证 |
| 黑名单 deauth | `DEAUTH_EXCEPT i,j` | ✅ | ✅ | ✅ | 命令/参数校验验证 |
| CSA 欺骗（PMF 绕过） | `CSA <idx> [ch] [cnt] [secs]` | ✅ | ✅ | ✅ | 帧格式逐字节校验、跨板接收 `csa_action=12`、真实客户端现场生效（人工确认） |
| DELBA 欺骗（拆 Block Ack 会话） | `DELBA <idx> [reason]` | ✅ | ✅ | ✅ | 帧格式逐字节校验、跨板收到 `delba=82`、ADDBA 精确补刀 `delbtr=5`、实验室链路吞吐量 **-99%**（480→5 KiB/s，链路不掉线） |
| BA 会话劫持（DELBA→伪造 ADDBA→BAR） | `BAATTACK <idx> [step]` / `BAPLANT` / `BARPUSH` | ✅ | ✅ | ✅ | 帧格式逐字节校验；只发 2 帧伪造 ADDBA 就把 4 Mbit/s 的流冻结且不自愈（需重连）；“窗口被推走”这一步未单独证明 |
| Probe 泛洪（Beacon + Probe Response） | `PROBE_BROADCAST` | ✅ | ✅ | ✅ | **双板实测**（另一块板扫到 37 个伪造 SSID） |
| STA 嗅探 | `STATIONS [sec]` | ✅ | ✅ | ✅ | 实测（能给出 STA 及其所属 AP） |
| 逐 AP 计数 | `STATS` | ✅ | ✅ | ✅ | 实测 |
| Evil Twin 钓鱼 | `EVILTWIN <idx>` / `EVILTWIN_STOP` / `CREDS` | ✅ | ✅ | 未知 | **只验证到命令接线**，热点/凭据回传未实测 |
| 触摸屏界面 | — | ✅（LVGL） | ❌（宏依赖 ESP32） | ❌ | 实测（校准、菜单、弹窗） |
| Windows 上位机 | — | ✅ | ✅ | ✅ | 无头结构测试 + 人工点击 |

---

## 2. 硬件

| 板子 | 说明 | 本项目用法 |
| --- | --- | --- |
| **ESP32-2432S028R**（CYD，2.8"） | ESP32-WROOM，4 MB Flash，ILI9341 + XPT2046 | 主力板：串口 + 触摸屏界面都跑在这块上 |
| **ESP32-C5**（16 MB Flash / 8 MB PSRAM） | 双频（2.4G + 5G） | 串口版：扫描与攻击支持 5G，**没有触摸屏界面** |

屏幕接线（CYD 固定，不用改）：

| 用途 | 引脚 |
| --- | --- |
| LCD（ILI9341，VSPI） | MISO 12 / MOSI 13 / SCLK 14 / CS 15 / DC 2 / 背光 21 |
| 触摸（XPT2046，独立 SPI） | MOSI 32 / MISO 39 / SCLK 25 / CS 33（PENIRQ/GPIO36 该板**未接**） |
| 板载 RGB LED | GPIO4（低电平点亮；GPIO2 是 LCD 的 D/C，别占用） |

---

## 3. 快速开始

### 3.1 编译烧写固件

需要 **ESP-IDF v6.1**（本工程用 EIM 安装，`arduino-esp32 4.0.0-rc1` 会在首次构建时自动下载）。

```powershell
# 让 idf.py 可用（Windows 下用 PowerShell 的激活脚本）
& 'C:\Espressif\tools\Microsoft.v6.1.PowerShell_profile.ps1'
cd <repo>\firmware

# ESP32-2432S028R（含触摸屏界面）
idf.py set-target esp32
idf.py build
idf.py -p COM5 flash
```

ESP32-C5（独立 build 目录 + 独立 sdkconfig，互不覆盖）：

```powershell
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 set-target esp32c5
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 build
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 -p COM8 flash
```

> `idf.py` 在 Git Bash 里会因 `MSYSTEM` 环境变量直接退出（IDF 6.1 行为），请用 PowerShell 或 cmd。

### 3.2 串口试跑

115200 8N1，命令以 `\r\n` 结尾：

```
PING
SCAN                       → SCAN_BEGIN / NET ... / SCAN_END 21
DEAUTH_ONLY 0,2 7          → OK DEAUTH_ONLY 2 aps
STATS                      → STATS_BEGIN / AP 0 <bssid> ch1 frames=... / STATS_END
PROBE_BROADCAST            → OK PROBE_BROADCAST（start 之后 probe_frames 一直涨）
STOP
```

完整命令表见 [固件 README](firmware/README.md#4-串口协议)。

### 3.3 上位机

```powershell
cd gui
pip install -r requirements.txt
python main.py --port COM5
```

一级菜单选攻击方式 → 二级选模式 → 页内 `扫描 AP` / `选择目标…`（弹窗） / `开始` / `停止`。

### 3.4 触摸屏（ESP32-2432S028R）

首次上电进入四角校准（左上 → 右上 → 右下 → 左下，存 NVS，之后免校准）。菜单：

```
Deauth → One / All / Only / Except → [Scan] [Targets] [Start] / [Stop] [Back] / [Reason: 7 class-3 frame]
Probe  → [Start] [Stop] [Back]
CSA    → [Scan] [Targets] [Start] / [Stop] [Back]   （自动对向频段 + 循环）
DELBA  → [Scan] [Targets] [Start] / [Stop] [Back]   （拆 Block Ack，固定 reason 37）
BA     → [Scan] [Targets] [Start] / [Stop] [Back]   （BA 会话劫持，固定 step 512）
Evil   → [Scan] [Targets] [Clone] [Stop] [Creds] [Back]
```

`Targets` 弹出模态列表，点行单选/勾选，`OK` 保存、`Back` 撤销。

---

## 4. 目录结构

```
.
├── README.md                     ← 你正在看的这个文件
├── LICENSE                       ← GPLv3（继承上游 ESP32-Deauther）
├── .gitignore
├── TODO.md                       ← 路线图：PMKID / CSA / 企业网络 / Android / BLE
├── firmware/                     ← 固件（ESP-IDF 工程）
│   ├── README.md                 ← 构建 / 协议 / 界面 / 故障排查
│   ├── 代码框架与攻击原理.md        ← 802.11 背景 + 攻击原理 + 代码框架
│   ├── 测试报告.md                 ← 用例矩阵、性能、已修缺陷、已知限制
│   ├── CMakeLists.txt / sdkconfig.defaults / sdkconfig.c5 / partitions.csv
│   ├── include/  src/            ← 攻击逻辑 + 串口协议
│   ├── components/wireless_ui/   ← 可选 LVGL 界面（宏控，与主固件解耦）
│   ├── tests/                    ← 自动化用例（36 项）
│   └── tools/gen_cjk_font.py     ← 生成界面用 CJK 子集字库
└── gui/                          ← Windows 上位机
    ├── README.md
    ├── main.py                   ← tkinter 界面（三级菜单 + 目标弹窗）
    ├── protocol.py               ← 协议解析（纯函数，可单测）
    └── requirements.txt          ← pyserial
```

---

## 5. 串口协议速查

| 命令 | 作用 |
| --- | --- |
| `PING` / `HELP` | 探活 / 帮助 |
| `SCAN` | 双频扫描（异步任务，结果逐行 `NET`） |
| `STATUS` | `mode/eliminated/deauth_frames/probe_frames/ch/networks/creds/heap/ui/caps` |
| `DEAUTH <idx> [reason]` | 单目标 deauth |
| `DEAUTH_ALL [reason]` | 全部 AP 轮流打 |
| `DEAUTH_ONLY <i,j,..> [reason]` | 白名单 |
| `DEAUTH_EXCEPT <i,j,..> [reason]` | 黑名单 |
| `REASON [1-65535\|random]` | reason code：固定值 / 每束随机 / 查询当前值 |
| `PROBE_BROADCAST` | 随机 SSID/BSSID 泛洪 Beacon + Probe Response |
| `STATIONS [sec]` | 跳信道嗅探 STA |
| `STATS` | 每 AP 已发 deauth 帧数 |
| `STOP` | 停止一切攻击 |
| `EVILTWIN <idx>` / `EVILTWIN_STOP` / `CREDS` | 克隆热点 / 关闭 / 导出凭据 |
| `TOUCH` / `CALIBRATE` | 触摸原始值 / 重新校准 |
| `UITARGETS` / `UI` | 屏上目标弹窗：打开 / 回报状态（诊断用） |
| `RXLOG` | 打印监听到的 802.11 帧（诊断命中率） |

`reason` 缺省为 1：可给固定值 `1..65535`，或给 `random`（每束从标准定义值里重掷）。
非法值（0、负数、越界、非数字）直接 `ERR`，不会静默生效。`<idx>` 只在最近一次 `SCAN` 内有效。

---

## 6. 架构

```
        ┌───────────────┐   UART 115200 行式协议   ┌──────────────────────────┐
        │ gui  │ ────────────────────────► │  firmware (ESP-IDF)      │
        │ (tkinter)     │ ◄──────────────────────── │  serial_console.cpp      │
        └───────────────┘   OK/ERR/NET/STATUS/...   │        │                 │
                                                   │        ▼                 │
        ┌───────────────┐   同一套命令（进程内）      │  command dispatch        │
        │ LVGL 触摸界面  │ ────────────────────────► │        │                 │
        │ (可选, ESP32)  │                          │  deauth / probe / evil   │
        └───────────────┘                          │  + 计数 + 抓包嗅探        │
                                                   └──────────────────────────┘
```

设计要点：

1. **默认静默**：`WiFi.mode(WIFI_MODE_STA)` + `WiFi.disconnect()`，没有 AP、没有 BEACON、没有 Web 服务。
2. **协议是唯一控制面**：屏上按钮和上位机都只发协议行，攻击逻辑只有一份。
3. **界面可选**：`CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT=n` 时 `components/wireless_ui/` 不编译任何源文件。
4. **频段运行时切换**：按目标信道设国家码 + 信道，C5 额外设 `WIFI_BAND_MODE_AUTO`，所以不需要为 2.4G / 5G 准备两套配置。

---

## 7. 验证状态（诚实版）

**已验证**

- 自动化：36/36 通过（`python -m unittest discover -s tests`，需接板子）
- 双板交叉：ESP32 泛洪期间，ESP32-C5 扫到 37 个伪造 SSID → 泛洪真的上了空口
- 触摸屏：四角校准 → 解算 → 存 NVS → 掉电保持；三级菜单 + 弹窗；`UITARGETS`/`UI` 可无手指复现
- 上位机：无头结构测试（页面组织、弹窗勾选、命令拼接）+ 人工点击
- 性能：PING p50 ≈ 4 ms，STATUS p50 ≈ 23 ms，单次扫描 ≈ 3.5 s，UI 启用后空闲堆 ≈ 107–110 KB

**没有验证 / 别指望**

1. **deauth 的可解码性**：11n 射频解不出 Wi-Fi 6（HE）PPDU，所以"哪台客户端在线"看不全：
   只有 legacy 客户端在跑时 `rxm` 才会涨。现在有两条证据链：`STATUS` 的 `txok/txerr` 证明帧被驱动接受，
   第二块板的 `RXMIX deauth=` 证明帧真的上了空口；拉不到命中时由 `blind=`（500 ms 广播兜底）继续发。
   客户端是否真断开取决于对端是否强制 PMF（WPA3 / 802.11w），这段不在固件可控范围。
2. **Evil Twin 的钓鱼链路**：只验证了命令接线（越界报错、`EVILTWIN_STOP`、`CREDS`），
   克隆热点在 5G 上能否开、凭据回传全链路，都**没实测**。
3. ~~屏上弹窗的观感~~：已人工确认（描边/圆角/字号/行高/滑动/点击都正常）。
4. **C5 无触摸屏界面**：Kconfig 宏 `depends on IDF_TARGET_ESP32`，属设计选择。

上述 1、2 与 UART 丢行已记入[待修清单](firmware/测试报告.md#71-待修清单已记录尚未动手)，暂未动手。

细节见 [测试报告](firmware/测试报告.md)。后续要做的能力（PMKID 抓取与导出、企业网络凭据、DELBA 的多客户端实测、Android 上位机、BLE 广播泛洪）见 [TODO.md](TODO.md)。

---

## 8. 免责声明

本项目仅供**自有网络**的安全研究、教学演示与设备自检使用。

- 对**未授权**网络发送 deauth 帧、伪造热点、收集他人 Wi-Fi 凭据，在中华人民共和国及多数国家和地区
  均属违法行为，可能承担行政或刑事责任。
- 5 GHz 信道与发射功率受各国无线电管理规定约束；本工程按目标信道配置国家码只为实现技术可行性，
  不构成合规建议。
- 使用本项目造成的一切后果（网络中断、设备损坏、法律纠纷）由使用者自行承担，作者不提供任何担保。
- 请勿用于干扰公共通信、商业竞争或任何恶意目的。

---

## 9. 许可与致谢

本项目是 **[tesa-klebeband/ESP32-Deauther](https://github.com/tesa-klebeband/ESP32-Deauther) 的改造版**：
基础 deauth 实现、raw frame 注入、原始 Web 界面的思路都来自它，之后移植到 ESP-IDF、
去掉 Web 控制台改为串口协议、加了 Probe 泛洪、双频支持、触摸屏界面和 Windows 上位机。

代码与思路来自以下 GPLv3 工程：

| 工程 | 用到了什么 |
| --- | --- |
| [tesa-klebeband/ESP32-Deauther](https://github.com/tesa-klebeband/ESP32-Deauther) | **基础** deauth 实现、raw frame 注入、原始 Web 界面 |
| [isiy0/ESP32-Deauther-EvilTwin](https://github.com/isiy0/ESP32-Deauther-EvilTwin) | Evil Twin / 钓鱼页面 / DNS 劫持 |
| [aligngl/ESP32-Deauther-red](https://github.com/aligngl/ESP32-Deauther-red) | 模块化结构、攻击统计 |

按 **GNU GPL v3** 发布，见 [LICENSE](LICENSE)。二次分发请保留本文件与 LICENSE。

发布地址：[XDUPWW/ESP32-Deauther-Gui-Controller](https://github.com/XDUPWW/ESP32-Deauther-Gui-Controller)
（本项目自己的托管仓库，不是上游）。
