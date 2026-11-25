# AGENTS.md

给 AI 编码代理的项目指南。默认读者**完全不了解**本仓库，读完应能独立编译、改动、测试。

文档与注释主要语言：中文（`README.md`、`firmware/*.md`、`gui` 的界面文案与 docstring）。
固件源码注释是英文（少量历史文件是葡萄牙语），新代码按文件现有语言写，不要混排。

---

## 1. 项目是什么

ESP32 / ESP32-C5 的 **802.11 无线安全测试工具**，由三块代码组成：

- `firmware/` —— ESP-IDF v6.1 工程（Arduino 作为 IDF 组件）。默认**完全静默**：`WiFi.mode(WIFI_MODE_STA)` + `disconnect()`，
  不建 AP、不发 beacon、没有 Web 控制台；扫描与攻击全部由串口命令行驱动。ESP32 目标可选带 LVGL 触摸界面。
- `gui/` —— Windows 桌面上位机（tkinter + pyserial），把同一套协议行包装成三/四级页面；**不含攻击逻辑**。
- `lab/rf_throughput/` —— 独立的迷你 ESP-IDF 工程（一块板当 AP、一块当 STA，TCP 4444 打流），只用于测量 DELBA / BA 攻击对吞吐的影响，不是产品代码。
- `lab/victim_btm/` —— `rf_throughput` 的 STA 专用变体：`CONFIG_ESP_WIFI_11KV_SUPPORT=y`、
  `btm_enabled`/`rm_enabled` 置 1，把每个连接事件的 reason code 打一行日志（`reason=12` 打成
  `BSS_TRANSITION!`），用来判伪造 BTM Request / Neighbor Report 到底有没有被受害者处理。
  原 `rf_throughput` 一字未改，继续提供 `ap` 角色。命令：`ssid <文本>` / `pass <口令>` /
  `country <cc>` / `join` / `sta <ssid>` / `btm <0|1>` / `rm <0|1>` / `ps <0|1|2>` / `scan` / `status` /
  `trigstat`（仅 Wi-Fi 6 目标：读 IDF 私有的 `esp_test_get_hw_tb_statistics()`，
  打 `rx_trig` / `tb_times` / `sifs_abort` / `pwr_oor`，用来判 11ax Trigger 到底有没有被收到、有没有被回应；
  `rx_mpdu` 是活性对照，它为 0 时其余数字无意义）。
  口令只存板子上的 NVS，**不要写进仓库任何文件**。

核心设计：**串口行协议是唯一控制面**。触摸屏按钮、GUI、脚本都只发协议行；攻击实现只有一份（`firmware/src/`）。
改功能时不要为某个界面单独写一条执行路径。

已实现的攻击：deauth（单/全/白/黑名单）、Probe/Beacon 泛洪、CSA 欺骗、DELBA 欺骗、BA 会话劫持、Evil Twin、
802.11v BTM Request 欺骗（BTM）、802.11k Neighbor Report 伪造（RRM）、EAPOL-Start/Logoff 洪泛、SAE Commit 洪泛、
Auth/Assoc 洪泛（WPA3 时自动升级成 SAE）、单播 QoS Null 的 PM 位欺骗（`qosnull.cpp`）、
HE BSRP Trigger 轮询（`bsrp.cpp`，只有帧级证据，调度字段仍是占位值）。
**TIM 投毒（克隆 beacon 改省电位图）已按计划下线**，代码与命令都不在了。
**NAV（虚拟载波侦听）已删除**：注入帧的 Duration 字段由驱动/MAC 重算，应用层改不了，详见 `attack-principles.md` 附录 A。
**PS-Poll 欺骗（控制子类型 10）也已删除**：单播的 PS-Poll 在本 MAC 上发不出去（广播 RA 10/10 上空气、
RA=BSSID 0/10），只留下 PM 位那一半，实测见 `attack-principles.md` §13 与附录 A；
    2026-11 这一半也收敛成单播 QoS Null（`QOSNULL`），另两种承载帧一起下线。
**TSF 投毒也已删除**：beacon 的时间戳字段同样被 MAC 覆盖成接口自己的 TSF（未关联时为 0），
见 §11 第 11 条；当时留下的 `TIM`（只做 TIM 位图）后来整体下线。
攻击原理的完整梳理见根目录 `attack-principles.md`（逐模块四层：协议层定位 / 帧格式 / 有效与失效 /
实现与实测），改模块时同步它。新人上手看 `learning-roadmap.md`（分阶段路线 + 架构分层 + API 盘点），
加模块时把新文件/新命令补进它的第 2/3 章。
`TODO.md` 里是未做的能力（PMKID、WPA-Enterprise、Android 上位机、BLE 泛洪）。

**合规边界**：README §8 声明仅限自有/授权网络。所有改动都要保留该声明，不要为了"方便"去掉确认框、目标校验或免责提示。

## 2. 关键配置文件

| 路径 | 作用 | 入库 |
| --- | --- | --- |
| `firmware/CMakeLists.txt` | `project(wireless_attack)`；强制 Ninja 响应文件；`-Wno-error=missing-field-initializers`；`-Wl,-z,muldefs` | 是 |
| `firmware/main/CMakeLists.txt` | 列出 `../src/*.cpp` 源文件、`INCLUDE_DIRS "../include"`、`REQUIRES arduino-esp32 wireless_ui nvs_flash` | 是 |
| `firmware/main/idf_component.yml` | 钉住 `espressif/arduino-esp32: 4.0.0-rc1` | 是 |
| `firmware/components/wireless_ui/idf_component.yml` | `lvgl ^9.4`、`esp_lvgl_port ^2.7`、`esp_lcd_ili9341 ^2.0`，限定 `target == esp32` | 是 |
| `firmware/components/wireless_ui/Kconfig` | `WIRELESS_ATTACK_LVGL_SUPPORT`（`depends on IDF_TARGET_ESP32`，Kconfig 默认 n，`sdkconfig.defaults` 里开成 y）、`WIRELESS_UI_CJK_CUSTOM` | 是 |
| `firmware/sdkconfig.defaults` | ESP32 默认配置；**改配置改这里** | 是 |
| `firmware/sdkconfig.c5` | ESP32-C5 的完整配置（独立 build 目录用） | 是 |
| `firmware/sdkconfig` | `idf.py set-target` 生成的产物 | 否（`.gitignore`） |
| `firmware/partitions.csv` | 4 MB：nvs 24 K @0x9000、phy、factory 3 MB @0x10000、spiffs 960 K @0x310000 | 是 |
| `firmware/dependencies.lock` | 组件管理器解析结果 | 是 |
| `firmware/include/definitions.h` | 运行参数宏（帧数/周期/缓冲/LED/调试开关） | 是 |
| `gui/requirements.txt` | 唯一运行依赖 `pyserial>=3.5` | 是 |

仓库里**没有** `pyproject.toml` / `package.json` / `setup.py` / lint 配置 / CI 配置：
`gui` 是裸脚本（`import protocol` 按当前目录导入模块，不是包），固件由 ESP-IDF 自己驱动构建。

## 3. 构建

版本要求：**ESP-IDF v6.1**（EIM 安装）、**arduino-esp32 4.0.0-rc1**（首次构建自动下载）、Python 用 IDF 自带 venv 或系统 3.13。

Windows 上必须在 **PowerShell 或 cmd** 里跑 `idf.py`。Git Bash 里 IDF 6.1 会因 `MSYSTEM` 环境变量直接退出（不是工程问题）。

ESP32（含触摸屏界面，build 目录 `build/`）：

```powershell
& 'C:\Espressif\tools\Microsoft.v6.1.PowerShell_profile.ps1'
cd firmware
idf.py set-target esp32
idf.py build
idf.py -p COM5 flash
idf.py -p COM5 monitor
```

ESP32-C5（双频，无触摸屏界面；**独立 build 目录 + 独立 sdkconfig**，与 ESP32 互不覆盖）：

```powershell
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 set-target esp32c5
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 build
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 -p COM8 flash
```

两条 `CMakeLists.txt` 的特殊设置不能删：

- `-Wno-error=missing-field-initializers`：arduino-esp32 4.0.0-rc1 与 IDF 6.1 的结构体新增字段冲突，会触发 Arduino 核里的 `-Werror`。
- `-Wl,-z,muldefs`：`src/deauth.cpp` 覆盖了 `libnet80211.a` 里的 `ieee80211_raw_frame_sanity_check()`（raw 帧注入的前提），重定义不能报错。
- `CMAKE_NINJA_FORCE_RESPONSE_FILE`：工程路径含空格/较长，arduino-esp32 的几十个 include 目录会把命令行顶爆。

产物大小参考：ESP32 带 LVGL 约 1.37 MB，C5 约 1.13 MB（factory 分区 3 MB）。

`lab/rf_throughput/` 是同样方式构建的独立工程（自己的 `build/`、`build_c5/`，`sdkconfig.c5` 不入库）。
`lab/victim_btm/` 同样（`idf.py -B build` 走 `sdkconfig.defaults`；C5 用 `-B build_c5 -D SDKCONFIG=sdkconfig.c5`，
那份 `sdkconfig.c5` 的 console 已改成 UART0，`rf_throughput` 那份是 USB-Serial/JTAG，别搞混）。

## 4. 分层红线与运行时契约

### 4.1 目标分层红线（P0 骨架已建；P5–P10 未落地；完整方案见 `架构与路线图-v2.md`）

依赖方向唯一：`客户端 → transport 插件 → transport_core → wbus → (services | attacks) → wifi_frame / hal_wifi`。
越层 include 由组件 CMakeLists 的 REQUIRES 白名单在编译期拦截；`tools/check_layers.py` 只查漏（`Serial.printf`、预格式化字符串）。

实现落点：**`firmware-v2/` 新工程**（纯 ESP-IDF，无 Arduino、无 managed components，断网可编）；
`firmware/` 只作行为基准（回执/帧字节/计数），代码不迁移、不复用。骨架已建，白名单已写进各组件的 `CMakeLists.txt`。

| 组件 | 允许 REQUIRES | 禁止出现 |
| --- | --- | --- |
| transport 插件（serial_text/lvgl_queue/ble_nus/tcp_json） | 只许 `transport` | `wbus.h`、attacks、`esp_wifi_*` |
| transport_core | `wbus` | 攻击内部头 |
| wbus | 无 Arduino、无 esp_* | 任何 wifi / 802.11 / MAC 字样（grep 为 0 是硬指标） |
| services | wbus、hal_wifi、wtarget、platform | `Serial` |
| attacks | wifi_frame、hal_wifi、wtarget、wbus、platform | `esp_wifi_*`、`Serial`、printf 格式化 |
| wifi_frame | 无 | `Arduino.h`、esp_* |
| hal_wifi | esp_wifi / esp_netif / esp_event / esp_timer | 全仓唯一允许处；唯一调 `esp_wifi_set_channel` 与 `esp_wifi_80211_tx` 的地方 |
| wireless_ui | transport 客户端 API | 直连 wbus、手写命令文本 |
| platform | `nvs_flash`、`esp_driver_uart/gpio/spi`、`esp_timer`、`esp_lcd`、`esp_lcd_ili9341` | 任何无线 / 帧 / 总线概念 |

P0/P1 已落地的实际白名单与三条实测踩坑（组件清单见 `firmware-v2/README.md`）：

- `wbus` 已可用：对象注册表 + `obj.method key=value` 调用 + 参数策略校验 + 回执 + 事件；组件本身不依赖任何 esp_* 组件。
- `transport` 已是插件表（串口插件 + 界面插件），输入行进 `wb_call_line`，回执广播给所有插件；
  `services` 只提供对象，界面能力由 `main` 通过 `services_ui_bind` 注入，界面不直连总线。
- `hal_wifi` 已实现：STA 初始化（不关联、PS 关）、国家码、信道租约（PINNED/ROAMING + 过期）、
  注入（45 ms 单播节流、`0x101` → `esp_restart`、覆盖 `ieee80211_raw_frame_sanity_check` + `-Wl,-z,muldefs`）、
  混杂接收（RX 队列 16 深、帧长上限 512、订阅扇出）、主动扫描、SoftAP、TSF、统计与驱动读回。
- `wifi_frame` 目前只实现 probe request 组帧与 IE/beacon/TIM IE/CSA 解析，其余帧构造仍是空实现（返回 `-1`）。
- `wtarget` 已实现（AP 按 BSSID upsert、RSSI 取最强、STA 记归属 AP）；`services` 的 `scan`/`radio`
  对象把扫描与信道操作暴露成方法。
- `idf_component_register` 不能放进 `if(...)`：条件分支里的 `REQUIRES` 不生效（只登记 `SRCS`/`INCLUDE_DIRS`），
  条件只能作用于源文件列表。踩过：屏幕组件整块 REQUIRES 丢失。
- 渲染（`lv_refr_now`、全屏刷）只能在 LVGL 任务里做。踩过：在 `console` 任务（栈 4 KB）里刷全屏 → 栈溢出重启。
- 方法名在 `wb_method_t` 里写**裸名**（`ping`），对象名只在 `wb_object_t`；写成 `system.ping` 会变成 unknown method。

四条运行时纪律：

1. `wbus_call*` 只能从主循环 `transport_drain` 发起；`wbus_emit` 任务安全（只入队）。
2. 主循环固定顺序：`transport_poll → transport_drain → attacks_tick → ui_tick`；drain 每轮有预算（≤4 条或 ≤2 ms）。
3. 状态变更必发事件；异步结果一律事件，回执只用于同步完成的方法。
4. `0x101 → esp_restart` 只存在于 hal_tx 一条路径；模块层见不到该错误码。

扩展成本基线（超出即说明分层退化，需先停下来复盘）：

- 新增一种上层接口 = 1 个 `.cpp` + 插件表 1 行 + Kconfig 开关。
- 新增一种攻击 ≤ 2 个新文件 + 0 处修改，legacy 命令自动可用。

### 4.2 当前实现（P4；与 4.1 不一致处一律以此为准）

现状（P4 完成；目标分层见 4.1 与 `架构与路线图-v2.md`，执行清单见 `TODO.md §5`）：

```
串口字节 → 行缓冲 → dispatch() ─┬→ 别名表（43 条）→ wbus_call() → 对象 handler（14 个对象）
                                └→ 旧 strcmp 链（25 条管道命令）
LVGL 按钮 → 命令队列 → wireless_console_execute()
                                     wb_reply_t sink（serial_console.cpp 注入）统一打印
```

- wbus（`components/wbus/`）是对象注册表 + 参数策略 + 事件的最小总线，**一个命令搬到对象表后，
  回执文本必须与旧 `strcmp` 分支逐字节一致**（测试与 `lab/*.py` 都靠它解析）。当前已迁移
  **13 个对象 / 40 条别名**：`deauth` / `csa` / `delba` / `ba` / `btm` / `rrm` / `eapol` / `qosnull` /
  `sae` / `authflood` / `probe` / `evil` / `radio`。新增/迁移命令时，回执一律走 `wb_reply_*()`，
  不要在新对象里直接 `Serial.print`。

- `src/main.cpp` 的 `setup()`：初始化串口 → STA 静默 → `init_evil_twin()` → 可选 LVGL 初始化（失败则打印 `WARN` 并回到纯串口形态）。
- `loop()` 每轮：`handle_serial_console()` → `ui_commands_drain()` → `wireless_ui_tick()` → `attack_step()` → `delay(2)` → Evil Twin 捕获期轮询。
- 任务划分：Arduino `loopTask`（主循环；`sdkconfig.defaults` 里 `CONFIG_ARDUINO_RUNNING_CORE=1`，`sdkconfig.c5` 是 0）、
  `scan_task`（prio 2，阻塞式扫描，避免卡主循环）、
  LVGL 任务（`esp_lvgl_port`，prio 4）、Wi-Fi 任务的混杂回调 `sniffer()`（`IRAM_ATTR`，只判断 + 入队，不打印、不发包）。
- **注入不在混杂回调里做**：回调只把"该打谁"塞进队列，主循环 `attack_step()` → `drain_tx_queue()` 按 1 ms 节奏出队，
  驱动拒收（`ESP_ERR_NO_MEM`）时退避 5 ms 重试。这条约束修掉过"计数在涨但帧没出去"的缺陷，别改回去。
- **所有注入走 `tx_guard_send()` / `tx_guard_send_as()`**（`src/tx_guard.cpp`，两个策略）：
  `kTxPolicyGuard`（45 ms 节拍，首个 `0x101` 打 `FATAL tx 0x101 ... policy=…` 后 `esp_restart()`）覆盖
  CSA 与各帧级模块（含 RRM）；`kTxPolicyBurst`（不节拍，`0x101` 只计错退避）覆盖 deauth 与 DELBA/BA
  （它们的多帧序列必须连发）。`BARSEQ` / `BATX` / `CTRLTEST` 这类"故意把池打空"的探针**必须**留在
  守卫之外，否则测不到它要测的东西。单播注入节拍上限约 20 帧/s（§11 第 7 条）——唯一例外是
  `qosnull.cpp`：PM 位帧在 20 帧/s 下几百帧就触发 `0x101`，它用 10 帧/s。
- **攻击模块只在一张表里注册**（`attack_module_t`，`include/deauth.h`）：`attack_modules_register_defaults()`
  在 `main.cpp` 的 `setup()` 里调用一次，之后混杂回调扇出、`attack_step()`、`attack_stop()` 全部遍历这张表。
  加模块 = 表里加一行，不要再往那三处手写调用。P6 计划把这张表搬到 `attacks/include/attack.h`。
- 界面与固件解耦：`components/wireless_ui/` 只暴露纯 C 的 `wireless_ui.h`，按钮通过 `wireless_ui_set_command_cb()`
  注入的回调发协议行；固件 → UI 方向只调 `wireless_ui_scan_begin/add_network/scan_end/status/log` 置标志，
  UI 更新由 `wireless_ui_tick()` 在主循环里加锁应用（不要跨任务直接调 LVGL）。
- NVS 由应用侧注入（`src/storage.cpp`，命名空间 `wui`、键 `calib`），UI 组件不认识 NVS。
- 频段是**运行时**切的：按目标信道设国家码（1–11 → `01`；12–13 → `CN`；≥15 → `CN` + 5 GHz 信道掩码），
  C5 另设 `WIFI_BAND_MODE_AUTO`。不需要为 2.4G/5G 准备两套 sdkconfig。

## 5. 代码组织

固件（`firmware/include/*.h` + `firmware/src/*.cpp`，一个模块一个头）：

| 文件 | 职责 |
| --- | --- |
| `main.cpp` | 启动、UI 命令队列、主循环调度 |
| `serial_console.cpp` | 行缓冲、`dispatch()` 命令分发、所有协议输出（`OK/ERR/INFO/STATUS/NET/…`）、`scan_task` |
| `deauth.cpp` | deauth 攻击、混杂回调 `sniffer()`、AP/STA 表、注入队列、逐 AP 计数、`attack_step()`、reason code 池、raw 帧构造 |
| `csa.cpp` | CSA 欺骗（倒计时播报、单播/广播混合、新信道克隆 beacon、Auth 成功 / Assoc status 17） |
| `delba.cpp` | DELBA 欺骗 + BA 会话劫持（DELBA → 伪造 ADDBA → BAR）、TID 学习 |
| `btm.cpp` | 802.11v BTM Request 欺骗：11v 能力学习、候选 Neighbor Report、Response 计数 |
| `rrm.cpp` | 802.11k Neighbor Report Response 伪造：幻影邻居元素（52/13）、按 STA 轮询发送、count 限次 |
| `bsrp.cpp` | HE BSRP Trigger（subtype 2 / Trigger Type 4）：32 字节单用户帧、AID/信道校验、45 ms 单播节拍；空口 10/10 可见且受害 STA 会回 HE-TB——但前提是 `ul_length ≥ 48` 且 AID 正确（`ap_tx_power`/`target_rssi` 不是闸门，别拿 `pwr_oor` 当判据），回应内容是 QoS Null，见 `测试报告.md §4.4.14`。`BSRPFIELD` 改这些字段 |
| `eapol.cpp` | EAPOL-Start/Logoff 洪泛：ToDS 数据帧 + LLC/SNAP 0x888E，收侧统计 EAP 包 |
| `sae.cpp` | SAE Commit 洪泛、WPA3 判别（`sae_classify`，AUTHFLOOD 也用它）、反 clogging token 回显 |
| `authflood.cpp` | Auth/Assoc 洪泛 + 随机身份轮换 + 嗅到 SAE 后自动转 `sae_start()` |
| `qosnull.cpp` | PM 位欺骗：伪造单播 QoS Null（ToDS，26 字节）让 AP 缓存受害 STA 的下行，每第 6 帧发 PM=0 释放；`qosnull_release()` 是撤销。节拍 10 帧/s（见 §11 第 8 条） |
| `tx_guard.cpp` | 统一注入入口 + 策略：`kTxPolicyGuard`（45 ms、首个 `0x101` 重启）/ `kTxPolicyBurst`（不节拍、`0x101` 退避），并集中记录 ok/err/throttled |
| `radio.cpp` | 信道仲裁：`radio_set_channel(owner, ch)` 记录 owner，两个 owner 在 2 s 内抢同一信道时打 `WARN radio:`；`RADIO` 的 `owner=`/`rtake=` 来自这里 |
| `bus_objects.cpp` | wbus 对象表：14 个对象（`deauth` / `csa` / `delba` / `ba` / `btm` / `rrm` / `bsrp` / `eapol` / `qosnull` / `sae` / `authflood` / `probe` / `evil` / `radio`）的参数策略、handler、事件；handler 从 `serial_console.cpp` 原样搬来，回执字节不变 |
| `include/console_commands.h` | 总线与控制台的桥：`console_scan_count()`、`console_apply_reason()`、`console_ui_log()`、`wbus_register_all()` |
| `components/wbus/` | 迷你 ubus：对象注册表、`wb_arg_spec_t` 参数策略、`wb_reply_t` 注入式输出、`EVT` 事件订阅。纯 C++，不依赖 Arduino/esp_* |
| `ie_util.cpp` | IE 遍历、RSN AKM（SAE/PSK）、MFPR、Extended Capabilities bit19 判定 |
| `evil_twin.cpp` | 克隆热点、DNSServer 劫持、Captive Portal（8080）、凭据表（RAM） |
| `general.cpp` | LED 闪烁等公共工具 |
| `storage.cpp` | NVS blob 封装，供 UI 校准数据使用 |
| `components/wireless_ui/src/` | `ui.c` 界面与对象树、`ui_port.c` LCD/触摸移植、`calib.c` 四角校准 |
| `tools/gen_cjk_font.py` | 生成 `fonts/lv_font_ui_cjk.c`（需 Node + `lv_font_conv` + Windows 自带 Noto Sans SC，产物已入库） |

上位机：`gui/protocol.py` 是纯函数解析层（`classify/parse_net/parse_status/parse_cred/parse_caps/band_of_channel`，
无 Tk 无 IO），`gui/main.py` 是串口线程 + 页面 + 目标弹窗（`SerialLink`、`TargetDialog`、`DeautherApp`）。
页面键：`home / deauth / one / all / only / except / probe / csa / delba / ba / evil / btm / eapol / sae / authflood / qosnull / status / log`。

**新增源文件必须同时加进 `firmware/main/CMakeLists.txt` 的 `SRCS`**，否则不会参与编译。
**新增功能的两端顺序**：先在 `gui/protocol.py` 加解析（可单测）→ 再在 `main.py` 加控件；固件侧先加头文件 + 计数器，再在 `dispatch()` 接线。

## 6. 串口协议（改动必须遵守）

- 115200 8N1，一行一条命令，`\r\n` 结尾；行缓冲 112 字节，超长回 `ERR line too long`。
- 命令在 `dispatch(char* line)` 里先整体 `toupper()` 再匹配（因此命令大小写不敏感、参数区分大小写）。
  它先把整行复制到本地 `work[128]` 再 `strtok`：已迁移到 wbus 的命令由别名表一次取完参数，
  其余命令继续走旧的 `strcmp` 链、沿用 `strtok(nullptr, ...)`。**同一语句里不要写两次 `strtok()`**
  （求值顺序未定义）；新代码走 `CALL` / 对象 handler，天然没有这个问题。
- wbus 命令：`WBUS`（列对象）、`DESCRIBE [obj]`（UI 元数据：标题/方法/参数类型/默认值/枚举）、
  `CALL <obj>.<method> k=v …`（关键字调用）、`EVTSUB [topic|pattern]`（事件流，默认关闭所以老输出不变）。
  加一个攻击对象时同时补 `label` / `enums` / `default`，界面将来直接吃这份元数据。
- 输出是行式纯文本，前缀固定：`OK …` / `ERR …` / `INFO …` / `SCAN_BEGIN` / `NET <idx> <rssi> <ch> <enc> <bssid> <ssid>` /
  `SCAN_END <n>` / `STATUS key=value …` / `STATS_BEGIN|AP|STATS_END` / `STA_BEGIN|STA|STA_END` /
  `CREDS_BEGIN|CRED|CREDS_END` / `RX …` / `RXMIX …` / `UI …`。SSID 含空格且放在 `NET` 行最后。
- `STATUS` 的 `key=value` 是机器可读契约（GUI 底栏、测试、`caps` 能力位都靠它）。加字段是兼容的，**改名/删字段会破坏 GUI 与测试**。
- `<idx>` 只在最近一次 `SCAN` 内有效；重扫后旧索引无意义。
- reason code：缺省 1；`1..65535` 或 `random`（每束从标准定义的 1–11、13–24 里重掷）；非法值（0、负数、越界、非数字）必须 `ERR`，
  不允许静默退化。DELBA 的 reason 只接受 1/32/37/38/39。
- 加命令时要同步：`print_help()` 文本、`firmware/README.md §4.1`、必要的 `gui` 页面、`tests/test_wireless_attack.py`。
- LVGL 界面**只能**通过协议行动作（`wireless_console_execute()`），并提供 `UI`/`UISCREEN`/`UITARGETS`/`UIREASON` 之类的无手指诊断命令，
  以便自动化回归。

## 7. 开发约定

- 缩进：绝大多数 C/C++ 文件 4 空格，左大括号与语句同行；`serial_console.cpp` 与 `include/types.h` 沿用 2 空格的 IDF 风格。
  **按文件现状写，不要整文件重排格式。** Python 4 空格。
- 命名：固件函数/变量 `snake_case`，静态变量 `s_` 前缀（`serial_console.cpp` 里文件级全局用 `g_`），常量 `kCamelCase`，宏 `UPPER_SNAKE`，
  结构体 `xxx_t`。头文件用 `#pragma once`（早期文件是 include guard，保持原样）。
- 攻击模块只更新计数器和状态，**不直接 `Serial.print`**；协议输出走 `wb_reply_t`（sink 由 `serial_console.cpp`
  注入 `Serial`），既避免污染机器可读流，也让同一份对象表将来能喂给 socket / LVGL。
- 每个可观测行为都要有计数器，并能从 `STATUS` 读出来（如 `txok/txerr/txec/blind/rev/delbtr/bassn`）。调参靠数据，不靠感觉。
- 运行参数放 `include/definitions.h`（帧数、周期、缓冲）；改帧数时注意 TX 缓冲会被 ACK 超时占满（单播帧尤其）。
- 不要复活 Web 控制台/SoftAP（上游有、本工程有意移除）。
- LVGL 侧约束：回调里不能阻塞（扫描必须进 `scan_task`）；`lv_layer_top()` 上的弹窗行数受 `LIST_ROWS=30`（数据上限 `MAX_ROWS=64`）限制；
  `CONFIG_LV_MEM_SIZE_KILOBYTES=80`（默认 32 KB 装不下列表，会 `LV_ASSERT_HANDLER` 死机）；中文用自带子集字库，不要换回 191 KB 的 LVGL 合集。
- 日志：`CONFIG_LOG_DEFAULT_LEVEL_WARN`，串口流里不要出现 INFO/DEBUG 噪声；固件调试打印用 `DEBUG_PRINT*`（默认编译为空）。
- 注释写"为什么"（硬件坑、驱动行为、实测数字），不要写"做了什么"；改动后清掉描述旧行为的注释。
- `evil_twin.cpp` 与 `evil_twin.h` 的葡萄牙语注释/文案来自上游，只在新改动的行里改语言。

## 8. 测试

`firmware-v2/` 的自测（不依赖人工点击，失败返回非 0）：

```sh
cd firmware-v2
sh host_tests/run.sh                       # 脱机：wbus 70 + wifi_frame 36 项，用系统 gcc，不需要板子
python tools/selftest.py COM5              # 板端：47 项，复位后逐条校验回执
python tools/aircheck.py COM5 COM6         # 跨板：22 项，一块注入一块嗅探，两块板同一份固件
python tools/pipecheck.py --port COM5      # 速率：读 C5 的 pcap 管道核 radiotap，CCK 断言 / OFDM 记 skip
```

板端脚本覆盖启动横幅、每个对象方法、参数校验报错文案、超长行、突发 40 条背压、
界面日志镜像（`ui.status` 的 `flush` 增长）、刷屏增量、主动扫描、信道仲裁拒绝、
注入闭环（广播 probe request → AP 发回 probe response）与运行期稳定性。

固件旧套件 `firmware/tests/test_wireless_attack.py`（58 个用例，unittest）：

```powershell
cd firmware
$env:DEAUTHER_PORT = "COM5"      # 默认就是 COM5
python -m unittest discover -s tests -v
```

- 端口打不开或固件无响应时，硬件相关测试类会 `SkipTest`（所以不接板子也能跑通，只是大部分跳过）。
- 纯 Python 的协议解析用例（10 个）不需要硬件，任何时候都应通过。
- 用例默认不发攻击帧，例外是 `PROBE_BROADCAST` 的 3 秒计数用例，以及 CSA/DELBA/BA 与七个帧级模块的
  "起来 → 看计数器 → 停"用例（打扫描到的第一个 AP，1–2 秒内 `STOP`）。不要写长期洪泛或对多个 AP
  的自动化用例——那是 `lab/` 脚本（需要人明确执行）该干的事。
- 硬件类用例在 `setUp` 里先发 `STOP/CSASTOP/DELBASTOP/BASTOP` 清残留状态（CSA 自动模式会停在 5G 信道，残留会让后续扫描偶发失败），
  新用例也要遵守这个清理约定。
- 自动化覆盖：协议解析、PING/HELP/STATUS/SCAN、参数校验、`DELBATEST`/`BATEST`/`BTMTEST`/`RRMTEST`/
  `BSRPTEST`/`EAPOLTEST`/`SAETEST`/`AUTHFLOODTEST` 帧字节、`UISCREEN` 逐屏切换、堆稳定性、命令洪泛、
  垃圾字节、PING/STATUS/扫描耗时、LVGL 就绪与弹窗行数/堆余量。`BSRP` 另有纯 Python 的 Trigger 解码单测。
- 空口层面的验证不在 unittest 里：用 C5 的抓包管道 + `lab/cap_frames.py`（帧字段）与
  `lab/air_check.py`（逐模块"起-抓-停"）、`lab/pool_limit.py`（缓冲池速率上限）、
  `lab/soak.py`（逐模块长跑，判据是 `STATUS` 的 `txgerr` 恒为 0 且无 `FATAL tx 0x101`）。
  实测数据见 `测试报告.md §4.4`。
- 回执兼容性矩阵（重构期间必跑）：`python lab/compat_matrix.py check`，89 条命令，
  错误文案逐字比对、OK/TEST 行比对结构（计数器和随机元素自动屏蔽），判据是 `0 command(s) differ`。
  基线 `lab/compat_baseline.json` 由 `baseline` 模式生成；**只有确实要改对外文案时才重新抓基线，
  并在提交信息里说明**。
- 端到端脚本 `lab/btm_sta.py`（BTM vs 真实 11v STA，判据 `btmresp>0`）需要两块 lab 板 + 攻击板同时在位，
  `lab/rf_throughput` 的 STA 角色要 `ps 1` / `btm 1`（后者需要 `CONFIG_ESP_WIFI_11KV_SUPPORT=y`）。
- 客户端侧的 BTM / RRM 判据用 `lab/victim_btm/`（11KV 打开，日志里找 `reason=12 BSS_TRANSITION!`）。
  实测结论见 `firmware/测试报告.md §4.4.12`：候选是幻影时 STA 回 BTM Response 但不动；
  **环境里有同 SSID/同口令的第二个 BSS 时，一条伪造 BTM 能把真实 STA 拐走**
  （`reason=207 ROAMING`，本机 IDF 不用 12）。**跑这类实验前必须 `ps 0`**——驱动默认
  `WIFI_PS_MIN_MODEM`，睡着的 STA 只在 DTIM 附近开窗，第三方注入的单播帧大部分听不见（踩过）。
- 上位机冒烟（不建窗口，可用于验证导入/布局没有崩）：

```powershell
cd gui
python main.py --self-test
```

- 测试数据、性能数字、已修缺陷都写在 `firmware/测试报告.md`。改完行为要更新那里的用例矩阵与数字，不要只改 README。
  现有实证手段：`STATUS` 的 `txok/txerr`、第二块板的 `MON` + `RXMIX`、`CSATEST`/`DELBATEST`/`BATEST` 的逐字节输出。
- 报告结论要区分"帧上空气"和"客户端真的断开"：后者受对端 PMF/PHY 代际影响，不在固件可控范围。

## 9. 提交与文档

- 提交信息用 **Conventional Commits**，`type(scope): 中文简述`，简述不加句号。
  现有 scope（取自提交历史）：`deauth`、`csa`、`delba`、`ba`、`ui`、`lvgl`、`sniffer`；`type` 用过 `feat/fix/docs/test/chore/ux`。
  例：`fix(ui): 目标弹窗建到 25 行时耗尽 LVGL 池，整机静默死机`、`feat(delba): Block Ack 会话拆除攻击（DELBA 欺骗）`。
- 一次提交只做一件事（功能 / 实验数据 / 文档分开），大型实验结论单独提交并在 `测试报告.md` 里落数字。
- 改功能时按需同步：`README.md`（能力矩阵/协议速查）、`firmware/README.md`（协议/行为/限制）、`firmware/测试报告.md`（实测数据）、
  `TODO.md`（状态 `[x]/[~]/[ ]`）、`gui/README.md`（页面与命令映射）。
- 不要提交：`build*`、`managed_components/`、`sdkconfig`、`sdkconfig*.old`、`__pycache__/`、`*.bin/*.elf/*.map`；
  根 `.gitignore` 还排除了 `/blog/`、`/参考博文/`、`/lab/rf_throughput/sdkconfig.c5`、`/lab/victim_btm/sdkconfig.c5` 与上游参考树。
  这些目录在磁盘上存在是正常的，不要"顺手加进 git"。
- 仓库没有任何 CI；"构建 + 接板子跑 unittest + `--self-test`"就是提交前的验证清单。

## 10. 安全与合规注意事项

- 仅限自有/授权网络。README 的免责声明、GUI 的确认框（`DEAUTH_ALL`、Evil Twin）、参数校验都是有意设计，不要移除。
- 默认静默是硬要求：不要引入 SoftAP、beacon 或 HTTP 服务作为常规路径（Evil Twin 是显式命令触发的临时状态，`STOP`/`EVILTWIN_STOP` 必须能回到静默）。
- `ieee80211_raw_frame_sanity_check()` 的覆盖是攻击能力的基础，属于有意为之；不要"修好"它，也不要把它扩散到其它符号。
- 抓到的凭据只存在 RAM（`captured_creds`，上限 50），没有持久化；新增存储要显式说明并考虑擦除路径。
- 串口连接**不要拉低 DTR/RTS**：CH340 会把板子按进复位/下载模式（GUI 与测试客户端都已显式关闭）。
- 不要提交任何真实 SSID/密码/抓包、个人串口或本机路径配置；`firmware/.vscode/settings.json` 含本机 IDF 路径，已被 `.gitignore` 排除。
- 许可是 GPLv3：二次分发保留 `LICENSE` 与致谢章节；新增文件沿用仓库现有版权头风格（本仓库文件普遍没有版权头，按现状）。
  **例外**：`firmware-v2/` 是独立重写、按 Apache-2.0 发布（`firmware-v2/LICENSE` + `NOTICE`），
  新文件首行带 `SPDX-License-Identifier: Apache-2.0` 与 `SPDX-FileCopyrightText`；
  不得把本仓库其余 GPLv3 代码拷进 `firmware-v2/`，否则该目录的许可声明就失效了。

## 11. 已知坑与文档漂移

实现层面的坑：

1. **写入的 Duration 上不了空口（NAV 因此被删除）**：`esp_wifi_80211_tx()` 注入的帧，
   Duration 字段由驱动/MAC 重算——单播一律 `SIFS+ACK@1Mbps`（30/26/20 字节的 action/BAR/data 实测都是 314 µs），
   广播 CF-End 一律 0，RTS 恒 990–1102 µs（随重发速率变）。设 1 µs 与设 32767 µs 结果完全相同，
   六种帧型都不带出我们写的值（C5 抓包实测，`测试报告.md §4.3.4`）。所以"用 Duration 预约信道"
   在本驱动上不可能，任何"覆盖率 = 帧率 × 声明时长"的算法都是假的。
2. **注入帧共享同一个 32 缓冲池，其中只有 CTS 不回收**：池大小 = `mgmt_sbuf_num`（上限 32，改 Kconfig 无效），
   池空即返回 `0x101`。紧循环时任何帧型都在 32 帧处停住（那只是"32 个缓存同时在途"）；把节拍拉到 30 ms，
   **RTS / CF-End / BAR 都能过 100 帧**，唯一例外是 **CTS**：每帧永久吃掉一个缓存，30/200/500 ms 节拍都是 32 帧封顶，
   10 s 静置也不恢复，之后连 wifi 配置 API 都会卡在锁上，只能硬复位。
3. **混杂模式是两级过滤**：`esp_wifi_set_promiscuous_filter()` 的 CTRL 位只是第一级，
   `esp_wifi_set_promiscuous_ctrl_filter()` 默认丢弃全部控制帧；`start_promiscuous()` 已固定设
   `MASK_ALL | (0x7C << 16)`，别退回默认值。掩码的位序是 `16 + subtype`，而 `MASK_ALL`（`0xFF800000`）
   **只覆盖子类型 7–15**——11ax 的 Trigger(2)/TACK(3)/BFRP(4)/NDPA(5)/扩展(6) 全在掩码外，驱动直接丢。
   BSRP 抓不到 subtype 2 就是这个原因，不是帧没发出去；`CTRLFILTER all` 同样按这个合成值设。
4. **11n 射频解不出 Wi-Fi 6（HE）PPDU**：目标 BSS 里只有 HE 客户端时抓不到 client→AP 帧，
   靠 500 ms 广播兜底（`blind=`）保底；客户端是否真断开取决于对端是否强制 PMF（WPA3/802.11w）。
5. **触摸板 PENIRQ（GPIO36）未引到排针**，只能用原始值窗口 + 稳定判据判断按压；屏幕花屏/上下颠倒靠 `invert_color` + `mirror_x/y`。
6. **阻塞扫描会饿死 idle 任务**，所以 `CONFIG_ESP_TASK_WDT_CHECK_IDLE_TASK_*` 关闭；否则 WDT backtrace 会打进协议流。
7. **UART RX 环形缓冲**默认 256 B 会丢整行，必须保持 `SERIAL_RX_BUFFER_SIZE=4096` 且在 `Serial.begin()` 之前设置。

7. **单播注入的可持续速率约 20 帧/s（固件已强制）**：`0x101` 是**我们自己**的驱动拒发（缓存池空），
   不是 AP 的动作。伪造 TA 的单播帧拿不到属于本机的 ACK（AP 回的 ACK 目标是伪造 MAC），硬件重传到
   重试上限才释放缓存；我们也不 ACK AP 的回复，AP 同样反复重发（实测每条 commit 对应 12.7 个回复）。
   实测：20 帧/s 注入 ≈ 空口 ~220 帧/s 负载。漏水桶拟合（排水 ≈32 帧/s、容量 ≈22）：50 帧/s → 63 帧
   `0x101`、40 帧/s → 117 帧、30/20 帧/s → 45 s 各 1350/900 帧零拒收；广播克隆 beacon 50 帧/s
   → 3000 帧零拒收（无需 ACK，缓存立刻回收）。精确占用时长不可观测（`tx_cb` 对注入帧不回调）。
   `tx_guard.cpp` 现在按策略节拍（`tx_guard_send_as()`）：`kTxPolicyGuard` 强制单播 45 ms 间隔、
   首个 `0x101` 立即重启，覆盖七个帧级模块 + `CSA`；`kTxPolicyBurst` 不节拍、`0x101` 只退避，
   覆盖 deauth 与 `DELBA`/BA——它们长跑 19–25 帧/s（在排水速率以下），且 deauth 的"2 单播 + 1 广播"
   与 BA 的 DELBA→ADDBA→BAR 都必须连发，加间隔会静默丢帧。`SAE` 的 `gap_ms` 低于 50 会被抬高并打 `INFO`，
   `STATUS` 的 `txg=` 是被策略挡下的帧数（不算错误）。`BARSEQ`/`BATX` 这类"故意打空池"的探针永在守卫外。
8. **beacon 的 TSF 上不了空口（TSF 投毒因此删除）**：MAC 用接口自己的 TSF 覆盖 beacon 的
   24..31 字节（未关联 STA 时为 0）。实测交给驱动的 `last_tsf=654632723879` vs 空口 `tsf=0`，
   同一帧的 TIM/SSID/interval/capability 逐字节保留。与第 1 条（Duration）同源的驱动字段重写。
9. **`STATUS` 一行约 1.1 KB**：机器读到完整一行 ~80 ms（115200）。`tests` 里 STATUS 往返阈值
   因此从 60 ms 放宽到 120 ms——这是串口带宽，不是固件变慢。

文档与代码不一致处（以代码为准，改动时顺手修正）：

- `firmware/README.md §7.4` 写 LVGL 堆 64 KB，`sdkconfig.defaults` 实际是 **80 KB**（注释解释了 64 KB 不够）。
- `firmware/代码框架与攻击原理.md §3.3` 仍写"每命中 +16 帧"，实际是 `1 单播 + 1 反向 + 1 广播 = 3 帧/命中`（见 `definitions.h` 与 `drain_tx_queue()`）。
- `tests/test_wireless_attack.py` 里 `ESPTOOL_PY` 常量目前未被使用。
- `firmware/代码框架与攻击原理.md §2.8` 仍把 NAV 当作可用模块描述（模块已删除），该节开头已加说明；
  攻击原理以根目录 `attack-principles.md` 为准。
