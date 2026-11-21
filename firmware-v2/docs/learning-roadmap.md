# 这个工程用了什么库，以及从零学过来要多久

写给会 C/C++ 但没碰过嵌入式的人。每一条都指向仓库里的真实文件，不讲空话。

**起点假设**：你会写 C，看得懂指针和结构体；没写过 MCU，没配过交叉编译，没读过串口日志。
**终点**：能在这个仓库里独立加一种攻击、或者改一版界面，出了问题知道从哪查。

---

## 一、库清单

| 库 | 版本 | 干什么 | 在哪儿用 |
|---|---|---|---|
| ESP-IDF | 6.1.0 | 芯片厂商的整套 SDK：启动、驱动、WiFi 协议栈、构建系统 | 全工程 |
| FreeRTOS | 随 IDF | 实时操作系统内核：任务、队列、延时 | `main/main.c`、`hal_wifi.c` 的 RX 任务 |
| esp_wifi | 随 IDF | WiFi 驱动：STA/AP 模式、裸帧注入、混杂接收、扫描、TSF | **只有** `components/hal_wifi/` |
| esp_timer | 随 IDF | 微秒级计时 | `main.c` 的主循环、`hal_wifi` 的节流 |
| NVS | 随 IDF | flash 键值存储，掉电不丢 | `plat_storage.c`（存注入速率、触摸校准） |
| esp_lcd + esp_lcd_ili9341 | 2.1.0 | LCD 面板驱动（SPI） | `plat_display.c` |
| XPT2046 | 无（自己写的） | 电阻触摸屏控制器 | `plat_touch.c`，裸 SPI 时序 |
| LVGL | 9.5.0 | 图形库：控件、布局、动画 | `wireless_ui/` |
| esp_lvgl_port | 6.1.0 | LVGL 与 ESP-IDF 的胶水：刷屏任务、输入设备注册 | `wireless_ui/ui_port.c` |
| CMake + Ninja | 随 IDF | 构建：CMake 描述依赖，Ninja 执行编译 | `CMakeLists.txt`、`build/` |
| esptool | 随 IDF | 烧写 flash、读芯片信息 | `idf.py flash` 背后 |

外加一个**不在清单里但必须提**的东西：`host_tests/`。`wifi_frame` 和 `wbus` 是纯 C，
不依赖 WiFi，所以能在 PC 上用 gcc 直接跑测试（现在 116 + 70 项）。这是全工程唯一能在
不插板子的情况下验证逻辑的地方。

---

## 二、硬件地图（先认清哪块板是什么）

| 板子 | 芯片 | 串口 | 有屏 | 用途 |
|---|---|---|---|---|
| CYD（ESP32-2432S028R） | ESP32-D0WD-V3 | COM5 | 有（ILI9341 + 触摸） | 注入板 |
| 第二块 ESP32 | ESP32-D0WDR2-V3 | COM6 | 无 | 嗅探板，同一份固件 |
| ESP32-C5 | ESP32-C5HR8 | COM10 | 无 | 双频 / WiFi 6，跑的是老工程那份固件 |

C5 只引出原生 USB（USB-Serial-JTAG），没有 UART0 排针。所以它的 `Serial` 必须指向
HWCDC，否则能烧写但一条命令都不回——这个坑在 `firmware/CMakeLists.txt` 里用
`ARDUINO_USB_MODE=1` 解决。

CYD 的接线（`plat_display.c` / `plat_touch.c` 里写死）：

```
LCD  : SPI3  MISO12 MOSI13 SCLK14 CS15 DC2  BL21   320x240
触摸 : SPI2  MOSI32 MISO39 SCLK25 CS33             XPT2046
控制台: UART0 115200
```

注意 LCD 和触摸是**两条独立的 SPI 总线**，不是一条总线两个从设备。这是 CYD 的板子设计。

---

## 三、学习路线

每阶段给：目标 / 读什么 / 动手 / 验收 / 天数（每天 2 小时）。

### 阶段 0：把东西跑起来（2 天）

**目标**：讲清"源码 → BIN → flash → 上电 → bootloader → app_main → 串口出字"这条链。

人话版：你写的代码被交叉编译器编成机器码，打包成一个 bin 文件，用 esptool 通过 USB 写进
flash 的固定位置。芯片上电后先跑一段厂商固化的 bootloader，它看看有没有要升级，没有就跳到
你 app 的入口 `app_main()`。整个过程你看不见，只能通过串口日志确认。

**读**：`README.md` 的"构建与烧写"一节；`partitions.csv`；`main/main.c`（只有 70 行）。

**动手**：

```powershell
Remove-Item Env:MSYSTEM -ErrorAction SilentlyContinue
& 'C:\Espressif\tools\Microsoft.v6.1.PowerShell_profile.ps1' | Out-Null
idf.py -B build build
idf.py -B build -p COM5 flash
idf.py -B build -p COM5 monitor      # 退出按 Ctrl+]
```

然后在 monitor 里敲 `PING`，应该回 `OK PONG`。

**验收**：不看资料，说出 `0x1000`（bootloader）、`0x8000`（分区表）、`0x10000`（app）三个
偏移各放什么；解释为什么 C5 的 bootloader 在 `0x2000` 而不是 `0x1000`。

**坑**：Git Bash 里直接跑 `idf.py` 会报错退出，因为 Git Bash 设了 `MSYSTEM` 环境变量。
必须走 PowerShell 包装，或者先 `unset MSYSTEM`。

### 阶段 1：ESP-IDF 的组件模型（2 天）

**目标**：看懂 `components/` 下每个目录是怎么被编进来的。

人话版：IDF 把代码按"组件"（component）切块，每个块有自己的 `CMakeLists.txt`，声明
"我有这些源文件、我要用哪些别的组件"。顶层的 `idf.py build` 会把依赖关系理清楚，一个个编。
`REQUIRES` 写漏了就是找不到头文件，不会自动帮你猜。

**读**：`main/CMakeLists.txt`、`components/hal_wifi/CMakeLists.txt`、
`components/wireless_ui/CMakeLists.txt`、根 `CMakeLists.txt` 里 `-Wl,-z,muldefs` 那几行。

**动手**：新建一个空的 `components/foo/foo.c` + `CMakeLists.txt`，在 `main/CMakeLists.txt` 的
`REQUIRES` 里加上 `foo`，加一行 `#include "foo.h"` 调一个空函数，编译通过。

**验收**：解释 `REQUIRES` 和 `PRIV_REQUIRES` 的区别；解释为什么
`idf_component_register` 不能放进 `if()` 里（条件分支里的 `REQUIRES` 不生效）。

**双 target 的坑**：切 target 会重写工程级 `sdkconfig`，所以 C5 必须用单独的
`-B build_c5 -D SDKCONFIG=sdkconfig.c5 -D IDF_TARGET=esp32c5` 三件套，否则会把 ESP32 的
配置覆盖掉。

### 阶段 2：FreeRTOS 的三个概念（2 天）

**目标**：看懂任务、队列、tick，能解释"为什么 RX 回调里不能发包"。

人话版：FreeRTOS 是个抢占式调度器，每个"任务"是一个死循环，系统按优先级轮着给你 CPU。
队列是任务之间传数据的通道，一边塞一边取，满了就丢或阻塞。

**读**：`hal_wifi.c` 的 `sniffer_cb`（跑在 WiFi 任务里）和 `rx_task`（自己创建的）——
这两个函数之间的 `xQueueSend` / `xQueueReceive` 就是队列的典型用法。再看 `main.c` 的主循环。

**动手**：在 `hal_wifi.c` 里把 `RX_QUEUE_DEPTH` 从 8 改成 2，跑
`monitor.start kind=all` 看 `radio.info` 里的 `rx dropped` 涨不涨。改回来。

**验收**：说清 `sniffer_cb` 里为什么只做 `memcpy` + `xQueueSend`，不在里面解析协议；
`rx_item_t` 为什么要把帧数据**拷贝**进队列而不是存指针（提示：驱动缓冲会被复用）。

### 阶段 3：外设（5 天，每天一个）

这里每个外设都遵循同一个套路：**概念 → 本工程怎么用 → 最小实验 → 验收**。

#### 3.1 UART（1 天）

概念：串口是一根线发、一根线收，双方约定同一个波特率（每秒多少位）。115200 意味着
每秒 115200 个 bit，一个字节约 10 bit（含起始停止位），所以一行 100 字节的日志要 8.7 ms。

**读**：`plat_console.c` 全文（不到 200 行）。

**动手**：加一个 `ECHO <text>` 命令，原样返回。

**验收**：解释为什么 `monitor` 的 `max=` 参数是必要的——算一下 50 帧/秒 × 100 字节/行
在 115200 下是每秒多少字节，和波特率上限比一比。

#### 3.2 GPIO（1 天）

概念：一个引脚可以被配成输出（我决定电平高低）或输入（我读电平）。还有上拉/下拉，
防止悬空时读到随机值。

**读**：`plat_led.c`、`plat_display.c` 里背光 GPIO21 的初始化。

**动手**：加一个 `led on` / `led off` 命令。

**验收**：说清为什么背光脚要单独初始化（它不属于 LCD 控制器）。

#### 3.3 SPI + LCD（2 天）

概念：SPI 是主从结构的四线总线（时钟、数据出、数据进、片选）。主机拉低某个从设备的
片选，然后按约定的时钟极性和相位一位一位发。显示屏有两个角色：**命令**和**数据**，
靠一根 DC 脚区分——DC 低时发的字节是命令，DC 高时是像素数据。

**读**：`plat_display.c` 从头到尾。重点是 `esp_lcd_new_panel_io_spi` 的参数、
`draw_bitmap` 回调、`LCD_DRAW_LINES 20` 这个分批刷屏的粒度。

**动手**：把 `LCD_DRAW_LINES` 改成 40，看 `ui.screen` 刷屏的耗时有变化吗（`ui.status`
里有刷屏计数和堆剩余）。

**验收**：解释 320×240×2 字节（RGB565）= 150 KB 为什么不能一次刷进去。ESP32 名义上有
520 KB SRAM，但扣掉 WiFi 协议栈和各种驱动，应用能用的只有 ~290 KB；LVGL 自己的画布池
又占了 80 KB（`CONFIG_LV_MEM_SIZE_KILOBYTES`），所以 `LCD_DRAW_LINES 20` 这种分批刷屏
不是优化，是必须。另外解释 DC 脚的作用。

#### 3.4 XPT2046 触摸 + NVS（1 天）

概念：电阻屏输出的是原始 ADC 值（0..4095），不是屏幕坐标。要建立映射得采四个角算线性
变换，算出来的系数存起来，掉电不丢——这就用到 NVS。

**读**：`plat_touch.c`（裸 SPI 读 0x90/0xD0 命令）、`ui_calib.c`、
`plat_storage.c`。

**动手**：用 `system.touch` 采几次原始值，观察按下和松开的差别。

**验收**：解释为什么换分辨率要重新校准；解释 `plat_storage_set("touch_cal", ...)` 存的是
什么。

### 阶段 4：WiFi 驱动模型（3 天）

**目标**：搞清 `hal_wifi` 为什么要这么写，以及它兜住了哪些坑。

**读**（按顺序）：

1. `hal_wifi.h` 全文——这是整个下层能力的清单
2. `hal_wifi.c` 的 `hal_wifi_init()`：注意速率是在 `esp_wifi_start()` **之前**设的
3. `hal_wifi_tx()`：单播 45 ms / 广播 20 ms 两道限速，`ESP_ERR_NO_MEM` → `esp_restart()`
4. `ieee80211_raw_frame_sanity_check()` 那个桩：为什么必须要它
5. `sniffer_cb()` + `rx_task()`：元数据从哪来

**关键概念，每个都要能用人话解释**：

- **`esp_wifi_80211_tx` 的第四个参数为什么是 `false`**：`en_sys_seq=false` 表示不覆盖帧里的
  序列号，否则发出去的帧序列号会被驱动改掉，嗅探端看到的和你构造的对不上。但注意官方文档：
  **关联到 AP 之后必须传 true**，否则返回 `ESP_ERR_INVALID_ARG`。
- **为什么需要覆盖 `ieee80211_raw_frame_sanity_check`**：`libnet80211.a` 里有个闭源函数会检查
  你要发的帧"像不像正常帧"，不像就拒绝。覆盖成恒返回 0 才能发伪造帧。链接时靠
  `-Wl,-z,muldefs` 允许重复定义。
- **0x101 是什么**：`ESP_ERR_NO_MEM`。驱动有 32 个发送缓冲，全占满之后这个错误会一直返回，
  而且**之后所有 WiFi API 都卡死**，只能重启。所以 HAL 里一见到它就 `esp_restart()`。
- **为什么速率只能在启动时设**：`esp_wifi_config_80211_tx_rate()` 官方只允许在
  `esp_wifi_init()` 之后、`esp_wifi_start()` 之前调用。运行期改没有受支持接口。
- **HT 为什么需要 QoS 载体**：管理帧会被驱动压回 1M，只有 QoS 帧能上 MCS。实测 MCS0–7 和
  短 GI 全部生效，最高 72.2 Mbps。

**动手**：

```text
radio.rate rate=54m        # 写 NVS，重启生效
system.reset
radio.tx_test kind=probe   # 看回执里的 rate= 是不是 54m
radio.info                 # 看 tx ok/err/throttled 和堆剩余
```

**验收**：说清 `radio.tx_bench count=100 gap=0 kind=bar unicast=false` 为什么只测出 50 fps
而不是更快——是 HAL 的广播限速在挡，不是驱动慢。

### 阶段 5：802.11 帧格式（3 天）

**目标**：看到一个帧的十六进制能认出类型、子类型、地址字段在哪。

**读**：`components/wifi_frame/include/wifi_frame/frames.h` 的常量表，
然后 `frame_build.c` 里最简单的两个：`wf_build_deauth`（26 字节）和 `wf_build_bar`（20 字节）。

**必背的三件事**：

1. **Frame Control 两个字节**：低 2 位是协议版本，接着 2 位类型（0=管理 1=控制 2=数据），
   接着 4 位子类型。所以 `0xC0` = 管理/12 = deauth，`0xB4` = 控制/11 = RTS。
2. **地址顺序随类型变**：管理帧是 DA/SA/BSSID，ToDS 数据帧是 BSSID/SA/DA，RTS 只有 RA/TA。
   写代码时最容易在这里错位。
3. **长度陷阱**：`rx_ctrl.sig_len` **含 4 字节 FCS**，你要的真实帧长要减 4。这个工程曾经
   因为一条 `sig_len <= 30` 的判断把所有 20 字节的 BAR 整条丢掉，排查了很久。

**动手**：`host_tests/test_frame.c` 里有逐字节断言。改坏一个字节，跑
`sh host_tests/run.sh`，看它能不能抓到。

**验收**：手算出一个 26 字节 deauth 帧每个字节是什么，和 `wf_build_deauth` 的输出对比。

### 阶段 6：本工程的分层与总线（3 天）

**目标**：能说清"为什么改一个攻击不用碰串口代码"。

**读**：`docs/adding-an-attack.md`（配套文档），然后 `wbus/wbus.h` 的参数策略部分。

**动手**：按 `adding-an-attack.md` 加一个空壳攻击（`start` 只回一行字，`tick` 什么也不做），
跑通 `DESCRIBE <名字>` 和 `<名字>.start`。

**验收**：解释 `wb_policy_t` 的 `n_policy` 写错会发生什么（多余参数被当成 unknown），
以及为什么攻击模块不需要知道串口、LVGL、以后可能加的 TCP 传输层。

### 阶段 7：LVGL 界面（4 天，只有 CYD 有屏）

**概念四件套**（先懂这四个，再看代码，否则会晕）：

1. **显示驱动**：LVGL 算好像素后，通过回调把一块区域交给你，你用 SPI 刷进屏。
2. **输入驱动**：LVGL 定时问"有没有触摸"，你把 XPT2046 的原始值转成屏幕坐标返回。
3. **心跳 `lv_tick`**：LVGL 靠一个毫秒计数器算动画进度，必须有人定期加它。
4. **任务 handler**：`lv_timer_handler()` 要在循环里不停被调用，界面才会响应。

**读**：`ui_port.c`（四件套全在这）、`ui_home.c`（三级菜单怎么搭）、`wireless_ui_stub.c`
（关掉 LVGL 时的空实现，说明宏控怎么做的）。

**动手**：在首页加一个只有一行 label 的新页面并烧进去。

**验收**：解释 `CONFIG_WB_LVGL` 关掉之后哪几个文件不参与编译（提示：看 CMakeLists 和
`wireless_ui_stub.c`），为什么 C5 的构建不需要改这里。

**字库的坑**：LVGL 内置字体没有中文。`wireless_ui` 里的中文靠子集字库，换文案要重新生成。

---

## 四、802.11 专项：只针对这个固件需要的部分

上面阶段 5 讲的是"能读帧"，这里讲"能设计攻击"。按重要性排：

1. **管理帧的保护边界**：802.11w（PMF）保护 deauth/disassoc 和部分 Action 帧。所以
   deauth 在强制 PMF 的 WPA3 网络上是无效的，而 BTM Request（category 10, action 7）
   不在保护集里——这是它"等效 deauth 但合法"的原因。
2. **控制帧完全无保护**：RTS/CTS/ACK/PS-Poll 没有任何认证，可以随意伪造。代价是效果
   有限（Delay/DoS，不是彻底断网）。
3. **省电机制**：STA 用 Null Data 的 PM 位声明睡眠，AP 从此把下行帧缓存进 TIM，STA 醒后
   用 PS-Poll 取。两个可注入点：伪造 PM 位、伪造 PS-Poll。
4. **WPA3 判别**：beacon/probe response 的 RSN IE 里找 AKM suite `00-0F-AC:8`（SAE）。
   本工程有 `wf_rsn_has_akm()` 和 `wf_rsn_mfpr_required()` 现成的。
5. **BTM 的前置条件**：受害 STA 必须在 Extended Capabilities IE 里声明支持 BSS Transition
   Management，否则发了也不理。`wf_extcap_has_bss_transition()` 就是干这个的。

---

## 五、常见坑速查

| 症状 | 真正的原因 | 怎么确认 |
|---|---|---|
| 串口一条命令都不回 | C5 上 `Serial` 还指着 UART0（板子只引出 USB） | 看 `ARDUINO_USB_MODE` 有没有定义 |
| 发出去但对面收不到 | 接收侧自己的帧长上限（曾经是 512）把它截了 | 用第三方固件（C5）对长度 |
| `rate=mcs7` 设了但空口是 1M | 用的是管理帧，驱动把管理帧压回 1M | 换 `kind=qosnull` |
| 参数设了不生效 | 参数根本没解析（`parse_rate` 曾经漏了 mcs） | 看回执里回显的值，别只看 `OK` |
| 板子莫名重启 | 帧池打穿（0x101），32 帧上限 | 看 `radio.info` 的 `tx err` 和日志里的 `tx pool gone` |
| 抓到的帧长度对不上自己发的 | `sig_len` 含 4 字节 FCS | 手动减 4 再看 |
| 广播发太快就崩 | 广播没有 ACK 但帧池照样有限 | 看 `tx_bench` 的 `throttled` 计数 |
| 界面上中文全是方块 | 内置字体没有中文字形 | 换子集字库 |
| 编译报重复定义 | 覆盖 `ieee80211_raw_frame_sanity_check` 需要 `muldefs` | 检查根 `CMakeLists.txt` |
| Git Bash 里 `idf.py` 直接退出 | `MSYSTEM` 环境变量 | 走 PowerShell 包装 |

---

## 六、时间预算

按每天 2 小时算：

| 阶段 | 天数 | 累计 |
|---|---|---|
| 0 环境与启动流程 | 2 | 2 |
| 1 组件模型 | 2 | 4 |
| 2 FreeRTOS | 2 | 6 |
| 3 外设（UART/GPIO/SPI-LCD/触摸） | 5 | 11 |
| 4 WiFi 驱动模型 | 3 | 14 |
| 5 802.11 帧格式 | 3 | 17 |
| 6 分层与总线 | 3 | 20 |
| 7 LVGL | 4 | 24 |
| 802.11 专项 | 2 | 26 |

**26 天到"能独立加一个攻击"**。如果目标只是改界面（阶段 0/1/3/7），大约 13 天。

想更快的话，走这条路：**只做阶段 0 → 4 → 5 → 6**（11 天），先能发帧和认帧，
LVGL 和触摸完全跳过——C5 那块板本来也没屏。
