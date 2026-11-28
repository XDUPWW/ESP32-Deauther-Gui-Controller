# 学习路线 —— 从"会 C++"到读懂这套 ESP32 无线测试固件

> 面向对象：会 C/C++ 语法，但**没有嵌入式经验**。不假设你懂 bootloader、分区表、SPI 主从、
> FreeRTOS、LVGL……这些词第一次出现时都会先用大白话解释，并且**一律用本仓库的代码/硬件做例子**。
>
> 本文件是"怎么学"；"攻击为什么有效"在 [`attack-principles.md`](attack-principles.md)（下称《攻击原理》）；
> 命令与行为在 [`firmware/README.md`](firmware/README.md)；实测数字在
> [`firmware/测试报告.md`](firmware/测试报告.md)。
>
> 每天按 **2 小时** 估算。全程按每阶段标注的天数合计 **30 天**；题面说的"约 26 天"是把阶段 6/7 的
> **选读项**（mac80211 对照、字库重生成）砍掉后的速通版，两条路我都标出来了。

---

## 0. 工程全景图（先看这张，再往下）

```
                        ┌─────────────────────────────────────────────┐
   人（手指）            │ 你 / GUI / 脚本                              │
        │               │ gui/main.py（tkinter）  lab/*.py（实验脚本）   │
        │ 触摸           └──────┬──────────────────────┬───────────────┘
        ▼                      │ USB 串口 115200 8N1   │
┌───────────────────┐          │ 一行一条命令          │
│ LVGL 触摸界面      │          ▼                      │
│ components/        │  ┌───────────────────────────┐  │
│  wireless_ui/      │  │ 串口控制台                 │  │
│  ui.c / ui_port.c  │  │ serial_console.cpp         │  │
│ （宏控，只有 ESP32）│  │ dispatch() → do_*()        │  │
└────────┬──────────┘  └───────────┬───────────────┘  │
         │ 按钮只发协议行            │ 同一套 dispatch()   │
         │ wireless_console_execute()│                    │
         └──────────────┬───────────┘                    │
                        ▼                                │
        ┌──────────────────────────────────────────────┐ │
        │ 攻击模块层（每个模块一个 .cpp + 一个 .h）      │ │
        │ deauth  csa  delba  btm  eapol  sae           │ │
        │ authflood  qosnull  evil_twin                 │ │
        └──────┬──────────────────────────┬────────────┘ │
               │ 组帧：手写字节 + IE 解析   │ 发射          │
               ▼                          ▼              │
     ┌──────────────────┐      ┌──────────────────────┐  │
     │ ie_util.cpp      │      │ tx_guard.cpp         │  │
     │ 找元素 / 判 AKM   │      │ 整流器：单播 45 ms     │  │
     └──────────────────┘      │ 首个 0x101 → 重启     │  │
                               └──────────┬───────────┘  │
                                          ▼              │
     ┌──────────────────────────────────────────────────┐ │
     │ ESP-IDF / Arduino 驱动层                          │ │
     │ esp_wifi_80211_tx、混杂模式、信道/国家码、NVS      │ │
     │ SPI（屏幕+触摸）、UART、GPIO、FreeRTOS            │ │
     └──────────┬───────────────────────────────────────┘ │
                ▼                                        │
        ┌──────────────┐   ┌──────────────────────┐       │
        │ Wi-Fi 射频    │   │ ILI9341 屏 / XPT2046   │       │
        └──────┬───────┘   └──────────────────────┘       │
               ▼                                          │
          空口（802.11 帧）  ←── firmware/tests/ 与 lab/ 从这里取证
```

三句话记住这个工程：

1. **控制面只有一条**：串口行协议。手指点屏、GUI 点按钮、脚本发命令，最终都是同一行文本进 `dispatch()`。
2. **攻击实现只有一份**：全在 `firmware/src/`；界面层不含任何攻击逻辑。
3. **两块板子差异很大**：ESP32（CYD，带屏）能跑 LVGL；ESP32-C5 没有屏（Kconfig `depends on IDF_TARGET_ESP32`），
   而且 C5 的 console 默认在 UART0 —— 想从 USB 口收命令得把 console 改到 USB-Serial/JTAG（后面阶段 0 会讲）。

---

# 第 1 章 学习路线

## 阶段 0：环境与人话版启动流程（2 天）

**目标**：能把"写代码 → 变成一个 BIN → 烧进 flash → 上电 → bootloader 跳 app_main → 串口出日志"
这条链完整讲出来，并且知道这条链上每一步在本工程的哪个文件/哪条输出里能看到。

**先补四个词（每个都配本工程实例）**

| 词 | 人话 | 本工程里在哪看到 |
| --- | --- | --- |
| 交叉编译 | 你的电脑是 x86，ESP32 是 Xtensa/ RISC-V 内核。用电脑上的编译器**生成另一种 CPU 的机器码**，这就叫交叉编译。 | `idf.py build` 调用的是 `xtensa-esp32-elf-gcc`（在 `C:\Espressif\tools\` 下），不是你系统里的 `gcc` |
| BIN / 镜像 | 编译产物最后被打包成一个二进制文件，烧写工具把它整块写进芯片外的 flash。 | 构建日志最后一行：`wireless_attack.bin binary size 0x161580 bytes`（≈1.41 MB） |
| flash / 烧写 | ESP32 自己没有硬盘，程序放在**片外**的一颗 SPI NOR flash 里（本板 4 MB）。"烧写"就是把这颗芯片的内容改掉。 | `idf.py -p COM5 flash`；分区表 `firmware/partitions.csv` |
| bootloader | flash 开头有一小段**芯片厂商写死的引导程序**，上电先跑它，它再去 flash 里把"你的程序"搬到内存并跳过去。 | 打开串口时最前面那几行 `rst:0x1 (POWERON_RESET)…` 就是它打的（115200，UART0） |

**阅读顺序**

1. `README.md §3`（编译烧写命令）
2. `firmware/partitions.csv`（4 行，先只看 4 个分区的名字/地址/大小）
3. `firmware/sdkconfig.defaults` 里跟"镜像/分区"有关的三行：
   `CONFIG_ESPTOOLPY_FLASHSIZE_4MB`、`CONFIG_PARTITION_TABLE_CUSTOM`、`CONFIG_PARTITION_TABLE_CUSTOM_FILENAME`
4. `firmware/src/main.cpp` 的 `setup()` 与 `loop()`（只有 99 行，是全工程的入口）
5. `firmware/src/serial_console.cpp` 的 `init_serial_console()`（这里是"串口第一行应用输出"的产地）

**动手练习**

1. `idf.py build` → 记下 bin 大小与"分区剩余百分比"。
2. `idf.py -p COM5 flash` → `idf.py -p COM5 monitor`，等出现这一行：

   ```
   INFO Wireless-Attack ready, type HELP
   ```

   这就是**应用的第一行输出**（上一行可能还是 bootloader 的日志）。在 monitor 里敲 `HELP`、`PING`、`STATUS`。
3. 故意把 `STATUS` 打成 `STATUSS`，看它回 `ERR unknown command ...` —— 这条错误信息来自 `dispatch()` 的最后一个 `else`。
4. 用 `idf.py size-components` 看这 1.41 MB 花在哪（不要背数字，学会**查**的方法就行）。

**验收标准**

- 不看资料画出：源码 → 交叉编译 → `.bin` → 烧进 flash 的 `factory` 分区 → 上电 → 一级 bootloader
  （ROM）→ 二级 bootloader → `app_main` → Arduino 的 `setup()/loop()` → 串口 115200 出 `INFO ... ready`。
- 解释 `partitions.csv` 里四行分别干什么：

  | 分区 | 地址/大小 | 干什么 | 本工程谁用它 |
  | --- | --- | --- | --- |
  | `nvs` | `0x9000` / 24 KB | 键值存储（掉电不丢），像很小的注册表 | 触摸校准（`storage.cpp`，命名空间 `wui`/键 `calib`）；Wi-Fi 驱动自己也会存一点 |
  | `phy_init` | `0xF000` / 4 KB | 射频校准数据 | Wi-Fi 驱动启动时读 |
  | `factory` | `0x10000` / 3 MB | 你的应用镜像就放这 | 就是那个 1.41 MB 的 bin |
  | `spiffs` | `0x310000` / 960 KB | 只读/可写文件系统 | 上游 Evil Twin 页面的静态文件预留（本工程基本没用满） |

- 说出"1.41 MB 里有什么"的**方法**：`idf.py size-components` 按组件列出；
  已知的两块：自研中文字库约 60 KB（`firmware/components/wireless_ui/Kconfig` 的注释）、
  LVGL 的 80 KB 是**内存池**（RAM）不是 flash。

**一个必须知道的坑**：CH340 那类串口芯片，**打开串口时拉低 DTR/RTS 会把板子按进复位或下载模式**。
所以 `gui/main.py` 的 `SerialLink` 和 `lab/*.py` 打开端口后都立刻 `dtr=False, rts=False`。
你自己写脚本时也要这样，否则会出现"一连上板子就重启/没反应"。

---

## 阶段 1：编译框架（2 天）

**目标**：看懂 `main/CMakeLists.txt` 每一行；讲清 "component（组件）" 是什么、
`idf.py` 和 CMake 什么关系、Kconfig 里的宏怎么把整个 LVGL 界面**编译进/排除出**固件。

**先补四个词**

| 词 | 人话 | 本工程实例 |
| --- | --- | --- |
| CMake | 一个"生成构建脚本的脚本"。你写 `CMakeLists.txt` 告诉它有哪些源文件、依赖谁，它生成真正干活的 `ninja` 规则。 | `firmware/CMakeLists.txt`（工程级）与 `firmware/main/CMakeLists.txt`（组件级） |
| `idf.py` | ESP-IDF 的命令行包装器：`build` = 调 cmake+ninja，`flash` = 调 esptool，`monitor` = 开串口。 | `idf.py build` / `-p COM5 flash` / `-B build_c5`（指定构建目录） |
| component（组件） | ESP-IDF 的"代码包"单位：一个目录 + 一个 `CMakeLists.txt`，声明"我有哪些源文件、我依赖谁、我的头文件在哪"。`main` 也是组件。 | `firmware/main/`（应用）、`firmware/components/wireless_ui/`（自研 LVGL 组件） |
| Kconfig → sdkconfig | 一堆开关的声明（`Kconfig` 文件），`idf.py menuconfig` 或直接改 `sdkconfig` 后生成 `sdkconfig.h` 里的 `#define CONFIG_xxx`。代码里用 `#if CONFIG_xxx` 判断。 | `components/wireless_ui/Kconfig` 的 `WIRELESS_ATTACK_LVGL_SUPPORT` |

**阅读顺序**

1. `firmware/CMakeLists.txt` —— 只有 20 行，但三个特殊设置都要能解释：

   | 行 | 作用 | 为什么非要它 |
   | --- | --- | --- |
   | `CMAKE_NINJA_FORCE_RESPONSE_FILE ON` | 让编译命令写进"响应文件"而不是全塞在命令行里 | 工程路径有空格且长，arduino-esp32 会加几十个 `-I`，Windows 命令行长度会爆 |
   | `-Wno-error=missing-field-initializers` | 关掉这一类警告的"报错化" | arduino-esp32 4.0.0-rc1 对着 IDF 6.1 编，结构体新增字段会触发它自己的 `-Werror` |
   | `-Wl,-z,muldefs` | 允许链接时出现**重复符号** | `src/deauth.cpp` 覆盖了 Wi-Fi 闭源库里的 `ieee80211_raw_frame_sanity_check()`（阶段 5/第 2 章会细讲） |

2. `firmware/main/CMakeLists.txt` —— 15 个源文件的清单 + `INCLUDE_DIRS "../include"` +
   `REQUIRES arduino-esp32 wireless_ui nvs_flash`。注意注释里那句：
   `wireless_ui` **永远**是依赖，因为宏关掉时它退化成"只有头文件的空组件"。
3. `firmware/components/wireless_ui/CMakeLists.txt` —— 一个 `if(CONFIG_...)` 决定编译 `ui.c/ui_port.c/calib.c`
   还是 `idf_component_register(INCLUDE_DIRS "include")`（空壳）。这就是"宏控编译"的**第一处**。
4. `firmware/components/wireless_ui/src/ui.c` 第 6–10 行：`#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT`
   把整个文件包住 —— **第二处**。两处缺一不可：CMake 决定"要不要编这个文件"，`#if` 决定"编进来时要不要有代码"。
5. `firmware/sdkconfig.defaults` —— 逐行读，重点：`CONFIG_ARDUINO_RUNNING_CORE=1`、
   `CONFIG_ESP_TASK_WDT_CHECK_IDLE_TASK_*` 为什么关（阻塞扫描会喂不到狗）、
   `CONFIG_LOG_DEFAULT_LEVEL_WARN`（串口是机器可读流，不能被日志噪声污染）、
   `CONFIG_LV_MEM_SIZE_KILOBYTES=80`（注释里写了 64 KB 为什么不够）。

**动手练习**

1. 往 `firmware/src/` 加一个 `hello.cpp`，写一个空函数；在 `main/CMakeLists.txt` 的 `SRCS` 里**漏掉它**编译一次
   （能过，但你的函数不存在），再**加上它**编译一次。体会"漏加进 SRCS 就等于没写"。
2. 把 `sdkconfig.defaults` 里 `CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT=y` 改成 `n`，重新 `idf.py build`，
   比较两次的 bin 大小与 `idf.py size-components` 的组件清单。
3. 恢复成 `y`，用 `idf.py menuconfig` 找到 `Wireless Attack UI (LVGL)` 菜单（就在你自己的组件里）。

**验收标准**

- 能指着 `main/CMakeLists.txt` 说清：`SRCS` / `INCLUDE_DIRS` / `REQUIRES` 三者的区别，以及为什么
  `wireless_ui` 要放进 `REQUIRES` 而不是删掉。
- 能解释宏控**两处**机制（组件 CMake + 源文件 `#if`），并说出宏关掉后 `main.cpp` 里哪几段代码消失
  （`#if CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT` 之间的队列、`wireless_ui_init()`、`ui_commands_drain()`、
  `wireless_ui_tick()`）。
- 知道双 target 的入口：ESP32 用 `sdkconfig.defaults`（默认开 LVGL），C5 用 `sdkconfig.c5`
  （`CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT` 根本不可能为 y，因为 Kconfig 写了 `depends on IDF_TARGET_ESP32`），
  构建目录也分开（`build/` 与 `build_c5/`）。

---

## 阶段 2：外设驱动基础（5 天，本工程硬件实操）

本阶段对每个外设都走同样的四步：**概念 → 本工程接线/用法 → 最小改动实验 → 验收**。
教具就是这块 CYD（ESP32-2432S028R）：屏是 ILI9341，触摸是 XPT2046，另有一颗 RGB LED。

> 引脚从哪来？`firmware/components/wireless_ui/src/ui_port.c` 开头的注释就写着完整表，
> 不是猜的：`LCD: MISO 12, MOSI 13, SCLK 14, CS 15, DC 2, RST -1, backlight 21` /
> `Touch: MOSI 32, MISO 39, SCLK 25, CS 33, IRQ 36`。

### 2.1 GPIO（第 1 天）

**概念**：GPIO = 通用输入输出引脚。配成输出就是"我能把这个脚拉高（3.3V）或拉低（0V）"，
配成输入就是"我读这个脚现在是高还是低"。板上 LED 常是"低电平点亮"（因为 LED 正极接 3.3V、
引脚接地才通），这一点必须看代码而不是猜。

**本工程用法**

- `firmware/include/definitions.h`：`#define LED 4` 与 `#define LED_ACTIVE_LOW 1`
  —— 注意注释解释了为什么不用 GPIO2：**GPIO2 在这块板上是 LCD 的 D/C 线**，拿来点灯会花屏。
- `firmware/src/general.cpp`：`blink_led()` 里 `digitalWrite(LED, LED_ON)`，其中 `LED_ON` 由
  `LED_ACTIVE_LOW` 决定是 `LOW` 还是 `HIGH`。
- 背光：`ui_port.c` 里 `PIN_LCD_BL 21`，`lcd_init()` 里配成输出并拉高 —— 屏亮不亮是这根脚决定的。

**最小改动实验**：在 `serial_console.cpp` 的 `dispatch()` 里加一条命令 `LED <0|1>`，
调用 `digitalWrite(4, on ? LOW : HIGH)`。改完 `idf.py build flash monitor`，敲 `LED 1` / `LED 0`。

**验收**：能解释"为什么 `LED_ACTIVE_LOW=1` 时写 `LOW` 才是亮"，并能说出本板 GPIO2 为什么不能当灯用。

### 2.2 UART（第 2 天）

**概念**：UART 是两根线（TX/RX）的异步串口。**波特率** = 每秒多少位（这里 115200），
**8N1** = 8 数据位、无校验、1 停止位；双方必须一致，否则收到乱码。它没有"包"的概念，
所以要自己定"一行一条命令、`\r\n` 结尾"这样的协议。

**本工程用法**

- `firmware/src/serial_console.cpp`：`Serial.setRxBufferSize(4096)` **在** `Serial.begin(115200)` **之前**
  —— 默认 RX 环形缓冲只有 256 字节，主机连发命令会整行丢掉（`测试报告` 缺陷 #23：300 条 PING 只回 233 条）。
- 行缓冲：`handle_serial_console()` 逐字节读到 `g_line`，遇 `\n` 调 `dispatch(g_line)`；
  超过 111 字节直接 `ERR line too long`。
- 命令解析：`dispatch()` 先把命令名整体 `toupper()` 再 `strcmp()`，参数用 `strtok`。

**最小改动实验**：加一条 `ECHO <text>`，把参数原样回 `OK ECHO <text>`。注意 `strtok` 会把分隔符改成 `\0`，
所以"取剩下全部参数"的写法要留神。

**验收**：能读懂 `handle_serial_console()` 的每一行、知道缓冲为什么是 4096、并成功加上 `ECHO`。

### 2.3 SPI Master（第 3–4 天）

**概念**：SPI 是"一个主机、多个从机"的同步串行总线，四根线：

- `SCLK` 时钟（主机给）、`MOSI` 主机→从机、`MISO` 从机→主机、`CS` 片选（拉低选中某个从机）。
- **主从**：ESP32 永远是主机；屏和触摸都是从机，各自一根 `CS`，所以可以挂在**同一条**总线上。
- **CPOL/CPHA**：时钟空闲电平与采样边沿，合起来叫"模式 0/1/2/3"。对不上就收到错位数据。
- **DC 脚**（只在屏上）：ILI9341 用它区分"这一字节是命令还是像素数据"——不是 SPI 标准的一部分，
  是这块屏自己的规矩。

**本工程接线（两条独立的 SPI 总线，别混）**

| 用途 | ESP-IDF 总线 | 引脚 | 时钟 | 代码 |
| --- | --- | --- | --- | --- |
| LCD ILI9341 | `SPI3_HOST`（VSPI） | MISO 12 / MOSI 13 / SCLK 14 / CS 15 / **DC 2** / RST 无 / 背光 21 | 40 MHz | `ui_port.c` 的 `lcd_init()` |
| 触摸 XPT2046 | `SPI2_HOST`（HSPI） | MOSI 32 / MISO 39 / SCLK 25 / CS 33 / IRQ 36 | 2 MHz，模式 0 | `ui_port.c` 的 `touch_init()` |

为什么分两条：屏是"高频 + 大数据量"（320×240×2 字节一帧 ≈150 KB），触摸是"低频 + 3 字节一次"，
分总线避免互相拖慢，也省得两套 CS/时序挤在一起。

**怎么读代码（按这个顺序）**

1. `lcd_init()`：`spi_bus_initialize(SPI3_HOST, …)` → `esp_lcd_new_panel_io_spi()`（把 DC 脚告诉它）
   → `esp_lcd_new_panel_ili9341()` → `reset/init/invert_color/mirror/disp_on_off`。
2. `touch_init()`：`spi_bus_initialize(SPI2_HOST, …)` → `spi_bus_add_device()`（2 MHz、模式 0）
   → `lv_indev_create()` 并把 `touch_read_cb` 注册成"读回调"（阶段 7 会再来看）。
3. `touch_read_axis()`：一次 SPI 事务发 3 字节（命令 + 2 个空字节），`rx_buffer` 里第 2、3 字节就是 12 位坐标。

**最小改动实验**：`TOUCH` 命令（`serial_console.cpp` 的 `do_touch()`）会打印原始值与映射后的屏幕坐标。
按住屏上某点敲 `TOUCH`，看 `raw=… screen=…`；再换一个角，观察原始值怎么变
（会看到"X 和 Y 是反的"——触摸屏装的方向跟屏不一样，这就是阶段 7.3 校准要解决的事）。

**验收**：能说清 DC 脚的作用、两条总线的引脚表、以及为什么"未触摸时原始值贴在 0 或 4095 两端"
（代码里用 `TOUCH_RAW_VALID_MIN/MAX` 120/3975 判断是否真的按下，因为这块板的触摸中断脚 PENIRQ 没引到排针）。

### 2.4 NVS + 定时器（第 5 天）

**概念**：**NVS** 是 IDF 提供的"键值存储"，落在 flash 的 `nvs` 分区，掉电不丢，适合存校准值、
Wi-Fi 配置这类小数据。**定时器**有三类，别混：

| 时间来源 | 精度/场景 | 本工程用例 |
| --- | --- | --- |
| `millis()`（Arduino） | 1 ms，够用就好 | 所有攻击模块的节拍（`tim_step()` 里 `now - s_last_tick < kBeaconMs`） |
| FreeRTOS 软件定时器 `xTimerCreate` | 有独立服务任务，回调不能阻塞 | `ui.c` 的 `s_build_guard`：列表构建超过 3 s 就重启，把"死机"降级成"重启" |
| `esp_timer` | 微秒级硬件定时器 | **本工程没有直接调用**；它由 `esp_lvgl_port` 内部使用（LVGL 心跳） |

**本工程用法（NVS）**

- `firmware/src/storage.cpp`：命名空间 `"wui"`、键 `"calib"`，把整个 `wui_calib_t` 结构体当一个 blob 存。
  `nvs_flash_init()` 返回 `ESP_ERR_NVS_NO_FREE_PAGES` 或 `NEW_VERSION_FOUND` 时先 `nvs_flash_erase()` 再初始化
  —— 这是标准写法，换固件版本后 NVS 布局变化就靠它自愈。
- UI 组件不认识 NVS：它只拿到 `wireless_ui_storage_ops_t`（load/save/clear 三个函数指针），
  由 `main.cpp` 把 `app_storage_*` 注入进去。这是"组件解耦"的样板。

**最小改动实验**：在 `storage.cpp` 里加一个 `app_storage_save_uint/get_uint`（换一个键名），
在 `dispatch()` 里加 `NVSET <n>` / `NVGET`，重启板子验证值还在。

**验收**：能读懂 `wui_calib_load()/wui_calib_save()/wui_calib_clear()` 的路径，并说出
`wui_calib_t` 里 `axis_x/axis_y/off_x/gain_x/off_y/gain_y/inset` 各自在校准数学里扮演什么角色
（阶段 7.3 会算一遍）。

### 2.5 附：本工程**没用到**但常见的 ESP32 外设（只做对照，不进实操）

| 外设 | 是什么 | 什么场景用 | 本工程为何没用 |
| --- | --- | --- | --- |
| I2C | 两根线（SDA/SCL）的总线，常接传感器、EEPROM、OLED | 温湿度、气压、RTC、小 OLED | 这块板没有 I2C 外设 |
| LEDC / PWM | 硬件 PWM 发生器，可调占空比与频率 | 调光、调色、蜂鸣器、舵机 | LED 只需要开/关，背光也只需要亮/灭 |
| ADC | 模数转换，读模拟电压（0–3.3V → 数值） | 电池电压、电位器、光敏电阻 | 触摸是数字 SPI 读数，不走 ADC |
| I2S | 数字音频总线（也常被借去驱动 LED 灯带） | 麦克风/喇叭、WS2812 | 没有音频需求 |
| GPTimer | 通用硬件定时器（比 `esp_timer` 更底层，可接引脚输出） | 精确定时、输入捕获、编码器 | 攻击节拍用 `millis()` 足够；LVGL 心跳由 `esp_lvgl_port` 用 `esp_timer` 做了 |

---

## 阶段 3：ESP32 系统基础（2 天）

**目标**：看懂"谁在什么时候跑"，能读串口日志里的任务/堆信息，知道为什么这个工程不敢在回调里干活。

**先补四个词**

| 词 | 人话 | 本工程实例 |
| --- | --- | --- |
| 任务（task）/ FreeRTOS | 一个"能独立跑的小线程"，有自己的栈；`xTaskCreate` 创建，优先级数字越大越优先 | `serial_console.cpp` 里的 `scan_task`（prio 2，阻塞式扫描，避免卡住主循环） |
| 队列（queue） | 任务之间传数据的管道，先进先出 | `main.cpp` 的 `s_ui_cmds`（深度 6、每条 48 字节）：LVGL 任务 → 主循环 |
| 回调（callback） | "你注册一个函数，事件发生时别人来调你" | Wi-Fi 混杂模式的 `sniffer()`（`deauth.cpp`，`IRAM_ATTR`） |
| 事件循环（event loop） | 驱动把"有事发生"打包成事件投递，你注册 handler | Arduino 层在内部用 `esp_event` 投递 Wi-Fi 事件；本工程的攻击逻辑**不依赖**事件循环，只在 `evil_twin.cpp` 里用 Arduino 的 `WiFi.softAP()` 封装 |

**本工程的"谁在跑"清单（这张表要背下来）**

| 执行体 | 优先级 | 干什么 | 绝对不要在这里做的事 |
| --- | --- | --- | --- |
| Arduino `loopTask`（`setup()`/`loop()`） | 默认 1（`CONFIG_ARDUINO_RUNNING_CORE=1`） | 串口解析、`attack_step()` 出队注入、UI 命令出队 | 不要长时间阻塞（扫描已经挪走了） |
| `scan_task` | 2 | `SCAN` 的阻塞扫描，扫完置标志 | 不要在这里注入帧 |
| `taskLVGL`（`esp_lvgl_port` 创建） | 4 | `lv_timer_handler()`，刷屏、跑 LVGL 定时器 | 不要直接碰攻击状态（所以按钮只发协议行） |
| Wi-Fi 任务的 `sniffer()` 回调 | 驱动内部（`IRAM_ATTR`） | 只做判断 + 入队（`queue_deauth()`），不打印不发帧 | 不要 `Serial.print`、不要 `esp_wifi_80211_tx` |
| FreeRTOS 定时器服务 | 高 | `s_build_guard` 超时重启 | 回调里不能阻塞 |

**日志阅读**：IDF 的日志格式是 `I (12345) TAG: 内容`（`I/W/E` = 信息/警告/错误，括号里是上电以来的毫秒数）。
本工程 `CONFIG_LOG_DEFAULT_LEVEL_WARN=y`，所以默认看不到 `I` 级日志——串口流要留给协议行。
调试时用 `definitions.h` 里的 `DEBUG_PRINT*` 宏（默认编译为空），或者临时把日志级别调回 INFO。

**动手/验收**：用 `STATUS` 里的 `heap=` 观察一次 `SCAN` 前后的堆变化（应在几百字节内）；
用 `PING` 的往返时间判断主循环有没有被阻塞（`tests` 里有 p50/p95 断言，正常 p95 < 5 ms）。

---

## 阶段 4：WiFi 驱动模型（3 天）

**目标**：理解"不连接任何 AP 的 STA 也能发帧"这件事在驱动层意味着什么，以及为什么注入有速率上限。

**四件事必须搞清楚**

1. **STA 生命周期**：`WiFi.mode(WIFI_MODE_STA); WiFi.disconnect();`（`main.cpp:setup()`）——
   板子**永远不关联**任何 AP。好处：不会自己发 beacon、不占 AP 的 station 表；代价：见第 3 点。
2. **信道是手工钉的**：`esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE)`。
   而 12/13 信道与 5 GHz 需要先设**国家码**，否则 `set_channel` 直接返回 258。
   这套逻辑在 `deauth.cpp` 的 `apply_country()` / `apply_band_mode()`：1–11 → `"01"`（世界通用），
   12–13 → `"CN"`，≥15 → `"CN"` + 5 GHz 信道掩码，C5 另设 `WIFI_BAND_MODE_AUTO`。
3. **`esp_wifi_80211_tx(ifx, buf, len, en_sys_seq)`**：ESP-IDF 的非公开 API（声明在 `esp_wifi.h`，
   实现在闭源 `libnet80211.a`）。四个参数：接口（本工程恒为 `WIFI_IF_STA`）、整帧字节、长度、是否由系统填序号。
   本工程第四参数一律 `false`（自己写死 `0xF0FF`）。
   - 它**只能在 STA 模式**下工作：AP 模式下返回 `ESP_OK` 但帧不上空口（esp-idf issue #6368）。
   - 它**不保证成功**：返回 `ESP_ERR_NO_MEM`（也就是日志里的 `0x101`）表示"我们自己的发送缓存池空了"。
4. **缓存池与速率**：驱动里有 32 个短缓冲（`mgmt_sbuf_num`，改 Kconfig 无效）。伪造 TA 的单播帧
   拿不到属于本机的 ACK，硬件要重传到上限才释放缓存 → 池子在 ~32 帧/s 的排水速度上平衡。
   本工程因此把单播统一压到 **20 帧/s**（`tx_guard.cpp` 的 `TX_GUARD_UNICAST_GAP_MS = 45`），
   广播帧（克隆 beacon）不等 ACK、立刻回收，所以 50 帧/s 也没事。

**动手**：用 `lab/pool_limit.py` 复现一次 0x101 边界（它会让板子重启，属于设计行为）：

```
python lab/pool_limit.py --port COM5 --bssid <你自家AP的BSSID> --module sae --gap 20
```

**验收**：用自己的话解释三件事：①为什么"没连 AP"的 STA 能发任意帧；②为什么伪造 TA 的单播会占满缓存；
③为什么广播帧不受同样限制。答不出来就回去读 `tx_guard.h` 的注释（那里写了完整的实测曲线）。

---

## 阶段 5：802.11 帧格式（3 天）

**目标**：能徒手写出本工程用到的每一种帧的前 30 个字节，并用串口的 `*TEST` 命令自证。

**先补概念**：一帧 802.11 = **MAC 头（24 字节起）+ 帧体 + FCS（4 字节校验）**。
FCS 通常由硬件加，所以你在串口里看到的构造长度比抓包长度少 4（例：EAPOL 构造 36 / 抓包 40）。

MAC 头 24 字节（本工程所有帧都从这几个偏移开始）：

| 偏移 | 长度 | 字段 | 备注 |
| --- | --- | --- | --- |
| 0 | 2 | Frame Control | 高 2 位=类型（0 管理/1 控制/2 数据），接着 4 位=子类型，再是 ToDS/FromDS 等标志 |
| 2 | 2 | Duration | **驱动会重算**，写什么都没用（见坑表） |
| 4 | 6 | Addr1 | 接收方（RA/DA） |
| 10 | 6 | Addr2 | 发送方（TA/SA） |
| 16 | 6 | Addr3 | BSSID 或 SA（由 ToDS/FromDS 决定） |
| 22 | 2 | Sequence Control | 本工程多处写死 `0xF0FF` |

**反学法（推荐顺序）**

1. `DEAUTH` 最简单：`build_deauth_ex()` 只有 26 字节 → 看 `DELBATEST`（30 字节，管理动作帧带类别/动作）
   → `BATEST`（ADDBA 33 字节 / BAR 20 字节，控制帧没有 Addr3）→ `EAPOLTEST`（数据帧 + LLC/SNAP）
   → `BTMTEST`（管理动作帧 + 元素）→ `TIMTEST`（beacon + 元素）。
2. 每次先看串口打印的 `len=` 和 `hex=`，**手算**每个字段的偏移，再与《攻击原理》对应节的帧图核对。
3. 元素（IE）的通用结构是 `id(1) + len(1) + body(len)`，`ie_util.cpp` 的 `ie_find()` 就是按这个走的。

**动手/验收**：在纸上写出 26 字节 deauth 的每个字节（含 FC、三个地址、序号、reason），
然后用 `DEAUTH 0 7` 发出去、用 `lab/tim_air.py` 或 C5 抓包确认空口上的字节与纸上一致
（注意 Duration 会被驱动改写，这一项允许不一致）。

---

## 阶段 6：攻击模块精读（5 天）

**目标**：每个模块都能说出"入口函数 → 组帧 → 学习（嗅探）→ 发射节拍 → 成功判据计数器"。

**阅读顺序（越靠前越简单）**

| 天 | 模块 | 阅读文件顺序 | 一句话机制 | 成功判据（`STATUS`） |
| --- | --- | --- | --- | --- |
| 1 | Auth/Assoc 洪泛 | `authflood.cpp`（`build_auth` → `build_assoc` → `authflood_step` → `authflood_on_rx`） | 每个随机 MAC 先认证再关联，消耗 AP 的 station 表 | `aff` 涨、`afids` 涨、`afst=0`（被接受）/`17`（表满） |
| 2 | SAE Commit 洪泛 | `sae.cpp`（`build_commit` → `store_token` → `sae_classify` → `sae_step`） | 每个 commit 让 WPA3 AP 做一次 ECC 标量乘 | `saef`、`saec`、`saeresp`、`saecode`（76=要 token） |
| 3 | EAPOL | `eapol.cpp`（`build_eapol` → `eapol_step` → `eapol_on_rx`） | 伪造成 STA 发 Start/Logoff，搅 802.1X 端口状态机 | `eaprxreq>0` 才算真踢动（本工程对 PSK AP 实测为 0） |
| 3 | BTM 强制漫游 | `btm.cpp`（`build_btm_request` → `learn_capabilities` → `btm_step`） | 伪造 AP 劝客户端漫游/离网 | `btmc`（支持 11v 的 STA 数）、`btmresp`（有应答才算端到端） |
| 4 | PM 位欺骗 | `qosnull.cpp`（`build_qos_null` → `qosnull_step` → `qosnull_on_rx` → `qosnull_release`） | 伪造 STA 的"我睡了"（单播 QoS Null + PM=1），让 AP 把下行缓存起来 | `qnf`、`qn1/qn0`（PM=1/PM=0）、`qndl`（发向受害者的下行帧） |
| 4 | CSA | `csa.cpp`（`build_csa_action` → `build_beacon` → `send_csa_round` → `csa_step`） | 通告换信道，然后在新信道顶克隆 beacon | `csaf`、`csa=announce/hold`、`csaauth/csarej` |
| 5 | DELBA / BA | `delba.cpp`（`build_delba` → `send_from_ap/sta/group` → 然后 `build_addba_req` → `build_bar` → `ba_tx`） | 拆聚合 / 种重排窗口 | `delbaf`、`delbat`、`babar`、`bassn` |
| 5 | Deauth | `deauth.cpp`（`build_deauth_ex` → `queue_deauth` → `drain_tx_queue` → `attack_step`） | 老本行 + 注入队列 + 盲目兜底 | `txok/txerr/rev/blind/eliminated` |

**怎么读一个模块（模板）**

1. 先读 `.h` 的注释（每个模块的头文件顶部都写了"为什么这样设计"）。
2. 找 `build_*()`：这是组帧，和第 5 阶段的帧表对照。
3. 找 `*_step()`：这是节拍与状态机（`millis()` 比较 + 游标轮转）。
4. 找 `*_on_rx()`：这是"学习"（能力、AID、TID），注意它由 `deauth.cpp` 的 `sniffer()` 分发。
5. 最后回到 `serial_console.cpp` 的 `do_*()`：参数校验与 `OK/ERR` 输出，以及 `STATUS` 里那串字段。

**索引**：`firmware/README.md` 的能力矩阵是"功能 ↔ 命令 ↔ 验证状态"，与《攻击原理》的节号一一对应。
**验收**：随便点一个模块，能在 3 分钟内讲清它的帧、节拍、学习来源、以及"什么情况下它无效"。

---

## 阶段 7：LVGL 图形界面（4 天，教具就是 `components/wireless_ui/`）

> 这一阶段全部代码在 `firmware/components/wireless_ui/`（`ui.c` 界面与对象树、`ui_port.c` 硬件移植、
> `calib.c` 校准数学），并且**只在 ESP32（CYD）上存在**：Kconfig 里 `depends on IDF_TARGET_ESP32`。

### 7.1 LVGL 心智模型（第 1 天）

LVGL 是个"画控件的库"，它自己不碰硬件。要让它在你的屏上跑起来，必须凑齐**四件套**：

| 四件套 | 人话 | 本工程谁提供 |
| --- | --- | --- |
| 显示驱动（flush 回调） | LVGL 画好一小块画面后，调你注册的函数把这块像素刷进屏。 | `esp_lvgl_port` 的 `lvgl_port_add_disp()`，底层是 `esp_lcd` + ILI9341。缓冲 = `320 × 20` 行、RGB565、单缓冲（`ui_port.c` 的 `disp_cfg`） |
| 输入设备驱动 | LVGL 需要一个"读指针位置"的回调，才能知道手指在哪。 | `ui_port.c` 的 `touch_init()`：`lv_indev_create()` + `lv_indev_set_read_cb(touch_read_cb)`，读的是 XPT2046（SPI2） |
| `lv_tick` 心跳 | LVGL 靠一个"毫秒计数器"算动画和超时。必须有人定期加它。 | `esp_lvgl_port` 内部：`esp_timer_start_periodic(...)` → 回调里 `lv_tick_inc(timer_period_ms)` |
| task handler | LVGL 不是中断驱动的，它要求你**周期性**调 `lv_timer_handler()` 处理事件/重绘。 | `esp_lvgl_port` 建了一个 `taskLVGL` 任务，循环里调 `lv_timer_handler()` |

**对号入座**：`ui_port.c:wireless_ui_port_init()` 就这四步——`lcd_init()`（硬件）→ `lvgl_port_init()`（task + tick）
→ `lvgl_port_add_disp()`（flush）→ `touch_init()`（输入）。缺任何一步，屏要么黑、要么不响应。

**宏关掉后哪几行先消失**（一定要自己验证一次）：

- 组件 CMakeLists 的 `if(CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT)` 变成 else 分支 → 三个 .c **不参与编译**；
- `ui.c` / `ui_port.c` / `calib.c` 文件里的 `#if CONFIG_...` 把整个文件体变空；
- `main.cpp` 里从 `#include "wireless_ui.h"` 到 `ui_commands_drain()`/`wireless_ui_tick()` 的那几段消失；
- `sdkconfig.h` 里没有 `CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT`，链接期自然没有 LVGL 符号。

**验收**：画出"手指按下 → XPT2046 → `touch_read_cb` → LVGL 事件 → 按钮回调 → `emit("DEAUTH 3 7")`
→ 命令队列 → `dispatch()`"这条链路。

### 7.2 对象树与控件（第 2 天）

**概念**：LVGL 里一切都是对象（`lv_obj_t*`），对象组成一棵树，父对象隐藏则子对象一起隐藏。
`label` 是文字、`button` 是可点的容器（里面通常放一个 label）、`list` 是带滚动的列表。

**本工程的对象树**（`ui.c` 的 `build_main_ui()`）

```
lv_screen_active()
├── title label            "Wireless Attack"
├── s_status label         "idle d=0 p=0 nets=0 e=0"（顶栏状态）
├── s_screens[SCR_MENU]    ← 一级菜单（第 1 行 [Deauth][Probe][CSA] …）
├── s_screens[SCR_DEAUTH]  ← 二级：One/All/Only/Except
├── s_screens[SCR_MODE]    ← 三级：Scan/Targets/Start/Stop/Reason
├── s_screens[SCR_CSA] / [SCR_DELBA] / [SCR_BA] / [SCR_PROBE] / [SCR_EVIL]
├── s_screens[SCR_FRAME]   ← 五个帧级模块共用的那一页（BTM/EAPOL/SAE/AUTH/QoSNull）
├── s_popup（lv_layer_top 上的模态目标选择弹窗）
├── s_log label
└── s_reason_popup（reason 选择弹窗）
```

切页就是把所有 screen 加 `LV_OBJ_FLAG_HIDDEN`、把目标那个去掉（`show_screen()`）。**没有删除/重建**，
所以切页是瞬时的；代价是对象常驻内存（这也是 80 KB 池的由来）。

工具函数只有三个：`make_screen()` / `make_row()` / `make_button_h()`。看懂这三个，整个 `ui.c` 就好读了。

**动手**：加一个新页面 `SCR_ABOUT`：一个 label 写"hello" + 一个 Back 按钮，菜单里加一个入口。
**验收**：编译烧录后能在屏上看到它，`UISCREEN about` 也能切过去（记得在 `show_by_name`/`screen_name` 里登记）。

### 7.3 输入与坐标系（第 3 天）

**为什么需要校准**：XPT2046 报的是它自己的 12 位原始值（0–4095），而且**轴线与屏不一致**
（这块板 `swap_xy`），不同批次的屏还有几毫米的偏移。所以要把"原始值 → 屏幕像素"做一次**仿射映射**：

```
screen_x = (raw[axis_x] - off_x) * gain_x + inset
screen_y = (raw[axis_y] - off_y) * gain_y + inset
```

四个角点采样后解出 `axis_*`（哪根原始轴对应屏幕哪一维）、`off_*`（原始值起点）、`gain_*`（比例）。
本工程的实现：`calib.c` 存/取 `wui_calib_t`，`ui.c` 的 `calib_start()` 走"左上→右上→右下→左下"四步，
判据是"800 ms 静置后连续 3 次采样稳定（±80 原始单位）"，采完 `wui_calib_save()` 写 NVS。

**为什么必须存 NVS**：换电池/断电后不希望用户再点四角。
**为什么换分辨率要重校准**：`gain_*` 与 `inset` 都跟屏幕尺寸绑定（`WUI_CALIB_INSET` 是边距）。

**动手**：`TOUCH` 命令打印 `raw=(…) screen=(…)`。按住左上角采一组原始值，用上面公式手算 screen 坐标，
与命令打印的对比（误差几个像素内即正确）。
**验收**：能解释"为什么未触摸时原始值贴在 0/4095"、"为什么要 `TOUCH_RAW_VALID_MIN/MAX`"、
"为什么这块板没有用中断脚判断按下"（PENIRQ 未引到排针）。

### 7.4 字库与模态弹窗（第 4 天）

**为什么中文不能直接用 LVGL 内置字体**：LVGL 自带 Montserrat 只有拉丁字母。要用中文得把"字符集"
栅格化成 C 数组（每个字一行位图），这很占 flash：内置 CJK 子集（约千字）在 16px/4bpp 下要 **191 KB**。
本工程只要"能看懂 SSID"，于是做了**自己的子集**：几百个高频字 + SSID 领域词，约 60 KB。

**生成原理**（`firmware/tools/gen_cjk_font.py`）：从 `components/wireless_ui/fonts/cjk_charset.txt`
拿字符集 → 调 Node 的 `lv_font_conv` 把 Windows 自带的 Noto Sans SC 栅格化 → 输出
`fonts/lv_font_ui_cjk.c`。Kconfig 的 `WIRELESS_UI_CJK_CUSTOM` 决定用它还是回退到内置子集。

**模态弹窗**（Targets）：`lv_layer_top()` 上建一张卡片，`targets_open()` 打开时**才**建行
（`rebuild_popup_list()`），每行是"一个容器 + 一个 label"。三个关键细节：

1. 行数上限 `LIST_ROWS = 30`，且建行前用 `lv_mem_monitor()` 看剩余内存，< 6 KB 就停（标题显示 `shown/total`）；
2. 建行期间挂一个 3 秒的 FreeRTOS 定时器 `s_build_guard`，没建完就 `esp_restart()`——把"LVGL 断言死循环"
   降级成"重启"（这是缺陷 #35 的修复）；
3. 池子大小 `CONFIG_LV_MEM_SIZE_KILOBYTES=80`：64 KB 时第 25 行左右就会 `lv_malloc` 失败 → 死机。

**动手**：给菜单加一个中文项（例如「关于」），自己跑一次 `python tools/gen_cjk_font.py`（需 Node + lv_font_conv），
确认屏上中文显示正常。
**验收**：能说清"为什么内置换字库会大 3 倍"、"为什么弹窗要按需建行"、"池子耗尽时固件会发生什么"。

---

## 阶段 8：界面与上位机（2 天）

**目标**：彻底理解"屏和 GUI 只是发协议行"这个设计，并能自己给 GUI 加一页。

**设计事实**

- LVGL 侧：按钮回调只调 `emit("DEAUTH 3 7")`；`emit()` → `wireless_ui_command_cb` → `ui_command_enqueue()`
  → 因为它在 LVGL 任务里执行，**必须入队**，由主循环的 `ui_commands_drain()` 调
  `wireless_console_execute()` → `dispatch()`。
- 上位机侧：`gui/protocol.py` 是**纯函数**（`classify/parse_net/parse_status/parse_caps`，无 Tk 无 IO），
  `gui/main.py` 只负责"控件 ↔ 协议行"和"协议行 ↔ 界面状态"。
- 两边共享的唯一契约是 `firmware/README.md §4` 的行格式（`OK/ERR/INFO/NET/STATUS/…`）与
  `STATUS` 的 `key=value` 字段名。**改字段名会同时打坏 GUI 和用例**。

**动手**：`gui/main.py` 里给某页加一个按钮，只发一条已有命令（例如 `STATUS`），并让日志显示在底栏。
**验收**：能说清"为什么 GUI 里没有一行业务逻辑"、"`protocol.py` 为什么不 import tkinter"、
以及"加一条新命令要同步哪四处"（`print_help()`、`firmware/README §4`、GUI 页面、`tests/`）。

---

## 阶段 9：横向机制（2 天）

**1) 整流器 `tx_guard.cpp`（半天）**

- 只做三件事：识别 RA 是不是组播（组播不等 ACK，放行）；单播强制 45 ms 间隔；第一次 `ESP_ERR_NO_MEM`
  就打印 `FATAL tx 0x101 ... -> restart` 并 `esp_restart()`。
- 为什么"重启"是恢复手段：CTS 那组实验里，池子耗尽后连 `esp_wifi_set_channel()` 都会卡在锁上（`测试报告 §4.3.3`）。
- 谁用它、谁故意不用它：五个新模块 + CSA 用；DELBA/BA/deauth 用自己的封装（长跑 19–25 帧/s，在排水速率以下）；
  `BARSEQ` 这类"就是要打空池子"的诊断探针**故意**在守卫外。

**2) 测试框架（半天）**：`firmware/tests/test_wireless_attack.py`（50 个用例，unittest）。
结构：纯协议解析用例（无硬件也能跑）+ 硬件功能用例（`SkipTest` 保护）+ 性能/稳定性用例。
判据几乎都基于 `STATUS` 的 `key=value`，所以**加计数器比加断言更重要**（先能观测，再谈验证）。

**3) lab 空口验证（1 天）**：这些脚本都要人明确执行，不在自动化里：

| 脚本 | 干什么 | 需要什么 |
| --- | --- | --- |
| `lab/cap_pipe.py` + `lab/cap_frames.py` | 读 C5 的抓包管道，按模块解码帧字段 | C5 抓包固件 + 管道 |
| `lab/air_check.py` | 逐模块"起-抓-停" | 同上 |
| `lab/pool_limit.py` | 复现 0x101 边界 | 攻击板 |
| `lab/soak.py` | 逐模块长跑，判据 `txgerr=0` 且无 `FATAL` | 攻击板 |
| `lab/btm_sta.py` | 端到端（真实 11v STA） | 三块板（AP+STA+攻击） |

**验收**：跑通 `python -m unittest discover -s tests`；给某个模块加一个计数器并在用例里断言它；
用 `lab/cap_frames.py` 亲手核实一次空口字节。

---

# 第 2 章 工程架构分析

## 2.1 模块依赖图（谁调谁）

```
                        main.cpp
        ┌──────────────────┼───────────────────────────┐
        │                  │                           │
   serial_console.cpp   evil_twin.cpp            wireless_ui（宏控）
        │                  │  └── 调 deauth 的 attack_deauth_single()
        │                  │
        ├─ deauth.cpp ─────┼── 被所有攻击模块调用：attack_sniffer_enable()
        │   │              │   attack_stop() / attack_step() / build_* 工具
        │   └─ sniffer()   │──→ hexcap.cpp（过滤匹配时复制原始帧到 8 槽队列）
        │        └── 分发 ─┼─→ csa_on_rx / delba_on_rx / btm_on_rx
        │                  │   tim_on_rx / eapol_on_rx / sae_on_rx / authflood_on_rx
        │
        ├─ csa.cpp        ── tx_guard_send()
        ├─ delba.cpp      ── 自己的 tx()（长跑在排水速率以下，故意不接守卫）
        ├─ btm.cpp        ── tx_guard_send() + ie_util
        ├─ eapol.cpp      ── tx_guard_send()
        ├─ qosnull.cpp    ── tx_guard_send()
        ├─ sae.cpp        ── tx_guard_send() + ie_util
        └─ authflood.cpp  ── tx_guard_send() + ie_util + sae_classify()

   storage.cpp ── main.cpp 注入给 UI 组件（load/save/clear 三个函数指针）
   general.cpp ── blink_led()（由 evil_twin.cpp 的两处 BLINK_LED() 宏调用）
```

**共享底座被谁依赖（精确清单）**

| 底座 | 提供 | 使用者 |
| --- | --- | --- |
| `deauth.cpp` | `attack_sniffer_enable()`、`attack_stop()`、`attack_step()`、`attack_rx_*`、`find_ap`、注入队列、`sniffer()` | 所有攻击模块；`sniffer()` 也把匹配的原始帧交给 `hexcap.cpp`，回调只做筛选与入队 |
| `hexcap.cpp` | 8 槽 / 512 字节原始帧队列，type/subtype/TID/TA/RA 过滤，命中与溢出计数 | `sniffer()` 入队；`serial_console.cpp` 通过 `HEXD` / `HEXLOG` / `HEXSTOP` 管理并在主循环打印 |
| `tx_guard.cpp` | `tx_guard_send()` + 三个计数 | `csa`、`btm`、`eapol`、`qosnull`、`sae`、`authflood` |
| `ie_util.cpp` | `ie_find` / `rsn_has_akm_sae` / `rsn_has_akm_psk` / `rsn_mfpr_required` / `extcap_has_bss_transition` | `authflood`、`sae`、`btm`（`csa` 自己写了一份等价的 IE 遍历；`rsn_mfpr_required` 目前无人调用） |

## 2.2 分层拆解（每层只干一件事）

| 层 | 文件 | 职责 | 边界（不许做什么） |
| --- | --- | --- | --- |
| 协议层 | `serial_console.cpp` | 行缓冲、命令分发、参数校验、所有 `OK/ERR/INFO/STATUS` 输出、`scan_task` | 不组帧、不发帧 |
| 组帧/解析层 | 各模块的 `build_*()` + `ie_util.cpp` | 把参数变成字节；从字节里找元素 | 不决定"打谁、打多快" |
| 发射守卫层 | `tx_guard.cpp` | 单播节流、`0x101` 处理、计数 | 不组帧、不管业务 |
| 攻击模块层 | 9 个 `.cpp` | 学习（嗅探）+ 状态机 + 节拍 | 不 `Serial.print`（只有 `authflood` 升级时打一行 `INFO`，是唯一例外） |
| 界面层（可选） | `components/wireless_ui/` | 把点击变成协议行；把固件状态画出来 | **不含任何攻击逻辑**，只调 `wireless_console_execute()` |
| 驱动层 | ESP-IDF / Arduino | `esp_wifi_80211_tx`、混杂模式、SPI、NVS、FreeRTOS | —— |

"屏/上位机只是发协议行、攻击逻辑只有一份"的落地方式：

- UI → 固件：按钮回调 `emit(line)` → 回调指针 → 队列 → `wireless_console_execute(line)` → 同一个 `dispatch()`。
- 固件 → UI：只调 `wireless_ui_scan_begin/add_network/scan_end/status/log` 置**标志**，
  由主循环里的 `wireless_ui_tick()` 加锁后应用（**不允许跨任务直接调 LVGL**，因为 LVGL 不是线程安全的）。
- GUI → 固件：串口写同一行；固件 → GUI：解析同一批输出行。

## 2.3 三条非常规路径（以及为什么必须这样）

### 2.3.1 覆盖 `ieee80211_raw_frame_sanity_check()` + `-Wl,-z,muldefs`

**先补链接器基础**（只讲够用的部分）：

- 编译后每个 `.o`/`.a` 里有**符号**（函数名、变量名）。链接时同名**强符号**出现两次会报
  `multiple definition`。
- 静态库（`.a`）里的符号是**按需抽取**的：只有当某个未定义符号恰好在库里时才把那一个 `.o` 拉进来。
- `-Wl,-z,muldefs` 告诉链接器："重复定义不要报错，用先到的那个"。

**本工程做了什么**：`deauth.cpp:22` 定义了一个同名函数 `ieee80211_raw_frame_sanity_check()`，
返回 0（"这帧是合法的"）。Wi-Fi 闭源库 `libnet80211.a` 里也有一份，它原本会拒绝"不合规"的裸帧。
靠 `-Wl,-z,muldefs` 让两份共存、让我们这份生效，`esp_wifi_80211_tx()` 才会接受任意帧。

**为什么标注"私有做法"**：它依赖闭源库里的**内部符号名**与调用位置。升级 IDF 后这个符号可能改名、
可能被内联、也可能改成别的校验逻辑，届时注入会静默失效（表现为"帧发不出去但返回 ESP_OK"）。
所以升级 IDF 后第一件事是跑 `CTRLTEST`/`BATEST` 确认注入还活着。

### 2.3.2 首个 `0x101` → `esp_restart()`

`esp_wifi_80211_tx()` 返回 `ESP_ERR_NO_MEM`（日志里 `FATAL tx 0x101`）意味着**我们自己的**短缓冲池空了。
为什么不退避重试？两条实测原因：

1. 池子不是"等一会儿就好"：CTS 那组实验里，耗尽后静置 10 s 仍是 `0x101`，连 `esp_wifi_set_channel()`
   都卡在锁上（只能硬复位）；
2. 一旦开始拒发，后续每一帧都会被拒，攻击状态与实际空口完全脱节——"假装还在跑"比诚实重启更糟。

所以策略是：**打一行 FATAL + `Serial.flush()` + `delay(20)` 再 `esp_restart()`**。
那 20 ms 是给 UART 把最后一行送出去的时间（`esp_restart()` 会丢掉 TX FIFO）。

### 2.3.3 控制帧与数据帧的发射路径不同

两者共用**同一个 32 个短缓冲池**，但**释放时机不同**，这决定了节拍：

| 帧类型 | 是否需要等 ACK | 缓冲何时回收 | 实测结果 |
| --- | --- | --- | --- |
| 广播帧（beacon / broadcast deauth） | 不等 | 立刻 | 克隆 beacon 50 帧/s 跑 3000 帧零拒收 |
| 单播控制帧（RTS / CF-End / BAR） | 多数不等 | 很快 | 节拍 30 ms 时 100 帧零失败（`BARSEQ 100 30`） |
| **CTS** | —— | **永不回收** | 30/200/500 ms 节拍都是 32 帧封顶，静置不恢复 |
| 单播管理/数据帧（伪造 TA） | 要等"属于本机"的 ACK，但 TA 是假的 → 等不到 → 重传到上限 | 慢 | 20 帧/s 稳态；50 帧/s 第 63 帧就 0x101 |

所以"控制帧能快发、数据帧必须慢发"不是偏好，是**池子回收速度**决定的。

## 2.4 构建系统

| 关注点 | 事实 | 位置 |
| --- | --- | --- |
| 工程级 CMake | 三个特殊设置见阶段 1 | `firmware/CMakeLists.txt` |
| 应用组件 | 15 个源文件 + `../include` + `REQUIRES arduino-esp32 wireless_ui nvs_flash` | `firmware/main/CMakeLists.txt` |
| 自研组件 | 宏开时编 `ui.c/ui_port.c/calib.c`（+可选字库），宏关时只 `INCLUDE_DIRS "include"` | `firmware/components/wireless_ui/CMakeLists.txt` |
| 组件依赖 | `REQUIRES lvgl esp_lvgl_port esp_lcd_ili9341`；`PRIV_REQUIRES esp_lcd driver esp_timer` | 同上 |
| 分区表 | 4 个分区，见阶段 0 的表 | `firmware/partitions.csv` |
| 双 target | ESP32：`build/` + `sdkconfig`（默认开 LVGL）；C5：`build_c5/` + `sdkconfig.c5`（Kconfig 决定不可能有 LVGL） | `firmware/sdkconfig.defaults` / `firmware/sdkconfig.c5` |
| C5 的 console | 默认 `CONFIG_ESP_CONSOLE_UART_DEFAULT=y`：命令从 **UART0** 进，USB 口只出日志。要从 USB 口收发命令得改成 `CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y`（`lab/rf_throughput/sdkconfig.c5` 就是这么改的） | 两个 sdkconfig |

---

# 第 3 章 库与 API 盘点

## A. WiFi / 协议线

| API | 使用位置 | 作用 | 为什么不能替代 / 注意 |
| --- | --- | --- | --- |
| `esp_wifi_80211_tx(ifx, buf, len, en_sys_seq)` | `tx_guard.cpp:40`、`deauth.cpp:349`（`tx_raw`）、`delba.cpp:162`（`tx`）、`deauth.cpp` 的 CTRLTEST | 把一整帧裸 802.11 直接交给 MAC 发出去 | 这是**唯一**能发任意帧的入口；但它只"交给驱动"，不保证上空气（AP 模式下静默失败，见 issue #6368）。用 `STATUS` 的 `txok/txerr` 与空口抓包双重确认 |
| `esp_wifi_get_tsf_time()` | **本工程未使用** | 读接口自己的 64 位 TSF（微秒时钟） | 它只能**读**不能**写**，所以不能用来伪造 beacon 的 timestamp —— 那个字段由 MAC 自己填（未关联时为 0），这就是 TSF 投毒失败的原因（坑表） |
| `esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE)` | 每个模块 `*_start()`；`attack_step()` 的信道跳变；`apply_country()` 之后 | 把电台钉到某个信道 | 12/13 与 5 GHz 必须先设国家码，否则返回 258；跳信道会打断当前收包 |
| 国家码 / 频段 | `deauth.cpp` 的 `apply_country()` / `apply_band_mode()` | 1–11 → `"01"`；12–13 → `"CN"`；≥15 → `CN` + 5G 掩码；C5 另设 `WIFI_BAND_MODE_AUTO` | 不做就没有 12/13 与 5 GHz；这套是**运行时**切的，不需要两套固件 |
| `esp_wifi_set_promiscuous*` + 两级过滤器 | `deauth.cpp:start_promiscuous()` | 开混杂模式收帧；第一级按"管理/控制/数据"过滤，第二级 `ctrl_filter` 决定具体哪些控制 subtype 上报 | 只设第一级会 `ctrl=0`（缺陷 #34）；本工程第二级设 `MASK_ALL` |
| `esp_wifi_register_80211_tx_cb()` | **本工程未使用**（曾经试过） | 注册"发送完成"回调 | 对注入帧一次都不回调，所以"这帧发出去没有"在应用层不可观测——所有速率结论都是"驱动接受了 N 帧" |
| `esp_wifi_init/start` | Arduino 的 `WiFi.mode()/WiFi.begin()` 内部；`evil_twin.cpp` 的 `WiFi.softAP()` | 初始化/启动 Wi-Fi 驱动与协议栈 | 本工程走 Arduino 封装，不直接调这两支；Evil Twin 是唯一会真的起 softAP 的地方 |

## B. 外设 / 驱动线（本工程实际用到的）

| 外设/API | 使用位置 | 作用 | 关键细节 |
| --- | --- | --- | --- |
| GPIO 输出（LED） | `definitions.h`（`LED 4`、`LED_ACTIVE_LOW 1`）、`general.cpp:blink_led()`、`main.cpp:setup()` | 板载 RGB LED 闪一下表示在跑 | 低电平点亮；不能用 GPIO2（LCD 的 D/C） |
| GPIO 输出（背光） | `ui_port.c`（`PIN_LCD_BL 21`，`lcd_init()` 里配输出并拉高） | 屏亮/灭 | 想在"省电"上做实验可以从这里切 |
| UART（控制台） | `serial_console.cpp:init_serial_console()` | 115200 8N1 命令行 | **`setRxBufferSize(4096)` 必须在 `begin()` 之前**；打开端口不要拉 DTR/RTS |
| SPI Master ×2 | `ui_port.c`：`lcd_init()`（SPI3，40 MHz，DC=GPIO2）、`touch_init()`（SPI2，2 MHz，模式 0） | 驱动 ILI9341 屏与 XPT2046 触摸 | 两套引脚表见阶段 2.3；触摸读一次是 3 字节事务 |
| NVS | `storage.cpp`（命名空间 `wui`、键 `calib`） | 掉电保持触摸校准 | `nvs_flash_init()` 要处理 `NO_FREE_PAGES`/`NEW_VERSION_FOUND`；UI 组件通过函数指针解耦 |
| `esp_timer` | **本工程无直接调用**；`components/wireless_ui/CMakeLists.txt` 里 `PRIV_REQUIRES esp_timer` | `esp_lvgl_port` 用它做 LVGL 心跳（`esp_timer_start_periodic` → `lv_tick_inc`） | 自己写代码时记住：回调在定时器任务里，不能阻塞 |
| FreeRTOS | `main.cpp`（`xQueueCreate`）、`serial_console.cpp`（`xTaskCreate scan_task`）、`ui.c`（`xTimerCreate` 保护建行） | 任务、队列、软件定时器 | 优先级/栈大小都在调用处写死，改之前先想清楚 |

---

# 常见坑速查表

| 现象 | 原因 | 现在还成立吗 | 出处 |
| --- | --- | --- | --- |
| 日志 `FATAL tx 0x101 (ESP_ERR_NO_MEM)`，随后重启 | 我们自己的 32 个短缓冲被占满（伪造 TA 的单播等不到 ACK） | ✅ 仍成立（守卫会先拦） | `tx_guard.cpp`、《攻击原理》附录 B |
| 紧循环发 32 帧就卡住 | 32 个缓存同时在途，不是"队列满" | ✅ 仍成立 | `测试报告 §4.3.3` |
| CTS 发 32 帧后永久卡死，静置也不恢复 | CTS 的缓存**不回收** | ✅ 仍成立（本工程不再用 CTS） | `测试报告 §4.3.3` |
| 写进帧里的 Duration 上不了空口 | 驱动/MAC 按"当前速率 + 预期应答"重算（单播恒 314 µs，广播 CF-End 0，RTS 990–1102 浮动） | ✅ 仍成立 → 所以 **NAV 模块已删除** | `测试报告 §4.3.1`、《攻击原理》附录 A |
| beacon 的 timestamp 写多少都变 0 | MAC 用接口自己的 TSF 覆盖（未关联时为 0） | ✅ 仍成立 → 所以 **TSF 投毒已删除** | `测试报告 §4.4.3` |
| 单播只能跑到 ~20 帧/s | 池子排水 ≈32 帧/s，20 帧/s 留余量 | ✅ 仍成立（**但 PM=1 的 QoS Null 例外：20 帧/s 几百帧就 `0x101`**） | `tests` + `lab/pool_limit.py`、`qosnull.cpp` |
| Action 帧的帧控制写成 `0x11D0` 却对不上 | 管理帧**没有** ToDS/FromDS 位：Action 的高字节只有 PM（`0x10`），`0x11` 是数据帧的 ToDS+PM | ✅ 仍成立（写用例时踩过） | `测试报告 §4.4.10` |
| PS-Poll 一帧都上不了空口 | **单播的 PS-Poll（控制子类型 10）本 MAC 不发送**：广播 RA 10/10、RA=BSSID 0/10 | ✅ 仍成立 → 所以 **PS-Poll 那一半已删除，改发单播 QoS Null** | `测试报告 §4.4.9`、《攻击原理》附录 A |
| 攻击计数器在涨，空口一帧没有 | `SCAN` 收尾时 `esp_wifi_set_channel()` 被拒，模块没检查返回值 | ⚠️ `QOSNULL` 已在回执里打 `chset=`/`WARN`，其它模块仍不报 | `qosnull.cpp`、`测试报告 §4.4.9` |
| 连发 300 条命令只回 233 条 | UART RX 环形缓冲默认 256 B，整行丢失 | ❌ 已修（`SERIAL_RX_BUFFER_SIZE=4096`） | 缺陷 #23 |
| `RXMIX ctrl=0 rts=0`，控制帧一帧都收不到 | 混杂模式**两级**过滤，第二级默认丢弃控制帧 | ❌ 已修（`MASK_ALL`） | 缺陷 #34 |
| 只看到 HE 客户端却抓不到它的上行帧 | ESP32 的 11n 射频解不出 Wi-Fi 6 PPDU | ✅ 仍成立（靠 `blind=` 兜底） | `AGENTS §11` |
| 点屏没反应/整机静默死机 | LVGL 池耗尽 → `lv_malloc` 失败 → 断言是空 `while(1)` | ⚠️ 缓解（80 KB 池 + 建行守卫 + 3 s 超时重启），但仍是硬限制 | 缺陷 #35 |
| 目标弹窗行数不到 30 | 池子紧张时建行提前收手 | ⚠️ 设计行为（标题会显示 `shown/total`） | `ui.c:ui_apply_pending` |
| 一连串口板子就复位/进下载模式 | CH340 的 DTR/RTS 被拉低 | ✅ 仍成立（脚本都 `dtr=False,rts=False`） | `gui/main.py`、`lab/*.py` |
| `STATUS` 读一行要 ~80 ms | 一行约 1.1 KB，115200 只有约 11 KB/s | ✅ 仍成立（用例阈值 120 ms） | `AGENTS §11` 第 9 条 |
| 12/13 或 5 GHz 设信道失败（返回 258） | 没先设国家码 | ✅ 仍成立 | `apply_country()` |
| C5 用 USB 口发命令没反应 | console 默认在 UART0，USB 只出日志 | ✅ 仍成立（改 `CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y`） | 第 2 章 2.4 |

---

## 附：本路线引用的真实落点（自查用）

- 入口与调度：`firmware/src/main.cpp:setup()` / `loop()`
- 协议层：`firmware/src/serial_console.cpp`（`dispatch` / `do_*` / `handle_serial_console` / `scan_task`）
- 守卫：`firmware/src/tx_guard.cpp`（`tx_guard_send`）
- 解析：`firmware/src/ie_util.cpp`（5 个函数）
- 攻击：`firmware/src/{deauth,csa,delba,ba,btm,rrm,eapol,qosnull,sae,authflood,evil_twin}.cpp`
- 界面：`firmware/components/wireless_ui/src/{ui.c,ui_port.c,calib.c}`、`include/wireless_ui.h`
- 字库：`firmware/tools/gen_cjk_font.py`、`components/wireless_ui/fonts/lv_font_ui_cjk.c`
- 存储：`firmware/src/storage.cpp`、`components/wireless_ui/src/calib.c`
- 构建：`firmware/CMakeLists.txt`、`firmware/main/CMakeLists.txt`、
  `firmware/components/wireless_ui/{CMakeLists.txt,Kconfig}`、`firmware/partitions.csv`、
  `firmware/sdkconfig.defaults`、`firmware/sdkconfig.c5`
- 测试与实验：`firmware/tests/test_wireless_attack.py`、`lab/*.py`、`lab/rf_throughput/`
- 提交（可对照阅读历史决策）：`5b0cf1d`（CSA）、`d70ebf7`（DELBA）、`1953421`（BA）、
  `860a321`（控制帧过滤器修复）、`92f7cb2`（LVGL 池死机修复）、`04efdcb`（删除 NAV）
