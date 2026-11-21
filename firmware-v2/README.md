# firmware-v2

按分层重写的 ESP32 无线测试固件工程。当前完成屏幕与串口的最小闭环，攻击模块尚未实现。

## 分层

```
L1 客户端     无线界面（可选）
L2 传输       transport：上层接口插件 + 命令队列 + 回执路由 + 事件扇出
L3 总线       wbus：对象注册表、参数校验、事件；services：系统级对象
L3.5 目标     wtarget：MAC → 句柄的设备登记表
L4 攻击       attacks：每种攻击一个目录（策略、节拍、计数、对象声明）
L4.5 编解码   wifi_frame：帧构造与 IE 解析（纯 C，可在 PC 上测）
L5 驱动       hal_wifi：注入、混杂接收、信道、扫描、SoftAP、诊断
```

依赖只能向下。各组件的 `CMakeLists.txt` 用 `REQUIRES` 白名单在编译期拦截越层 include：
`attacks` 里出现 `esp_wifi.h` 编译失败，`wbus` 里出现 Arduino 也编译失败。

## 组件作用

| 组件 | 作用 |
| --- | --- |
| `hal_wifi` | 收发与射频：裸帧注入与节流、混杂接收与订阅、信道与国家码、扫描、SoftAP、诊断探针 |
| `wifi_frame` | 802.11 帧构造、IE 解析 |
| `wbus` | 对象注册表、参数策略、回执路由、事件发布订阅 |
| `services` | 扫描、状态、监听、目标 STA、诊断等系统对象 |
| `wtarget` | 目标设备登记表（BSSID / STA MAC / 信道） |
| `attacks` | 各类无线攻击的策略与计数 |
| `transport` | 上层接口插件框架（串口 / 屏幕 / BLE / 网络），字节与总线调用的翻译 |
| `platform` | 板级能力：控制台 UART、LCD 与触摸、NVS 存储、状态灯 |
| `wireless_ui` | 板载触摸界面客户端（可选） |
| `main` | 初始化与主循环编排 |

## 已实现

- `platform`：UART0 控制台（115200 8N1）、ILI9341（SPI3）、XPT2046（SPI2）、NVS 键值、GPIO4 状态灯
- `transport`：行解析、`\r`/`\n`/退格处理、命令表、外部组件可注册命令、输出镜像（供界面显示同一份回执）
- `wireless_ui`：LVGL 9 + esp_lvgl_port 显示与触摸、主页（标题/运行时长/剩余堆/回执行）、触摸四点校准数据存 NVS
- `main`：初始化顺序与常驻循环

串口命令：

| 命令 | 作用 |
| --- | --- |
| `PING` | 存活检查，返回毫秒级运行时间 |
| `INFO` | IDF 版本、剩余堆与历史最小堆、运行秒数 |
| `TOUCH` | 采样一次触摸原始坐标与按下状态 |
| `HELP` | 命令表（含已注册的外部命令） |
| `SCREEN` | 全屏红/绿/蓝/白循环，验证 SPI 刷屏通路 |
| `UI` | 界面状态与累计刷屏次数 |

## 板级接线（ESP32-2432S028R）

| 用途 | 引脚 |
| --- | --- |
| LCD（SPI3） | MISO 12、MOSI 13、SCLK 14、CS 15、DC 2、RST 无、背光 21 |
| 触摸（SPI2） | MOSI 32、MISO 39、SCLK 25、CS 33 |
| 状态灯 | GPIO4，低电平点亮 |
| 控制台 | UART0，115200 |

## 构建与烧写

```powershell
& 'C:\Espressif\tools\Microsoft.v6.1.PowerShell_profile.ps1'
cd firmware-v2
idf.py -B build build
idf.py -B build -p COM5 flash
```

不依赖 Arduino。托管组件（`lvgl`、`esp_lvgl_port`、`esp_lcd_ili9341`、`cmake_utilities`）
由 `components/wireless_ui/idf_component.yml` 声明，首次构建需要组件本地缓存或网络；
解析结果记在 `dependencies.lock`，`managed_components/` 不入库。

## 状态

- [x] 目录骨架、空组件、`REQUIRES` 白名单、可编译入口
- [x] 屏幕点亮（ILI9341 + LVGL）、触摸采样、串口命令闭环
- [ ] 总线与驱动层代码（wbus / hal_wifi / wifi_frame）
- [ ] 攻击模块重写
- [ ] 其余上层接口插件

## 已知约束

- `idf_component_register` 不能放进 `if()`：条件分支里的 `REQUIRES` 不会生效，条件只能作用于源文件列表。
- 渲染（`lv_refr_now`、全屏刷新）只能在 LVGL 任务里做；`console` 任务栈 4 KB，放渲染会栈溢出重启。
- 触摸坐标映射依赖四角校准，默认值来自本板实测；换屏或换分辨率需重新校准。

## 许可证

Apache License 2.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

本工程为独立重写实现，代码不派生自任何 GPL 工程；新增源文件首行带
`SPDX-License-Identifier: Apache-2.0` 与 `SPDX-FileCopyrightText`。

本目录以外的代码（固件旧实现、上位机、实验脚本）不适用本许可。
