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

- `wbus`：对象注册表、`obj.method key=value` 调用、参数策略校验（类型/范围/必填/默认值/未知参数）、回执与错误文案、事件发布订阅
- `platform`：UART0 控制台（115200 8N1）、ILI9341（SPI3）、XPT2046（SPI2）、NVS 键值、GPIO4 状态灯
- `transport`：插件表、行解析（`\r`/`\n`/退格/超长）、串口插件、把输入行路由到 `wbus`、把回执广播给所有插件
- `services`：`system` 对象（ping/info/help/touch/reset）、`ui` 对象（screen/status），界面能力由 `main` 注入
- `hal_wifi`：STA 初始化（不关联、PS 关）、国家码/频段、信道租约、注入（45 ms 单播节流、
  `0x101` 直接重启、覆盖 `ieee80211_raw_frame_sanity_check`）、混杂接收（RX 队列 + 订阅扇出）、
  主动扫描、SoftAP、TSF、统计与驱动读回诊断
- `wifi_frame`：probe request 组帧、IE 查找、beacon/probe response 解析（SSID/信道/RSN AKM/MFPR/
  扩展能力）、TIM 与 CSA 解析；其余帧构造仍是空实现
- `wtarget`：设备登记表（AP 按 BSSID upsert、RSSI 取最强、STA 带归属 AP）
- `attacks`：攻击驱动描述符与登记表（空，无攻击注册）
- `wireless_ui`：LVGL 9 + esp_lvgl_port 显示与触摸、主页（标题/运行时长/剩余堆/回执行）、触摸校准存 NVS、作为 `transport` 插件显示同一份回执
- `main`：按层序编排与常驻循环

仍需补齐的帧构造：deauth/disassoc/auth/assoc/beacon/action/data/null/LLC-SNAP/BAR/RTS
（签名已固定，实现返回 `-1`）。

串口命令一律是 `对象.方法 [key=value ...]`：

| 命令 | 作用 |
| --- | --- |
| `system.ping` | 存活检查，返回毫秒级运行时间 |
| `system.info` | IDF 版本、运行秒数、剩余堆与最小堆、已注册对象数 |
| `system.help` | 从注册表生成的对象/方法/参数签名表 |
| `system.touch` | 采样一次触摸原始坐标与按下状态 |
| `system.reset` | 重启 |
| `ui.status` | 界面状态：就绪与否、累计刷屏次数、剩余堆 |
| `ui.screen [count=1..4]` | 全屏色块循环，验证 SPI 刷屏通路 |
| `radio.info` | MAC、信道与占用者、国家码、收发与信道统计、TSF |
| `radio.chan ch=1..196 [hold=0..600000]` | 申请并切换信道（租约），被占时返回占用者 |
| `radio.release` | 释放信道租约 |
| `radio.diag` | 从驱动读回混杂/过滤/信道/国家码 |
| `radio.tx_test [ssid=""]` | 注入一个广播 probe request，用来验证注入链路 |
| `scan.ap [dwell=1..500]` | 主动扫描（阻塞 1~2 s），结果写入目标表并逐条打印 |
| `scan.listen [dwell=20..2000]` | 被动监听：拿到信道租约后自动跳 1..13 信道 |
| `scan.stop` / `scan.status` | 停止监听 / 监听计数（beacon、probe response、丢弃） |
| `scan.list` / `scan.clear` | 目标表内容 / 清空 |

参数校验由 `wbus` 统一负责，报错文案形如
`ERR ui.screen: count must be 1..4` / `ERR ui.screen: count is not a number` /
`ERR ui.screen: extra is not a parameter of screen` / `ERR bogus.ping: unknown object`。

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

## 自测

两层，都不依赖人工点击：

| 入口 | 依赖 | 覆盖 |
| --- | --- | --- |
| `sh host_tests/run.sh` | 系统 gcc | `wbus` 70 项 + `wifi_frame` 36 项：注册表、调用、参数策略、回执、事件、边界、probe 组帧逐字节、beacon/TIM/CSA/RSN 解析 |
| `python tools/selftest.py COM5` | pyserial + 板子 | 44 项：启动、对象方法、参数报错、超长行、突发背压、界面镜像、刷屏增量、主动扫描、信道仲裁、注入闭环（AP 回应我们的 probe）、稳定性 |

板端自测会复位开发板并逐条校验回执，失败返回非 0。最近一次结果：主机 106/106、板端 44/44。

## 状态

- [x] 目录骨架、空组件、`REQUIRES` 白名单、可编译入口
- [x] 屏幕点亮（ILI9341 + LVGL）、触摸采样、串口命令闭环
- [x] 总线骨架：注册表 / 调用 / 参数策略 / 回执 / 事件；插件化传输；对象方法命令
- [x] 各层契约头文件（`hal_wifi`、`wifi_frame`、`wtarget`、`attacks`）
- [x] 射频底座：注入与节流、混杂接收、信道租约、两条扫描、SoftAP、目标表
- [ ] 其余帧构造（deauth/auth/assoc/beacon/action/data/BAR/RTS）
- [ ] 攻击模块重写
- [ ] 其余上层接口插件（LVGL 队列以外的 TCP / BLE）

## 已知约束

- `idf_component_register` 不能放进 `if()`：条件分支里的 `REQUIRES` 不会生效，条件只能作用于源文件列表。
- 渲染（`lv_refr_now`、全屏刷新）只能在 LVGL 任务里做；`console` 任务栈 4 KB，放渲染会栈溢出重启。
- 触摸坐标映射依赖四角校准，默认值来自本板实测；换屏或换分辨率需重新校准。
- 注入能出去靠覆盖 `libnet80211` 里的 `ieee80211_raw_frame_sanity_check`，链接期必须带
  `-Wl,-z,muldefs`（已写进顶层 `CMakeLists.txt`），否则会报重复定义。
- 混杂接收的帧长上限 512 字节；更长的帧直接丢弃并计入 `rx_too_long`（旧版用 256 字节时
  把带一堆 IE 的 beacon 全丢了）。
- WiFi 起来后剩余堆约 80 KB（LVGL 池 80 KB + WiFi 栈 + RX 队列 8 KB），后续攻击模块要按这个预算分配缓冲。

## 许可证

Apache License 2.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

本工程为独立重写实现，代码不派生自任何 GPL 工程；新增源文件首行带
`SPDX-License-Identifier: Apache-2.0` 与 `SPDX-FileCopyrightText`。

本目录以外的代码（固件旧实现、上位机、实验脚本）不适用本许可。
