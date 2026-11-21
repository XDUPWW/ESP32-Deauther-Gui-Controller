# firmware-v2

按分层拆开的 ESP32 无线测试固件工程。当前是骨架：只有目录、空组件和可编译的入口，没有攻击实现。

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
| `platform` | NVS 存储、LED、日志 |
| `wireless_ui` | 板载触摸界面客户端（可选） |
| `main` | 初始化与主循环编排 |

## 构建

```powershell
& 'C:\Espressif\tools\Microsoft.v6.1.PowerShell_profile.ps1'
cd firmware-v2
idf.py -B build build
```

纯 ESP-IDF，不依赖 Arduino 与托管组件，断网也能编译。

## 状态

- [x] 目录骨架、空组件、`REQUIRES` 白名单、可编译入口
- [ ] 总线与驱动层代码
- [ ] 攻击模块重写
- [ ] 上层接口插件

## 许可证

Apache License 2.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

本工程为独立重写实现，代码不派生自任何 GPL 工程；新增源文件首行带
`SPDX-License-Identifier: Apache-2.0` 与 `SPDX-FileCopyrightText`。

本目录以外的代码（固件旧实现、上位机、实验脚本）不适用本许可。
