# BLE 靠近弹窗：通道、PID 与实测总结

日期：2026-11-28
范围：Redmi K60（Android 15 / HyperOS 3.0 / GMS 26.45.31）+ 经典 ESP32（COM5）

---

## 1. 一句话结论

- **手环/手表的靠近卡片可以稳定复现**：手机自己的可穿戴 RSSI 表给出 58 个非零 PID，实测 **22 个能弹卡**，标题覆盖 Xiaomi Watch S2/S3/S4/S5、REDMI Watch 5/6、Redmi 手环2、手环8、手环11 等。
- **手环 10 四个变体全部确认**：`59FA/59FB/59FC/6188`，标题分别为手环10、NFC版、陶瓷版、耀影金特别版。
- **耳机不在 MiBeacon PID 表里**：`hlthopen` 的 RSSI 表只有 102 个手表/手环 + 2 个体脂秤，`buds/ear` 零命中。
- **Google Fast Pair 在 K60 上不可用**：`com.android.nearby.halfsheet` 未安装；发真实 Fast Pair model ID 无任何手机反应。实际生效的是小米自己的 `fast_connect`（EasyTether / 经典蓝牙名称）。
- **耳机目前卡在“没有真机”**：无法抓它的广播，无法确认 fast_connect 认的是 BLE 服务还是经典蓝牙名称。

---

## 2. 已验证的 PID 与卡片标题

### 2.1 手环 10 四变体（逐一确认，`onCreate Address` 对得上）

| PID | `xiaomi-ble` 名称 | HyperOS 卡片 |
| --- | --- | --- |
| `59FA` | Smart Band 10 | 发现小米手环10 |
| `59FB` | Smart Band 10 NFC | 发现小米手环10 NFC版 |
| `59FC` | Smart Band 10 Ceramic Edition | 发现小米手环10 陶瓷版 |
| `6188` | Smart Band 10 Glimmer Edition | 发现小米手环10 耀影金特别版 |

### 2.2 手表/手环 22 个命中（来自手机 RSSI 表的 58 个非零 PID）

| PID | 表内型号 | 实际卡片 |
| --- | --- | --- |
| `2429` | midr.watch.m62a | 发现 Xiaomi Watch S2 42mm |
| `281C` | mijia.watch.n60 | 发现 Xiaomi Watch H1 |
| `2897` | mijia.watch.m69 | 发现 Redmi 手环2 |
| `3787` | miwear.watch.m66dsn | 发现 小米手环8 迪士尼100周年限定版 |
| `3916` | mijia.watch.n62 | 发现 Xiaomi Watch S3 |
| `398C` | mijia.watch.n62lte | 发现 Xiaomi Watch S3 eSIM |
| `39C8` | mijia.watch.n62s | 发现 Xiaomi Watch S4 Sport |
| `4461` | mijia.watch.n62car | 发现 Xiaomi Watch S3 eSIM |
| `4671` | mijia.watch.n62cg | 发现 Xiaomi Watch S3 eSIM |
| `4C92` | mijia.watch.n60e | 发现 Xiaomi Watch H1 E |
| `4E01` | mijia.watch.o62 | 发现 Xiaomi Watch S4 |
| `4E02` | mijia.watch.o62lte | 发现 Xiaomi Watch S4 eSIM |
| `4F2A` | miwear.watch.o65 | 发现 REDMI Watch 5 |
| `4F2B` | miwear.watch.o65m | 发现 REDMI Watch 5 eSIM |
| `5736` | miwear.watch.o61 | 发现 Xiaomi Watch 5 |
| `578A` | miwear.watch.o61lte | 发现 Xiaomi Watch 5 eSIM |
| `5F5E` | miwear.watch.o63 | 发现 Xiaomi Watch S4 41mm |
| `67CC` | miwear.watch.p65 | 发现 REDMI Watch 6 |
| `6B4D` | miwear.watch.p62 | 发现 Xiaomi Watch S5 46mm |
| `6DFB` | miwear.watch.p62lte | 发现 Xiaomi Watch S5 eSIM 46mm |
| `8536` | miwear.watch.q63 | 发现 Xiaomi Watch S5 |
| `8812` | miwear.watch.q66cn | 发现 小米手环 11 |

完整 58 个 PID 的逐条结果在 `firmware-v2/build/watch_pid_sweep.json`（工作区产物，不入库）。

### 2.3 未命中不能当“不支持”

58 个里 36 个没弹，但其中包含已知能弹的 `59FA/59FB/59FC/6188`。原因是手机连续弹了二十多张卡后进入限流/抑制状态；后期连 `59FA` 对照都不弹。**未命中要在冷却或重启后复测**。

---

## 3. PID 表是怎么拿到的

不用爆破。手机在 `MiuiWearableDownload` 里请求：

```
https://hlthopen.io.mi.com/hlthopen/public/product/rssi_threshold
  ?data={"phoneKey":"mondrian","include_gray":false}
```

返回 JSON 里直接有 `model` 和 `pd_id`。匿名请求该接口是 **401**，但手机把响应打进了 logcat：

```bash
adb logcat -v time -s MiuiConfigNetConnectController:V MiuiWearableDownload:V MiuiConfigNetActivity:V
```

从日志提取到 104 个唯一 `(model, pd_id)`：102 个手表/手环 + 2 个体脂秤，没有耳机。过滤非零、≤0xFFFF 后得到 58 个候选 PID。

另一个接口 `https://hlth.io.mi.com/glasses/product/rssi_threshold` 也存在，但匿名 401，且当前日志没抓到响应。

---

## 4. 帧格式（MiBeacon `0x33`）

```
02 01 08 0e 16 95 fe 33 58 <pid_lo> <pid_hi> 01 <MAC 6 字节反序> 08
```

| 偏移 | 字段 |
| --- | --- |
| 0–1 | 16 位帧控制 `0x5833`：version 5、auth mode 2、capability include、MAC include、未加密 |
| 2–3 | PID，小端（`FA 59` → `0x59FA`） |
| 4 | 帧计数器 |
| 5–10 | MAC 反序，**必须等于广播地址**；否则解析器按 MAC 不匹配丢弃 |
| 11 | capability 字节（`08`），公开代码只记录、无 bit 定义 |

实测改帧控制高字节（`38/48/58/68`）或 capability（`00/08/28/48/20`）都不影响卡片，**PID 是决定项**。

发送命令：

```
blespam.start mode=popup raw=<19B hex> addr=<同一 MAC> cycle=100
blespam.start mode=xiaomi        # 手环10固定 PID，自动换地址回填 MAC
blespam.stop
```

---

## 5. 限流与坑

- 同一地址最多 3 次；之后 `ignore the device pop-uo 3 times`。
- 弹出后 5 分钟内再出现会 `Ignore the device pop-up less than 5 mins`。
- 日志把地址掩成 `00:00:00:XX:XX:XX`；**复用相同后 3 字节会互相触发黑名单**，批量测试必须换后缀。
- 连续弹二十多张卡后，手机会进入全局抑制；已知能弹的 PID 也会失败。
- 打开 COM5 会因 CH340 拉 DTR 复位板子，计数每次从零开始。

---

## 6. Fast Pair 与耳机

### 6.1 Fast Pair 试过什么

从公开工程 `Danct12/fastpairknockr` 取真实 model ID，按 14 字节格式发：

```
03 03 2C FE 06 16 2C FE <model 3B> 02 0A 00
```

试了 `0xDEEA86`（Xiaomi Buds 4 Pro）、`0xC8C641`（Redmi Buds 4 Lite）、`0xE07634`（OnePlus Buds Z）。板子确认在发（`cycles>0`、`adv_err=0`），手机侧无扫描记录、无通知、无半屏。

原因：

- `com.android.nearby.halfsheet` **未安装**（`pm path` 空，`pm enable` 报 Unknown package）
- K60 实际启用的是小米 `fast_connect`：`is_fastconnect_scan_enable=1`、`fast_connect_support_mode=1`，并带一大串经典蓝牙名称/MAC 黑名单
- `BluetoothExtension.apk`（`com.xiaomi.bluetooth`）里有 `EasyTetherCoreService`、`MiuiFlipBudsPro`，同时引用 `0xFE95` 和 `0xFE2C`

所以 Fast Pair 的 `0xFE2C` 广告在这台机器上不会被处理，换 model ID 也没用。

### 6.2 耳机为什么卡住

- 可穿戴 RSSI 表里没有耳机条目
- 没有真耳机，抓不到它的广播，无法确认 fast_connect 走的是 BLE 服务还是经典蓝牙名称
- `headset_name` 白名单（Redmi Buds、Xiaomi Buds、FlipBuds、FIIL、MOMENTUM…）更像经典蓝牙名称匹配

---

## 7. 复现入口

| 内容 | 路径/命令 |
| --- | --- |
| 帧构造与发送 | `firmware-v2/components/attacks/blespam/blespam.c` |
| 手环 10 四变体 | `blespam.start mode=popup raw=… addr=…` |
| 手表/手环批量 | `firmware-v2/build/watch_pid_sweep.json`、`build/watch_pids.txt` |
| 手机日志 | `firmware-v2/build/pid_sweep_logcat2.txt` |
| 源码核对 | `参考博文/开源源码/xiaomi-ble 源码梳理.md` |
| 早期实验 | `lab/ble_pair_probe/小米快连弹窗实验结论.md` |
| 研究简报 | `ESP32_Android_Quick_Pair_Research_Prompt.md` |

`xiaomi-ble` 源码事实：96 个 `DEVICE_TYPES` 条目，可穿戴只有 4 个手环 10 变体（`devices.py:378-392`）；PID 取 `data[2]+(data[3]<<8)`（`parser.py:2251`）；帧控制 16 位（`parser.py:2204`）；capability 只记录（`:2296-2315`）；HA 钉的是 `xiaomi-ble==1.21.2`，与本地 1.22.1 有版本差。

---

## 8. 下一步

1. 耳机：借一台 Redmi/Xiaomi Buds 开盖抓一帧，确认 `0xFE95` / `0xFE2C` / 私有服务；或做经典蓝牙 A2DP/HFP 名称模拟。
2. 手表/手环：等手机冷却/重启后复测 36 个未命中，特别是 `8813/8814/8816`（手环11 变体）和 `59FA` 对照。
3. 若继续扩 PID：不要再全量爆破 65,536；直接从手机 RSSI 表取候选，按块验证。
