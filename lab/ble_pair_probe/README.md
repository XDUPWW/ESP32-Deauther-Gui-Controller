# ESP32 主动连接与 Android 配对实验

这是独立的 ESP-IDF 实验工程，使用自定义 UUID 和单次连接，验证 ESP32 作为 BLE Central 主动连接自有手机上的可连接测试广播，并发起标准 BLE 安全配对。**该实验不是 Google Fast Pair，也不会证明小米或 OPPO 耳机式卡片可用。**

## 原理和边界

手机须先在测试应用中显式启用 BLE Peripheral 广播。设备通电后主动扫描 30 秒，只连接广播或扫描响应里含下列 UUID 的可连接设备一次，然后调用 `ble_gap_security_initiate()`。扫描回复只在此前收到同一地址的可连接广播时才接受；地址不记录到日志，也不自动重试。配对确认框由手机系统决定；手机不支持该角色、未启动广告、手机已有 bond 或系统策略不同时，可能没有弹窗。

测试服务 UUID：`5e1377f6-f0b1-4196-9f46-c6f870623f91`。它是本实验自定义标识，既不是 Fast Pair 的 FE2C，也不是耳机厂商身份。手机测试应用需要将它放在 128-bit Service UUID 列表，且开启可连接广播。

ESP32 声明 Display Only 并要求 MITM 和 LE Secure Connections；如协商为输入密码，串口显示一次性六位数字，由操作者在手机输入。其他需要 ESP32 确认或输入的交互当前不支持，会断开。不要在公共环境打开该测试广告。

## 硬件与构建

- 经典 ESP32，ESP-IDF v6.1，NimBLE；手机需安装可创建自定义可连接 BLE 广播的应用，例如已安装的 nRF Connect。应用的具体界面和 Android 版本是否允许设置服务广播须现场核实。
- 本工程开启 bond 持久化。`nvs_flash_init()` 出错时直接退出，**不会自动擦除 NVS**。
- 本工程是独立固件，刷写会覆盖板上原有应用和可能的分区表；需先确认备份与恢复方式，不要使用 `erase-flash`。不要把备份、设备地址、配对密钥、截图或个人数据加入仓库。

```powershell
& 'C:\Espressif\tools\Microsoft.v6.1.PowerShell_profile.ps1'
cd lab/ble_pair_probe
idf.py set-target esp32
idf.py build
```

## 实验步骤

1. 确认板卡、当前固件和恢复方案。手机蓝牙开启，在测试应用的广告设置中创建上述 UUID 的可连接 legacy 广播；不使用真实耳机或第三方品牌身份。
2. 操作者允许刷写后，按实际串口用 `idf.py -p COMx flash` 刷入。串口监视为 115200 8N1；注意 CH340 的 DTR/RTS，使用已有的禁用自动复位串口工具更稳妥。
3. 串口应依次出现 `30-second scan started`、`test advertiser found`、`connect request rc=0`、`connect status=0`、`security request rc=0`。每次只尝试一次；未发现时扫描到期退出。
4. 观察手机实际出现的系统 UI；如要求输入配对码，从串口读取一次性六位数并由用户决定是否输入。记录 `encryption status`、`encrypted`、`authenticated`、`bonded`；断开后停止手机测试广告。
5. 与不启用测试广告的对照比较。重复实验前，**由用户明确选择**是否在手机忘记该实验设备；程序不会自动删除已有 bond。若需清理 ESP32 的实验 bond，另行设计定向删除，不能擦除整个 NVS。

## 判据与记录

分别记录手机型号、系统版本、手机测试应用及其广告设置、连接是否成功、配对 UI 类型、用户是否确认、认证及 bond 状态。扫描与连接成功只证明主动 BLE 链路；出现普通系统配对框不等于 Google Fast Pair；只有获得自有 Model ID、密钥并完成完整 Provider 后，才能单独评估快速配对卡片。

已知局限：手机必须运行并允许测试广告；不含业务 GATT 通信、超时断连、工厂清除、Fast Pair 认证、量产密钥保护、Wi-Fi 共存或对 OPPO 机型的验证。串口输出只用于本地测试，勿保存密码或设备地址。

## 2026-11-28：现有硬件实验

- 经典 ESP32、ESP-IDF v6.1；Redmi K60（23013RK75C）、Android 15、HyperOS 3.0，Google Play 服务 `26.45.31`；手机使用已安装的 nRF Connect 创建上述测试广播。
- 构建通过，实验固件已刷入 ESP32。手机测试广播最初误设为 Bluetooth 5 扩展广播，Windows 能看到，经典 ESP32 扫描不到；改为可连接 legacy 广播后，ESP32 成功匹配 UUID 并发起连接。
- 串口依次报告 `connect status=0`、`security request rc=0`、`passkey injected rc=0`。手机通知栏出现系统“配对请求”；自动化打开通知、输入 ESP32 生成的本次配对码并点击系统确认。手机蓝牙服务的 `Bonded devices` 中随后出现该实验设备。确认操作约在板端启动后 11 秒完成。
- 首轮没有及时确认，板端报告 `encryption status=13 encrypted=0 authenticated=0 bonded=0`。成功轮手机 bond 已确认，但板端最终的加密状态日志未完整捕获，因此**不能据此宣称本轮板端 `authenticated=1` 或确认加密算法**。
- 手机沿用了先前固件的设备名称缓存，系统通知显示历史名称；它是本实验 ESP32，不是耳机身份。测试广播已关闭，板端复位后只执行一次 30 秒扫描。实验建立的手机 bond 有意保留，未删除已有配对数据。
- 结果是 **ESP32 主动连接手机测试广播并触发普通系统配对请求**，不是在手机无需运行测试广播时出现的快速配对卡片，也不是 Google Fast Pair。OPPO 与 Pixel 尚未测试。
