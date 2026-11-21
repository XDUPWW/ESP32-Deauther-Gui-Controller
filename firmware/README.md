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
│   ├── csa.h / delba.h       CSA 欺骗 / DELBA + BA 会话劫持
│   ├── wnm.h / tim.h        802.11v BTM Request / TIM 投毒
│   ├── eapol.h / sae.h       EAPOL-Start/Logoff / SAE Commit 洪泛
│   ├── pspoll.h              电源管理（PM 位）欺骗
│   ├── authflood.h           Auth/Assoc 洪泛 + WPA3 自动升级
│   ├── tx_guard.h            注入守卫：首个 0x101 立即重启；节拍上限
│   ├── ie_util.h             IE / RSN(AKM/PMF) / Extended Capabilities 解析
│   ├── evil_twin.h           钓鱼热点与凭据
│   ├── serial_console.h      命令分发入口
│   ├── definitions.h         宏：信道上限、每轮帧数、reason、LED、调试开关
│   ├── types.h               802.11 帧结构体（空口序）
│   └── storage.h             NVS 注入接口（给 UI 用）
├── src/
│   ├── main.cpp              启动：STA 静默、初始化各模块、主循环 tick
│   ├── serial_console.cpp    串口解析 + 命令实现（SCAN/DEAUTH/...）
│   ├── deauth.cpp            deauth 攻击 + 嗅探触发 + 逐 AP 计数 + STA 嗅探
│   ├── csa.cpp               CSA 欺骗（倒计时播报 + 新信道克隆 beacon + 接应）
│   ├── delba.cpp             DELBA 欺骗 + BA 会话劫持（DELBA→ADDBA→BAR）
│   ├── wnm.cpp               802.11v BTM Request 欺骗
│   ├── tim.cpp               克隆 beacon 篡改 TIM
│   ├── eapol.cpp             EAPOL-Start/Logoff 洪泛（ToDS 数据帧 + LLC/SNAP）
│   ├── pspoll.cpp            伪造 PM=1 Null Data（让 AP 缓存受害 STA 的下行）+ PM=0 撤销
│   ├── sae.cpp               SAE Commit 洪泛 + WPA3 判别 + 反 clogging token 回显
│   ├── authflood.cpp         Auth/Assoc 洪泛 + 自动切换到 SAE
│   ├── tx_guard.cpp          统一的 esp_wifi_80211_tx 封装与 0x101 重启规则
│   ├── ie_util.cpp           IE 遍历、AKM/PMF/11v 能力位判定
│   ├── evil_twin.cpp         克隆 AP、DNS 劫持、登录页、凭据表
│   ├── general.cpp           公共工具（信道、国家码、随机 SSID/MAC）
│   └── storage.cpp           用 nvs_flash 实现 UI 的 load/save/clear
├── components/wireless_ui/   可选 LVGL 界面（见 §7）
├── tests/test_wireless_attack.py   51 项自动化用例
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
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 -p COM10 flash
```

C5 开发板一般只引出原生 USB（USB-Serial-JTAG），没有 UART0 排针。顶层 `CMakeLists.txt`
对 `esp32c5` 目标定义了 `ARDUINO_USB_MODE=1` 和 `ARDUINO_USB_CDC_ON_BOOT=1`，Arduino 的
`Serial` 因此指向 `HWCDCSerial`；`sdkconfig.c5` 里同时把次要 console 关掉，免得 IDF 的 log
和 HWCDC 抢同一个外设。没这两步，串口能烧写但一条命令都不回。

C5 上 `RXLOG` 的 `fmt=` 直接是驱动的 `cur_bb_format`：0=11b、1=11g、2=HT、3=VHT、4~7=HE。
只有 0 和 1 会给确切的 `rate=<Mbps>`；HT/HE 帧打 `rate=ht/vht/he`，因为驱动那个字段
放的是 L-SIG 的 RATE，只描述前导。经典 ESP32 上 `fmt=` 只有 0（11b/g）和 2（HT），
HT 帧还要连 `mcs` 一起看。

之后切回 ESP32 用普通 `idf.py build` 即可；两套互不覆盖。
（首次切换 target 时组件管理器会重新下载非当前目标的 `managed_components`，属正常现象。）

### 3.4 产物大小

| 目标 | 镜像 | 分区占用 |
| --- | --- | --- |
| ESP32（含 LVGL） | 1.40 MB | 3 MB 分区的 47% |
| ESP32-C5（无 LVGL） | 1.17 MB | 3 MB 分区的 39% |

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
| `STATUS` | 状态 | `STATUS mode=.. eliminated=.. deauth_frames=.. probe_frames=.. ch=.. rx=.. rxm=.. txok=.. txerr=.. txerr_nomem=.. txec=.. txdrop=.. txg=.. txgok=.. txgerr=.. blind=.. rev=.. csa=<idle\|announce\|hold> csaf=.. csac=.. csch=.. csaauto=.. csacycle=.. csaauth=.. csarej=.. wnm=.. wnmf=.. wnmc=.. wnmskip=.. wnmresp=.. wnms=.. tim=.. timf=.. timaid=.. timreal=.. eap=.. eapf=.. eaprx=.. eaprxreq=.. eaprxsta=.. sae=.. saesec=.. saef=.. saec=.. saeresp=.. saecode=.. saetok=.. saeecho=.. af=.. aff=.. afa=.. afs=.. afids=.. afst=.. afup=.. delba=.. delbaf=.. reason=.. rlast=.. networks=.. creds=.. heap=.. ui=.. caps=..` |
| `WBUS` | wbus 对象表：列出已迁移到总线的对象、方法、事件 | `WBUS objects=2` / `WBUS deauth "Deauth / disassoc flood" methods=start,stop events=state` |
| `DESCRIBE [obj]` | 对象的 UI 元数据（标题 / 方法 / 参数名·类型·默认值·枚举），供 GUI 与触屏生成页面；不带参数=全部对象 | `OBJ csa "CSA spoof"` / `METHOD csa.start ".."` / `ARG csa.start ch type=enum default=-1 values=auto` / `EVT csa state` |
| `CALL <obj>.<method> [k=v ...]` | wbus 关键字调用，与同名旧命令等价（`CALL deauth.start idx=3 reason=7` ≡ `DEAUTH 3 7`）；未知对象/方法/参数各有独立 `ERR` | `OK DEAUTH 3 ssid` / `ERR unknown arg nope (try DESCRIBE deauth)` |
| `EVTSUB [topic\|pattern]` | 订阅总线事件（默认关闭，所以老输出一个字节都不变）；`*` 结尾做前缀匹配，不带参数=取消全部 | `OK EVTSUB deauth.*` / `EVT deauth.state active=1` / `OK EVTSUB none` |
| `DEAUTH <idx> [reason\|random]` | 单目标 deauth | `OK DEAUTH <idx> <ssid>` / `ERR ...` |
| `DEAUTH_ALL [reason]` | 扫描到的全部 AP 轮流打 | `OK DEAUTH_ALL ...` |
| `DEAUTH_ONLY <i,j,..> [reason]` | 白名单 | `OK DEAUTH_ONLY <n> aps` |
| `DEAUTH_EXCEPT <i,j,..> [reason]` | 黑名单 | `OK DEAUTH_EXCEPT <n> aps` |
| `REASON [1-65535\|random]` | reason code：数字=固定值，`random`=每束随机，不带参数=查询当前值 | `OK REASON 7` / `OK REASON random` / `REASON 7` |
| `CSA <idx> [ch] [cnt] [secs]` | CSA 欺骗。不给 `ch`（或写 `auto`）= 自动挑**对向频段**的随机信道并**循环**打；给了 `ch` 就是单次指定信道 | `OK CSA 0 auto(opposite-band) count=5 hold=5s loop=1 ssid=..` |
| `CSASTOP` | 停止 CSA | `OK CSASTOP frames=31` |
| `CSATEST` | 打印 band 判定 + Action 帧 + 带 CSA IE 的 Beacon + Auth/Assoc 响应帧的**原始字节**（格式自检） | `CSATEST band ap_ch=1(2.4G) new_ch=153(5G) auto=1` / `CSATEST authresp ...` / `CSATEST assocresp ... status=17` |
| `DELBA <idx> [reason]` | DELBA 欺骗（拆 Block Ack 会话）。reason 只接受真实对端会用到的 1/32/37/38/39，缺省 37 | `OK DELBA 0 reason=37 ch=1 ssid=..` |
| `DELBASTOP` | 停止 DELBA | `OK DELBASTOP frames=347` |
| `DELBATEST` | 打印 DELBA 帧的**原始字节** + TID/Initiator 位解码（格式自检） | `DELBATEST ap_to_sta len=30 cat=3 act=2 tid=0 init=1 reason=37 hex=D000...` |
| `BAATTACK <idx> [step]` | BA 会话劫持：DELBA 清场 → 伪造 ADDBA 种窗口 → BAR 推窗，循环（`step` 0–2047，<128 为对照） | `OK BAATTACK 0 step=512 ch=1 ssid=dt` |
| `BAPLANT <idx> [step]` | 只种窗口（≤8 帧 ADDBA）然后**完全静默**，用于判断静默期是否也会瘫 | `OK BAPLANT 0 step=512 ch=1` |
| `BARPUSH <idx> [step]` | 只发 BAR（不发 ADDBA/DELBA）后静默，用来隔离"推窗"与"会话改写" | `OK BARPUSH 0 step=512 ch=1` |
| `WNM <idx> [cand\|bare] [timer] [ch] [sta-mac]` | 802.11v BTM Request 欺骗。`cand`=带一个幻影候选 BSS（默认），`bare`=不带候选列表；`timer` 是 disassociation timer（TBTT，必须非 0，默认 10）；`ch` 是候选 BSS 通告的信道；给了 `sta-mac` 就直接对那个 MAC 发（不必等它自己说话） | `OK WNM 0 mode=cand timer=10 cand_ch=6 ssid=..` / `OK WNMSTA 02:AA:BB:CC:DD:EE` |
| `WNMSTOP` | 停止 BTM 欺骗 | `OK WNMSTOP frames=45 responses=0 last_status=0` |
| `WNMTEST` | 打印 BTM Request 原始字节 + 解码（category/action/request mode/timer/候选元素），格式自检 | `WNMTEST ... cat=10 act=7 ... imm=1 cand=1 timer=10` |
| `TIM <idx> [tim\|clear] [aid]` | 克隆目标 AP 的 beacon 并篡改 TIM。`tim`=按 AID 置位（默认）、`clear`=清空 bitmap；`aid=0` 表示用学到的全部 AID，1..255 指定单个 AID | `OK TIM 0 mode=tim aid=3 ch=12` |
| `TIMSTOP` | 停止克隆 beacon | `OK TIMSTOP frames=277 real_beacons=50` |
| `TIMTEST` | 打印 TIM 元素与克隆 beacon 的字节 | `TIMTEST tim len=6 ... dtim_count=0 ... bitmap=08 bmp_mask=0x00000008` |
| `EAPOL <idx> [tid\|-1] [sta-mac]` | EAPOL-Start/Logoff 洪泛，伪造受害 STA 的 MAC。`tid` 是 QoS TID（默认 6），`-1` 只发非 QoS 数据帧 | `OK EAPOL 0 tid=6 ch=12 ssid=..` |
| `EAPOLSTOP` | 停止 EAPOL 洪泛 | `OK EAPOLSTOP frames=110 rx_ap=0 rx_sta=0 eap=0` |
| `EAPOLTEST` | 打印两种 EAPOL 数据帧（非 QoS + QoS）的字节与解码 | `EAPOLTEST start plain ... etype=888E ver=2 type=1` |
| `PSPOLL <idx> [sta-mac] [null\|qosnull\|action]` | 电源管理（PM 位）欺骗：用受害 STA 的 MAC 发 PM=1 的帧，AP 以为它睡了，把下行缓存起来。`null`=Null Data、`qosnull`=QoS Null（默认，实测最强）、`action`=单播 Action(127，不受 PMF 保护)；给了 `sta-mac` 就直接打那个 MAC | `OK PSPOLL 0 mode=pm frame=qosnull sta=02:AA:.. ch=6 chset=0 ssid=..` |
| `PSPOLLREL` | 撤销：给每个受害者补一帧 PM=0 后停止（AP 于是把攒下的帧放出来） | `OK PSPOLLREL clients=1 flushed=1` |
| `PSPOLLSTOP` | 停止 PM 位欺骗（不发帧，直接停） | `OK PSPOLLSTOP frames=101 null=101 flush=17 dl=844` |
| `PSPOLLTEST` | 打印三种帧型（Null Data / QoS Null / 单播 Action）与 PM=0 版本的字段与十六进制 （PM=1 与 PM=0 只差 `frame[1]` 的 0x10 位） | `PSPOLLTEST qosnull len=26 fc=0x11C8 pm=1 tods=1 tid=0 ...` |
| `SAE <idx> [point\|rand] [gap_ms]` | SAE Commit 洪泛（WPA3）。`point`=发合法 P-256 生成元（默认），`rand`=随机字节对照组；`gap_ms` 是帧间隔，默认 50 ms | `OK SAE 0 elem=point gap_ms=50 ch=12` |
| `SAESTOP` | 停止 SAE 洪泛 | `OK SAESTOP frames=.. identities=.. responses=.. tokens=.. echoed=..` |
| `SAETEST` | 打印 Commit 字节（alg/seq/group/元素）+ 带 token 的容器形状 | `SAETEST commit len=128 alg=3 seq=1 ... group=19` |
| `AUTHFLOOD <idx> [both\|auth\|assoc] [noauto]` | Auth/Assoc 洪泛，每个身份一个随机 MAC。嗅到目标 RSN 里含 SAE 时自动切到 SAE 洪泛（加 `noauto` 关闭） | `OK AUTHFLOOD 0 mode=both auto=1 ch=12 ssid=..` |
| `AUTHFLOODSTOP` | 停止 Auth/Assoc 洪泛 | `OK AUTHFLOODSTOP frames=130 identities=66 last_status=0 upgraded=0` |
| `AUTHFLOODTEST` | 打印伪造的 Authentication / Association Request 字节 | `AUTHFLOODTEST auth len=30 alg=0 seq=1 status=0` |
| `BASTOP` | 停止 BA 攻击 | `OK BASTOP delba=54 addba=1 bar=256` |
| `BATEST` / `BATX` | 打印伪造 ADDBA/BAR 的字节与解码 / 各发一帧并打印驱动返回值 | `BATEST addba len=33 ...` / `BATX delba(30B)=0 addba(33B)=0 bar(20B)=0` |
| `RESTART` | `esp_restart()`；注意 burst 之后它可能卡在 wifi 反初始化，恢复靠主机拉 RTS | `OK RESTART` |
| `MON <ch> <secs>` | 被动监听（`ch=0` 表示逐信道跳），计数器从 0 开始，便于用第二块板验证注入 | `OK MON ch=6 8s` |
| `RADIO` | 打印驱动的嗅探状态：`promisc`、类型 mask、**控制帧 subtype mask**、当前信道，以及信道仲裁的当前 owner 与抢占次数 | `RADIO promisc=1(0) filter=0x00000007(0) ctrl_filter=0xFF800000(0) ch=1 owner=csa rtake=2` |
| `CTRLFILTER [hex\|all\|none]` | 查询/设置二级控制帧过滤器（默认 `all`；设成 `0` 就一帧控制帧都收不到） | `OK CTRLFILTER set=0xFF800000 readback=0xFF800000 err=0` |
| `CTRLTEST [subtype] [broadcast\|bssid] [dur]` | 注入 10 帧指定子类型的控制帧（默认 RTS=11、RA=广播、Duration=0），用第二块板验证"控制帧到底能不能被上报/被发出去" | `OK CTRLTEST subtype=10 ra=bssid dur=0xC025 sent=10` |
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
| `UIREASON` | 打开屏上 reason 弹窗（等价点 `R:x`） | `OK UIREASON` |
| `UI` | 屏状态 | `UI screen=.. popup=.. items=.. rpopup=.. ritems=.. nets=..` |
| `UISCREEN <name>` | 切到指定屏幕（`menu/deauth/mode/probe/csa/delba/ba/evil/wnm/tim/eapol/pspoll/sae/authflood`），给自动化测试用 | `OK UISCREEN delba` |
| `RXLOG` | 打印最近 256 条监听到的 802.11 帧（诊断），每行带 `rssi/ch/dur/fmt/rate`；收到的 CSA Action 会额外打印 `RXCSA <i> src=.. cat=4 act=4 nch=.. cnt=.. len=..` | `RXLOG_BEGIN <n>` / `RX i type=.. ...` / `RXLOG_END` |
| `RXMIX` | 收到的帧按类别计数（beacon/probe resp/deauth/auth/assoc/ctrl/data/action），并用 `csa_action` / `csa_ie` 单独统计 CSA 帧、`addba` / `delba` 统计 Block Ack 管理动作、`bar/ba/pspoll/rts/cts/ack` 统计控制帧 subtype | `RXMIX beacon=.. deauth=.. ctrl=.. data=.. action=.. csa_action=.. csa_ie=..` |

`reason` 缺省 1：

- **固定值** `1…65535`。标准明确定义的是 1–11、13–24；用其它值仍会发送，但会打印
  `INFO reason N is outside the defined set ...`（多数客户端会忽略未定义 reason）。
- **`random`**：每一束（每次命中）从这 23 个标准值里重掷一个，`STATUS` 的 `rlast=` 是最近一次用的值。
- **非法输入**（`0`、负数、`>65535`、非数字）→ `ERR reason must be 1..65535, or 'random'`，
  不再像以前那样静默退化成 1。

`<idx>` 只在最近一次 `SCAN` 内有效（重扫后旧索引无意义）。

所有攻击与射频命令都已迁移到 wbus 总线（`TODO.md` 第 6 节 P1–P4）：`DEAUTH*` / `CSA*` / `DELBA*` /
`BA*` / `WNM*` / `TIM*` / `EAPOL*` / `PSPOLL*` / `SAE*` / `AUTHFLOOD*` / `PROBE_BROADCAST` /
`EVILTWIN*` / `CREDS` / `RADIO`，共 40 条命令映射到 13 个对象。命令名与回执文本
**一个字节都没变**，内部改由 `wbus_call()` 分发，所以参数校验、`DESCRIBE` 元数据、`EVT` 事件
都不必每个模块各写一遍。新代码优先用 `CALL <obj>.<method> k=v`。
留在旧 `strcmp` 链里的是控制台管道（`HELP`/`PING`/`STATUS`/`STATS`/`SCAN`/`STOP`/`REASON`/`MON`/
`STATIONS`/`RXMIX`/`RXLOG`/`RESTART`/`CTRLTEST`/`CTRLFILTER`/`TOUCH`/`CALIBRATE`/`UI*`），
两种路径的对外行为一致；改动后必须过 `lab/compat_matrix.py check`（89 条命令零差异）。

### 4.2 输出行

```
NET  <idx> <rssi> <信道> <加密> <BSSID> <SSID>      # 信道 >14 即 5 GHz，SSID 在最后（可含空格）
AP   <idx> <bssid> ch<信道> frames=<该 AP 已发 deauth 帧数>
STA  <i> <mac> <所属AP> ch<信道> <rssi>dB frames=<n>
CRED <idx> <用户名> <密码> <时间戳ms>
RX   <i> type=<0..3> sub=<n> len=<n> dest=<mac> src=<mac> bssid=<mac>
```

`caps` 取值：`deauth`、`eviltwin`、`probe`、`wnm`、`tim`、`eapol`、`sae`、`authflood`，
C5 额外带 `5g`。

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
- **CSA 欺骗**（`CSA`）：在目标 AP 的信道上按 `count = 5→1` 每 100 ms 播报一轮，每轮 3 帧广播 Action +
  每个已见客户端 1 帧单播 Action + 1 帧带 CSA IE 的 Beacon；countdown 结束后跳到新信道，用
  克隆 beacon（同 BSSID/SSID/从真 beacon 抄来的 RSN IE）每 100 ms 顶 `hold` 秒。
  **默认自动**：2.4G 的 AP 被通告到一个随机 5G 信道，5G 的 AP 反之，每轮重新随机，一轮接一轮
  直到 `CSASTOP`（`STATUS` 的 `csaauto=1` / `csacycle=` 可观测）。
  CSA 的帧也走 `tx_guard_send()`：广播帧豁免，单播的那一路（每个客户端每轮 1 帧）被整流器限速，
  所以"客户端很多"不会把 TX 缓存推开（`STATUS` 的 `txg=` 会体现被挡下的帧，它们下一轮再发）。
- **新信道上冒充 AP**（每轮 500 ms，`CSA_AUTO_HOLD_MS`）：发克隆 beacon，收到客户端的
  **Auth 请求就回成功**、收到 **Assoc/Reassoc 请求就回失败**（status 17「AP 无法再接客户端」）。
  客户端于是"看得见、认证得过、就是连不上"，留在新信道反复重试，而不是马上回原信道。
  计数看 `STATUS` 的 `csaauth=` / `csarej=`。
  CSA 不是 robust 管理帧，**PMF 不校验它**，所以这条路线对 WPA3 客户端仍然有效。
- **DELBA 欺骗**（`DELBA`）：先听（QoS 数据帧的 TID、BA/BAR 的 TID、ADDBA 的 TID，同时学客户端 MAC），再对每个已知客户端按 TID 单播 DELBA——**AP→STA 和 STA→AP 两个方向都发**，每 100 ms 重发一轮；一个客户端都没听到时发广播 DELBA 兜底（`delbb=`）。
  它不踢人：客户端一直关联着，只是丢了 A-MPDU 聚合。实验室实测（ESP32 AP ↔ C5 客户端，TCP 下载）：480–630 KiB/s → 0–5 KiB/s（约 -99%），`ADDBA` 重建会被再拆一次。
  嗅探能力：单播管理帧（Auth/Assoc/ADDBA）**收得到**，所以“听到 ADDBA 立刻补刀”会真的触发
  （实验室 `delbab=7`、`delbtr=5`）；BA/BAR 控制帧收不到（`ctrl=0`/`delbar=0`），
  所以另用 QoS 数据帧的 TID 做周期扫描兜底（见 §11 第 6 条）。
- 注入不在混杂回调里做：回调只把"该踢谁"塞进队列，主循环按 1 ms 节奏出队、失败退避 5 ms 重试。
  这是修掉"`deauth_frames` 在涨但帧没出去"那个 bug 的关键（见 §11）。
- `PROBE_BROADCAST` 不需要目标也不需要扫描：4 帧/4 ms，SSID/BSSID 每帧随机，120 ms 换信道。
- `STOP` 立即停一切（含 Evil Twin），回到静默。
- **802.11v BTM Request 欺骗**（`WNM`）：WNM Action（category 10 / action 7）。注意保护状态：
  action 类别里只有 Public/HT/Unprotected-WNM/Self-protected/VHT/厂商自定义不算 robust，**category 10
  在 robust 集合里**——所以 PMF 强制（WPA3）的客户端会在驱动里直接丢弃，本模块打的是
  PMF 关闭或可选（大多数 WPA2）的网络。伪造 TA 为 AP BSSID 即被客户端接受。`cand` 模式带一个幻影候选 BSS（Neighbor
  Report 元素 id 52 / len 13，指向同频段的另一个信道）；`bare` 模式不带候选列表。
  **disassociation timer 必须非 0**：wpa_supplicant 只在
  `DISASSOC_IMMINENT 且 timer != 0` 时才 `wpa_supplicant_req_scan()`，置 0 等于什么都没发生。
  客户端能力从它的 Probe/（重）Association Request 里的 Extended Capabilities（id 127, bit 19）
  学出来，明确不支持的会被跳过（`wnmskip=`）；`sta-mac` 参数可以绕过学习直接指定目标。
  每个客户端 300 ms 重发一次，全局节拍 50 ms（见 §11 第 10 条）。可观测：`wnmresp=`（BTM Response
  数量）、`wnms=`（最后一次的 status，1=reject unspecified，说明它解析了但拒绝）。
- **TIM 投毒**（`TIM`）：克隆目标 AP 的 beacon（同 BSSID/SSID/RSN IE/capability/
  beacon interval），每 20 ms 发一帧（真 AP 是 100 TU ≈ 102 ms，即 5 倍占空比），
  **在学到真 beacon 之前一帧都不发**（否则 SSID 为空的帧只会被当成另一个坏网络）。
  TIM 元素按 **AID** 索引：第 i 字节第 j 位 = AID `8i+j`（bit 0 是 AID 0，也就是组播灯，
  对应 Bitmap Control 的 bit 0），所以 AID 1 落在 `0x02` 而不是 `0x01`；DTIM count 固定 0
  （每个 beacon 都是 DTIM → 客户端每次都全醒）；AID 从 AP 的 Association Response（偏移 28..29，
  掩 0x3FFF）学出来，也可以用 `aid=` 直接指定。
  **TSF 那半已删除**：MAC 用接口自己的 TSF 覆盖 beacon 的 24..31 字节（未关联 STA 时是 0），
  写什么都上不了空口，见 §11 第 11 条。
- **EAPOL-Start / Logoff 洪泛**（`EAPOL`）：ToDS 数据帧 + LLC/SNAP（`AA AA 03 00 00 00 88 8E`）
  + EAPOL 头（version 2、type 1/2、length 0），TA 伪造受害 STA。Start 让认证器重启 802.1X，
  Logoff 把受控端口打回未授权态，两者交替发送让端口抖动。QoS（subtype 8, TID 6）与非 QoS
  （subtype 0）两种形态交替发，因为不同驱动接受的形态不同。**WPA2/WPA3-PSK 下多数 AP 直接忽略
  EAPOL-Start**，所以效果必须看对端计数：`eaprxreq=` 是 AP 发回的 EAP 包（type 0，即
  EAP-Request/Identity，证明 802.1X 状态机真重启了）、`eaprxsta=` 是真实 STA 自己发的 EAPOL
  （证明它收到了 Logoff 去重认证）。实验室对华为 WPA2 AP 实测两者都是 0——功能面只证明"帧上空气、
  格式正确"。
- **SAE Commit 洪泛**（`SAE`）：Authentication 帧，algorithm 3、sequence 1、group 19（P-256），
  后跟 32 字节 scalar + 64 字节 element。element 默认用 **P-256 生成元**（公开常量、合法曲线点），
  这样 AP 没法在点校验阶段提前短路；`rand` 是随机字节对照组，两者对比就能定位"贵在哪一步"。
  反 clogging 是反射式校验，不是防护：AP 回 status 76（token required）时，模块把 token 存回该
  身份，下一帧原样回显（H2E 形态装进 Element 255 / Ext 93 容器，非 H2E 形态直接跟在 group 后面），
  这才让 AP 真做标量乘。身份（随机 MAC）每 4 帧换一个，顺带消耗 AP 的 SAE 状态。
  判别：`saesec=` 从 RSN IE 的 AKM 得出（`00-0F-AC:8/9/24` = SAE），`saecode=` 是 AP 回来的
  status（13 = 该 AP 不支持 SAE，76 = 要 token，0 = 不可能出现在这里）。
- **Auth/Assoc 洪泛 + WPA3 自动升级**（`AUTHFLOOD`）：Authentication（algorithm 0 / seq 1）与
  Association Request 各一帧一个身份，身份每 2 帧换成新随机 MAC，Association Request 带目标的
  SSID 与 RSN IE（不带的话 AP 在查表之前就把帧丢了，洪泛白打）。`afst=` 是 AP 回来的 status，
  **17 = 表满**（"AP 无法再接客户端"）才是目标，13 = 该 AP 不吃开放式认证，0 = 竟然接受了。
  嗅到目标 AKM 含 SAE 时自动停自己、转 `sae_start()`（`afup=1`，串口打一行 `INFO AUTHFLOOD ...`），
  因为 SAE AP 对开放式 Auth 只回 status 13，洪泛对它是免费的。
- **电源管理（PM 位）欺骗**（`PSPOLL`）：用受害 STA 的 MAC 发带 **PM=1** 的帧——AP 收到就把这个 STA 当成"睡了"，下行不再直接发，
  而是缓存进 TIM；真站醒着、永远不来取，于是收不到。每第 6 帧改发 **PM=0**：让 AP 把攒下的帧
  "放"给一个并不在听的站（把"延迟"变成"丢失"），同时也是撤销（`PSPOLLREL` 给每个受害者补一帧）。
  同一个 PM 位有三种承载帧，各家协议栈认的不一样，所以可切：`null`=Null Data（data 4，24 B，帧控制 `0x1148`）、`qosnull`=QoS Null（data 12，26 B，`0x11C8`，多 2 字节 QoS Control）、`action`=单播 Action（mgmt 13，29 B，`0x10D0`，类别 127）。**默认 `qosnull`**（实测 −38%，另两种 −30% / −21%）。
  这三条都**不属于 PMF 的 robust 集合**（数据帧的 PM 位本就不受保护，厂商自定义 Action 也不在集合里）——这是它相对 deauth/DELBA/BTM 的差异（那三条在强制 PMF 的 WPA3 网络上会被客户端驱动丢弃）。
  节拍是 **10 帧/s**（不是 20）：实测 20 帧/s 时这个帧型会在几百帧后打满短缓存池并触发
  `0x101` 重启。效果边界与实测见 `attack-principles.md §13`：下行吞吐 −24…−46%、零掉线，
  因为受害者自己的上行帧（PM=0）会把 AP 的状态翻回来。
  有一半被删除了：伪造 **PS-Poll**（控制子类型 10）在本 MAC 上**单播发不出去**
  （广播 RA 10/10 上空气、RA=BSSID 0/10），所以模块里只剩 PM 位那一半（附录 A）。
- 所有新模块都走 `tx_guard_send()`：**第一次 `0x101`（`ESP_ERR_NO_MEM`）立即 `esp_restart()`**，
  重启前打一行 `FATAL tx 0x101 ... -> restart`。这是刻意设计——池空了之后射频不再接受任何帧，
  假装还在跑比重启更糟。节拍上限的实测数据见 §11 第 10 条。
- 原理与帧结构见 [代码框架与攻击原理.md](代码框架与攻击原理.md)。

---

### 5.1 六个模块的验证步骤

判据分三层，越往下越有说服力：**① 帧上空气且字段对**（抓包管道）→ **② 对端有回应**（STA 侧计数）
→ **③ 效果可观测**（客户端断开/吞吐下降/AP 表满）。本仓库只做到 ②，③ 需要对应的对端环境。

空口抓包统一用 C5 的管道（信道固定 12，攻击前把目标调到该信道或改 C5 固件）：

```bash
python lab/cap_frames.py --seconds 6 --bssid <AP-BSSID>     # 帧字段
python lab/air_check.py --port COM5 --bssid <AP-BSSID>      # 逐模块起-抓-停
```

| 模块 | 命令 | ① 抓包看什么 | ② 串口计数 | ③ 需要什么对端 |
| --- | --- | --- | --- | --- |
| BTM Request | `WNM <idx> cand 10 <ch> <STA-MAC>` | `cat=10 act=7 req_mode=0x05 timer=<n>` + Neighbor Report 元素 | `wnmf>0`；能解析并回应的 STA 会让 `wnmresp>0`、`wnms` 有值（1 = reject unspecified） | COM6 跑一个 STA 固件：`CONFIG_ESP_WIFI_11KV_SUPPORT=y`，连接时 `wifi_sta_config_t.btm_enabled=1`，再连上目标 AP。它会在 Assoc Request 里带 Extended Capabilities bit19（本模块据此判定能力），收到 BTM 后触发扫描/漫游。**不支持的 STA 会被 `wnmskip` 跳过，属预期** |
| TIM | `TIM <idx> tim <aid>` / `clear` | 克隆 beacon 的 TIM 元素：`dtim_count=0`、bitmap 按 AID 置位（AID 3 → `08`）；`clear` 模式的 bitmap 应为 `00`。**管道没起时**用 `lab/tim_air.py`（COM6 的 `sniff <ch>`）核对 | `timf>0`、`timreal>0`（说明学到了真 beacon；没学到就一帧都不发）、`timaid` 位图 | 会进 PS 模式且有下行缓存的客户端（手机锁屏 / IoT 设备）。对照 `clear` 与 `tim` 两种模式的唤醒次数/丢包 |
| EAPOL | `EAPOL <idx> 6 <STA-MAC>` | `AAAA03…888E ver=2 type=1/2`，非 QoS 与 QoS(TID6) 交替 | `eapf>0`；**`eaprxreq>0` 才说明 AP 的 802.1X 状态机真的重启**（AP 回 EAP-Request/Identity），`eaprxsta>0` 说明真实 STA 收到了 Logoff | WPA2/WPA-Enterprise 或 802.1X 的 AP。**WPA2-PSK 下这条 AP 完全忽略**，`eaprxreq`/`eaprxsta` 都是 0，属于已知边界 |
| SAE | `SAE <idx> point 50` | `alg=3 seq=1 group=19`，128 字节；AP 的回复是 `alg=3 seq=2 status=…` | `saef>0`、`saeresp>0`、`saecode`（13 = 该 AP 不吃 SAE；76 = 要反 clogging token；`saetok>0` 说明 token 到了、`saeecho>0` 说明回显了） | WPA3-SAE 的 AP。效果判据：拿到 token 回显后，**合法 STA 的 ping RTT 明显上升**。对照组 `SAE <idx> rand 50`（随机元素，AP 在点校验就退），两者 RTT 差异即"贵在哪一步" |
| PM 位欺骗 | `PSPOLL <idx> <STA-MAC> [qosnull\|null\|action]` | 三种帧型各自的帧控制高字节：`0x1148`(Null)/`0x11C8`(QoS Null)/`0x10D0`(Action)，都带 PM=1，`ra=<BSSID> ta=<STA>`。**管道没起时**用 `lab/pspoll_air.py`（另一块板跑 lab 固件的 `ap` + `sniffpoll <ch>`，一块板同时当 AP 与嗅探器，逐帧型统计 PM=1 帧数） | `pspf>0`、`pspfrm`（当前帧型）、`pspnul/pspfl`（PM=1/PM=0 各多少）、`pspdl`（发向受害者的下行帧）；`psprxp` 恒 0 属正常（ESP-IDF 站点按 DTIM 收帧，从不发 PS-Poll） | 一台 AP + 一个真实客户端：`lab/pspoll_ps.py` 量 AP 侧 RATE，三种帧型分别为 −30%/−38%/−21%，撤销后立刻恢复 |
| Auth/Assoc 洪泛 | `AUTHFLOOD <idx> both` | `alg=0 seq=1` 的 Auth + 带目标 SSID/RSN 的 Assoc Request，TA 每帧换随机 MAC | `aff/afa/afs>0`、`afids` 持续增长；**`afst=17` 才是目标（表满）**，13 = 该 AP 不吃开放认证，0 = 竟然接受了；目标是 WPA3 时应看到 `afup=1` 与 `INFO AUTHFLOOD ... -> SAE commit flood` | 一台能看客户端列表/拒绝接入的 AP。合法 STA 对照：它开始连不上即达标 |

**稳定性**：`python lab/soak.py --port COM5 --bssid <AP> --minutes 4` 逐模块长跑，判据是
`STATUS` 的 `txgerr` 恒为 0（`txgok` + `txg` = 想发的帧数），且串口里没有 `FATAL tx 0x101`。

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
一级  [Deauth] [Probe] [CSA]
      [DELBA] [BA] [Evil]
      [WNM] [TIM] [EAPOL]
      [SAE] [Auth] [PS-Poll]
二级  Deauth -> [One] [All] / [Only] [Except] / [Back]
三级  模式页：[Scan] [Targets] [Start] / [Stop] [Back] / [Reason: 7 class-3 frame]
      最后一行是 reason 按钮，直接写着当前值 + 含义（`Reason: 7 class-3 frame` /
      `Reason: random (per burst)`），点它弹出 23 个标准 reason + `random` 的列表（24 行、可滑动），
      点一行即选中并关闭，同时发 `REASON <值>` / `REASON random`
      串口诊断：`UIREASON` 打开该弹窗，`UI` 回报 `rpopup=` / `ritems=`
      点 Targets → 模态弹窗（lv_layer_top 上的卡片）
         pick targets (N) - multi
          [x] 0. HomeWiFi | 8C:AA:.. ch1 -40dB
           >  1. Guest    | 8C:AA:.. ch6 -55dB
         [All] [None] [Back] [OK]
```

- 弹窗里 `One/All` 是单选（`>`），`Only/Except` 是勾选（`[x]`）；`OK` 保存、`Back` 撤销（快照还原）。
- `Start` 按当前模式发 `DEAUTH` / `DEAUTH_ALL` / `DEAUTH_ONLY` / `DEAUTH_EXCEPT`。
- `Probe` 页只有 `Start/Stop/Back`（广播泛洪不需要目标）
- `CSA` 页：`Scan -> Targets -> Start`，不用选信道：`Start` 发 `CSA <idx>`，
  固件按对向频段随机挑信道并循环；标签写着 `CSA #0 TP-LINK -> auto (opposite band)`。
- `DELBA` 页：和 CSA 页同形（`Scan -> Targets -> Start` / `Stop` / `Back`），
  `Start` 固定发 `DELBA <idx> 37`；标签写着 `DELBA #0 TP-LINK reason=37`。
- `BA` 页：同样四键，`Start` 固定发 `BAATTACK <idx> 512`（步进在屏上不可调，串口/GUI 可调）；
  标签写着 `BA #0 TP-LINK step=512`；`UISCREEN ba` 可供自动化切换。
- 六个帧级模块页（`WNM` / `TIM` / `EAPOL` / `SAE` / `Auth` / `PS-Poll`）共用同一个版式：
  一行目标（`WNM #0 TP-LINK`）、`[Scan] [Targets] [Start]`、`[Stop] <变体> [Back]`。
  `Start` 发不带参数的缺省命令（`WNM 0` / `TIM 0` / `EAPOL 0` / `SAE 0` / `AUTHFLOOD 0` / `PSPOLL 0`），
  中间那个变体键发对照形态：`Bare`=`WNM 0 bare`、`Clear`=`TIM 0 clear`、`Plain`=`EAPOL 0 -1`、
  `Rand`=`SAE 0 rand`、`NoAuto`=`AUTHFLOOD 0 both noauto`。PS-Poll 那一页的变体键是**帧型循环**（`QoSNull`→`Null`→`Action`），点一下换一种帧型并重启攻击；撤销 `PSPOLLREL` 与受害 MAC 走串口/GUI。参数细分仍走串口/GUI。
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
5. **DELBA 只吃"有流量的客户端"**：没有在线流量就没有 BA 会话，DELBA 对它无效；
   静默 BSS 里只有广播兜底帧（`delbb=`），效果未验证。
6. **混杂模式是两级过滤，缺一不可**（已修）：`esp_wifi_set_promiscuous_filter()` 的 CTRL 位只表示
   "控制帧这一类要"，`esp_wifi_set_promiscuous_ctrl_filter()` 才决定哪些 subtype 上报，而它的
   默认值丢弃全部控制帧。实测：mask=`0` → `ctrl=0`；mask=`MASK_ALL` → `ctrl=37 rts=10 ba=2 ack=24`
   （`rts=10` 是另一块板注入的 10 帧）。`start_promiscuous()` 现在固定设 `MASK_ALL`，
   想复现"收不到"的状态可以用 `CTRLFILTER none`。
7. **PS-Poll 欺骗不可用（已删除）**：控制子类型 10 的帧**单播**发给 AP 时一帧都上不了空口
   （`CTRLTEST 10 bssid 0xC025` 两轮各 0/10），而同样 16 字节、改成广播 RA 时 10/10 上空气且
   `Duration/ID = 0xC025`（AID 37）原样保留——说明不是字段被改写，而是这条发送路径不通。
   PS-Poll 只有单播才有意义，所以模块里只剩 PM 位那一半。探针留在 `CTRLTEST`。
8. **PM 位帧的节拍是 10 帧/s，不是 20**：三种承载帧（Null/QoS Null/Action）在 20 帧/s 下约 170–400 帧
   （9–20 s）就把短缓存池打满并触发 `FATAL tx 0x101 ... -> restart`；10 帧/s 时 60 s / 600 帧
   零拒收。`pspoll.cpp` 自己把 `kSendMs` 压到 100 ms（`tx_guard` 的 45 ms 间隔挡不住这个）。
9. **`SCAN` 之后立刻开打会打到"错误信道"**：扫描收尾时 STA 会拒绝 `esp_wifi_set_channel()`，
   而模块只把返回值丢掉了——现象是"计数器在涨、空口一帧没有"。现在 `PSPOLL` 的回执里带
   `chset=`，非 0 时再打一行 `WARN`；复现脚本先用 `MON <ch> 2` 把信道钉住。
10. **单播注入的可持续速率约 20 帧/s（固件已强制）**：`0x101` 是**我们自己的**驱动拒发
   （缓存池空了），不是 AP 拒绝。伪造 TA 的单播帧拿不到"属于自己的"ACK（AP 回的 ACK 目标是伪造的
   MAC，本芯片不认），硬件会重传到重试上限才释放缓存；同时我们从不 ACK AP 的回复，AP 也在反复
   重发（实测每条 commit 对应 **12.7 个** AP 回复）。结果是 20 帧/s 的注入在空口上造成约
   **220 帧/s** 的实际负载，每个缓存被占用整段时间。广播帧相反：不需要 ACK、也没人回，缓存立刻回收
   （克隆 beacon 50 帧/s 跑 3000 帧零拒收）。
   把池子当漏水桶拟合（排水 ≈32 帧/s、容量 ≈22）与实测完全吻合：50 帧/s → 63 帧 `0x101`；
   40 帧/s → 117 帧 `0x101`；30 / 20 帧/s → 45 s 各 1350 / 900 帧零拒收。
   精确的占用时长**不可观测**（`esp_wifi_register_80211_tx_cb()` 对注入帧不回调、抓包管道会丢帧），
   所以上面是曲线证据，不是秒表读数。
   守卫（`tx_guard.cpp`）自己做这件事：单播两帧之间至少 `TX_GUARD_UNICAST_GAP_MS = 45` ms，
   被挡下的帧计 `txg=`（不算错误、不算发送）；`SAE` 的 `gap_ms` 小于 50 会被抬到 50 并打 `INFO`。
   所以任何参数组合都推不爆池子。
   **稳定性判据**（`lab/soak.py`）：跑守则期间 `STATUS` 的 `txgerr` 必须恒为 0
   （`txgok` 是被驱动接受的帧数、`txg` 是被整流器挡下的帧数，两者之和才是"想发的帧"），
   并且串口里不能出现 `FATAL tx 0x101`。长时间压测结果见 `测试报告.md §4.4.5`。
   **覆盖范围**：五个新模块 + `CSA`（含 HOLD 阶段的 auth/assoc 应答）都走这个守卫。
   `DELBA` / BA 会话劫持 / deauth 仍用各自的 `esp_wifi_80211_tx` 封装：实测它们的长跑速率本来就在
   19–25 帧/s（排水速率以下），而且 BA 的节拍（40 ms）是已记录的 -99% 吞吐实验的前提，动它就得
   重跑那个实验，所以先不改；它们在 `0x101` 上的行为是"计一次错、下一轮重试"，不会重启或卡死。
   `BARSEQ` 这类故意打空池子的诊断探针永远留在守卫之外。
11. **beacon 的 TSF 上不了空口（TSF 投毒因此已删除）**：MAC 用接口自己的 TSF 覆盖 beacon 的
   24..31 字节（未关联 STA 时为 0）。实测 `last_tsf=654632723879`（交给驱动的值）vs 空口 `tsf=0`，
   而同一帧的 TIM/SSID/interval/capability 逐字节保留。与第 1 条（Duration）同源的驱动字段重写，
   所以 `tsf`/`both` 两个模式与 `ttsf=` 字段在 2026-11 一并删除，`TIM` 只做 TIM。
12. **`STATUS` 一行约 1.1 KB**：五个新模块各带一组计数器，115200 下机器读到完整一行要 ~80 ms
   （`tests` 的 STATUS 往返用例阈值因此从 60 ms 放宽到 120 ms）。这是串口带宽，不是固件变慢。

第 1、2 条已记入[待修清单](测试报告.md#71-待修清单已记录尚未动手)（当前只记录，未动手）。
UART 丢行已修复：`Serial.setRxBufferSize(4096)`（`SERIAL_RX_BUFFER_SIZE`），300 条 PING 洪泛实测 300/300 响应。

