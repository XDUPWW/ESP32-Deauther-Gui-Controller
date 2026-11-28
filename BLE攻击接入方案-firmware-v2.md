# BLE 攻击接入方案（firmware-v2 路线）


## 0. 定论

落点就一个：firmware-v2/。理由不是偏好，是现状——hal_ble（NimBLE 初始化/随机地址/广播/扫描/GATT NUS）、ble_frame（AD Structure 构造、地址工具）、services/ble_object.c（ble.info/addr/adv/scan）、transport/ble_text.c（手机 BLE 控制通道）都已经能跑；缺的只有载荷模板库 + 轮换引擎 + 攻击对象。legacy firmware/ 里没有 BT 栈，往里加要同时碰 Arduino WiFi 共存、IRAM 和内存预算，不做。

两个能力合成一个模块、两种模式：泛洪和弹窗共用同一套"停广播 → 换地址/换载荷 → 再开广播"的轮换引擎，差别只在载荷来源。这样只加一个对象、一张表、一条 UI 规则。


## 1. 平台事实（先钉死，后面所有设计都从这里长）

| 事实 | 影响 |
| --- | --- |
| 经典 ESP32 只支持 BLE 4.2 legacy 广播，AD 数据 31 字节封顶 | 弹窗模板必须 ≤31 字节；放不下就得走扫描响应 |
| C5 是 BLE 5.0，但 sdkconfig.c5 里 CONFIG_BT_NIMBLE_EXT_ADV 没开 | 本期只做 legacy；扩展广播留 P7 |
| hal_ble.h 里 HAL_BLE_ITVL_MIN=160（100ms），注释写"规范下限 100ms" | 注释是错的：Core Spec Vol 6 Part B §4.4.2.2 的下限是 20ms（HCI 0x0020）。100ms 只是控制通道的保守值，进攻线要能传 32 |
| NimBLE/控制器要求：改随机地址前必须停广播 | 一次轮换 = stop → set addr → set data → start，四步必须原子 |
| attacks_tick 周期 50ms | 轮换上限 20 次/s；空口实际广播率 = 1000/itvl（itvl=20ms → 约 2.5 个广播事件/轮换） |
| GATT NUS 在开机后就占着广播（ble_text.c 懒启动） | 需要广播占用仲裁，否则攻击和手机控制通道互相改数据 |
| Wi-Fi 与 BLE 共用 2.4G 射频，CONFIG_ESP_COEX_SW_COEXIST_ENABLE=y | 泛洪会拖慢 Wi-Fi 注入，反之亦然，必须标定 |
| 经典 ESP32 控制器固定预留 55KB DRAM，BTDM_CTRL_BLE_MAX_CONN=1 | 攻击对象静态区控制在 1–2KB；受害设备点"连接"会占掉唯一连接槽 |
| 弹窗是否出现取决于 OS 版本、屏幕状态和厂商限流 | 结论只能写"在 X 版本上观测到/未观测到"，不能写"必然弹" |

## 2. 分层与文件


```text
transport（串口 / LVGL / BLE NUS）
        ↓
wbus  ←  attacks/blespam（对象：start/stop/test/list）
        ↓
attacks/blespam.c（轮换状态机、计数、广播占用者）
        ↓
ble_frame/payload（模板 → AD Structure，纯 C，可主机测）
        ↓
hal_ble（唯一碰 NimBLE 的地方：地址/广播/扫描/仲裁/GATT）
```

新增：

| 文件 | 内容 |
| --- | --- |
| components/ble_frame/include/ble_frame/payload.h | 模板结构体、渲染 API、平台枚举 |
| components/ble_frame/src/payload.c | 模板表、bf_payload_render()、bf_payload_find/list |
| components/attacks/blespam/blespam.c | blespam_start/stop/tick/frames/active、随机地址与名称生成、计数 |
| components/attacks/blespam/blespam_object.c | wbus 对象 blespam：参数策略、回执、test hex dump |
修改：

| 文件 | 改动 |
| --- | --- |
| components/hal_ble/include/hal_ble/hal_ble.h + src/hal_ble.c | 广播占用仲裁、原子轮换、扫描响应、计数器、间隔下限常量 |
| components/ble_frame/include/ble_frame/adv.h + src/adv.c | 补 BF_AD_SERVICE_DATA16 (0x16) 与 bf_adv_service_data16()（Fast Pair 要用） |
| components/attacks/CMakeLists.txt | 加两个 SRCS；REQUIRES 增加 ble_frame hal_ble |
| components/attacks/include/attacks/attack.h + src/attacks.c | 声明并注册 blespam_attack() |
| components/wireless_ui/src/ui_home.c | build_ble() 增加攻击格子；build_wifi() 跳过 name 以 ble 开头的对象，避免 BLE 攻击混进 WiFi 页 |
| components/transport/src/plugins/ble_text.c | blespam.stop 释放仲裁后，poll 里重新拉起 GATT 广播 |
| AGENTS.md §4.1 层白名单 | attacks 允许的依赖加 ble_frame hal_ble |
| host_tests/、tools/selftest.py、tools/aircheck.py | 载荷字节用例、板端回执用例、空口观察段 |
| firmware-v2/README.md、components/attacks/README.md、docs/adding-an-attack.md | 对象与方法补进清单 |

## 3. HAL 改造（签名先定，实现按这个写）


```c
// 广播占用者：console / gatt / blespam 三方互斥，抢不到返回 ESP_ERR_INVALID_STATE
esp_err_t   hal_ble_adv_claim(const char *owner);
void        hal_ble_adv_release(const char *owner);
const char *hal_ble_adv_owner(void);


```c
// 一次原子轮换：stop → addr? → adv data → scan rsp? → start，全在 host 任务里做完
typedef struct {
    const uint8_t *addr;      // NULL = 不换地址
    const uint8_t *adv;  size_t adv_len;
    const uint8_t *rsp;  size_t rsp_len;   // NULL = 不设扫描响应
    uint16_t itvl;            // 0.625ms 单位，0 = HAL_BLE_ITVL_HCI_MIN
    bool     connectable;
} hal_ble_adv_cycle_t;

esp_err_t hal_ble_adv_cycle(const hal_ble_adv_cycle_t *c, uint32_t *took_us);
esp_err_t hal_ble_scan_rsp_set(const uint8_t *data, size_t len);
```

hal_ble_stats_t 追加：adv_cycles、cycle_errors、last_cycle_us、addr_rotations、data_rotations、conn_refused、claim_denied、scan_upserts、scan_full_drops。最后两个是给观察端用的——扫描表只有 32 条，没有丢弃计数就会重演 hexdrop 那种"看起来零命中"的误导。

常量修正：


```c
#define HAL_BLE_ITVL_HCI_MIN 32     // 20ms，Core Spec Vol 6 Part B §4.4.2.2
#define HAL_BLE_ITVL_DEFAULT 160    // 100ms，保持 console/GATT 的现状
```

实现要点只有三条：OP_ADV_CYCLE 走现有 job 队列（约 2KB 静态区，4 个 job 各带 255B 缓冲）；连接事件在 gap_event 里判断 owner 是 blespam 时立即 ble_gap_terminate() 并计 conn_refused（受害设备点弹窗不能真建连，也不能占掉唯一连接槽）；hal_ble_adv_start 保持旧行为，攻击只走 hal_ble_adv_cycle。


## 4. 载荷模板库


```c
typedef enum { BF_PLAT_APPLE, BF_PLAT_SAMSUNG, BF_PLAT_GOOGLE, BF_PLAT_MICROSOFT, BF_PLAT_OTHER } bf_platform_t;

typedef struct {
    const char    *name;        // "apple_airpods"
    bf_platform_t  platform;
    uint16_t       company_id;  // 0x004C / 0x0075 / 0x0006；Fast Pair 填 0
    uint16_t       service_uuid;// 0 = 厂商数据；0xFE2C = Fast Pair
    const uint8_t *body;        // 已去掉 AD 头和公司 ID
    uint8_t        body_len;
    bool           scan_rsp;    // true = 载荷放扫描响应
    bool           connectable; // 模板建议的广播类型
} bf_payload_t;

size_t bf_payload_count(void);
const bf_payload_t *bf_payload_at(size_t i);
const bf_payload_t *bf_payload_find(const char *name);
bool bf_payload_render(const bf_payload_t *tpl, bf_adv_t *set, bool with_flags);
```

模板族（字节按公开的 Continuity / Fast Pair / SwiftPair 协议文档填，逐版本核对后再入库）：

| 模板族 | AD 容器 | 标识 | 目标端 UI |
| --- | --- | --- | --- |
| apple_airpods / apple_beats | Manufacturer Specific 0xFF | 公司 ID 0x004C，Continuity type 0x07 | iOS/macOS 靠近配对卡片 |
| apple_tv / apple_homepod | Manufacturer Specific | 0x004C，Continuity type 0x0F | 设置助理卡片 |
| apple_airtag | Manufacturer Specific | 0x004C，type 0x12 | Find My 相关提示（不一定弹窗） |
| samsung_buds | Manufacturer Specific | 公司 ID 0x0075 | Galaxy 手机 Buds 弹窗 |
| google_fastpair | Service Data 16-bit 0x16 | UUID 0xFE2C + model ID | Android "附近设备" 通知 |
| microsoft_swiftpair | Manufacturer Specific | 公司 ID 0x0006 | Windows 10/11 "新设备" toast |
离线判据（host_tests）：每个模板渲染后逐字节对 fixture、adv 与 scan_rsp 各自 ≤31、公司 ID 小端、find 对未知名字返回 NULL。这一层不过，后面所有实验都不做。


## 5. 攻击模块

blespam.c 的状态机：

flood：每轮换随机 static 地址（bf_addr_random_static）+ 生成名称（或空名）+ Flags，rotate=addr。
popup：每轮换模板载荷，rotate=data；rotate=both 时地址也换，用来试"换 MAC 能否绕过 OS 限流"。
mix：模板表轮询，给"哪种载荷最有效"的粗筛用。
周期由 cycle（默认 50ms，20–1000）控制，广播间隔由 itvl（默认 20ms）控制；两者分开，才能测"轮换率"和"广播率"各自的影响。
计数：cycles/cycle_err/addr_rot/data_rot/conn_refused/claim_denied，frames() 返回 cycles。
对象（blespam_object.c）：


```text
blespam.start [mode=flood|popup|mix] [template=<name>] [itvl=20] [cycle=50] [rotate=addr|data|both] [connect=1]
blespam.stop
blespam.test  [mode=...] [template=...] [itvl=20] [rotate=...] [connect=1]   →  hex + 长度 + 是否放得下
blespam.list                                                               →  模板名/平台/容器
```

回执示例：


```text
OK blespam flood cycle=50ms itvl=20ms rotate=addr
OK blespam popup template=apple_airpods len=28 connect=1
ERR blespam.start: template must be one of apple_airpods,..., see blespam.list
```

对象不填 title，改为在 build_ble() 里按名字前缀 ble 列格子；build_wifi() 同步跳过这些对象。这样 BLE 攻击只出现在 BLE 页，WiFi 页的格子仍由现有 10 个攻击组成。


## 6. 命令与计数契约

ble.info 追加一行：adv_cycles=… cycle_err=… last_cycle_us=… addr_rot=… data_rot=… conn_refused=… claim_denied=…
观察端：ble.scan action=start duration=15000 / action=list / action=stop，scan_reports 增量就是广播率，列表 hex 用来逐字节核对。
STOP 语义：attacks_stop_all() 已经会调每个 active 模块的 stop()，blespam.stop 释放仲裁；ble_text 的 poll 发现 owner==NULL && !adv_running 时重新拉起 GATT 广播。

## 7. 实验路线


### P0 平台标定（半天）

hal_ble_adv_cycle 落地后，串口跑 1000 次轮换，记 last_cycle_us 与 adv_cycles。判据：轮换耗时稳定、cycle_err=0、heap 无持续下降。同时用 ble.adv itvl=20 验证 20ms 被控制器接受（现在会被 HAL_BLE_ITVL_MIN 抬到 100ms）。



### P1 载荷离线（1 天）

host_tests 新用例：模板 fixture、31 字节边界、scan_rsp 拆分、未知模板报错。判据：sh host_tests/run.sh 全绿。能证明：字节按设计生成；不能证明：空口上真长这样。



### P2 空口可见性（半天）

CYD（COM5）跑 blespam.start mode=flood，第二块板（COM7 或刷 v2 的 C5）跑 ble.scan，10s 窗口；再换 mode=popup。判据：观察端 hex 与 blespam.test 一致、scan_reports 明显增长、地址在轮换、停手 1s 内归零。拿不到一致 hex 就停下查控制器改写，不进入效果测试。



### P3 泛洪效果（1 天）

四臂交替：关 / 固定地址 / 每轮换地址 / 每轮换地址+名称。每臂 60s × 3 轮。指标：观察端 reports/s、scan_full_drops、受害手机扫描列表条目数、UI 卡顿（人工）、10 分钟耗电（系统电池页，粗测）。判据：换地址臂的列表污染显著高于固定地址臂；固定地址臂用来分离"空口占用"和"列表污染"两个机制。



### P4 弹窗矩阵（1–2 天）

受害设备只用自有：iPhone（记 iOS 版本）、Android（记厂商/版本）、Win11（SwiftPair 通知开启）。变量：模板、connectable、itvl（20/50/100）、rotate（固定/换地址）、屏幕状态（锁屏/解锁/设置页）、距离（0.5/2/5m）。指标：首次弹窗时延 T_first、60s 内弹窗次数、第几次爆发后被 OS 抑制、conn_refused（有没有人点连接）。对照：同长度随机 body、公司 ID 置零、别的平台模板。判据：至少一个平台模板在 1m 内 5s 出现弹窗，且 STOP 后不再出现；若某版本不弹，结论写"该版本未观测到"，并记录屏幕状态与是否被限流，不写"机制无效"。



### P5 共存（1 天）

Wi-Fi 侧用 deauth.start idx=N 跑 60s（约 20 帧/s），BLE 关 vs 泛洪；指标 radio.info 的收发计数与 system.info 堆。反向再测：Wi-Fi 攻击期间 BLE 观察端的 reports/s。判据：给出"BLE 泛洪让 Wi-Fi 注入帧率下降 X%"和"Wi-Fi 攻击让 BLE 广播率下降 Y%"两组数字，作为操作包线；X 超过预设阈值（建议 30%）就把两者写成互斥能力，不硬凑同时跑。



### P6 收尾（半天）

10 分钟浸泡：堆稳定、无 WDT、cycle_err 不增长；STOP 后 GATT 控制通道能恢复；确认开机不自启任何攻击。报告写进 firmware/测试报告.md 新一节（v2 编号自己定），附模板矩阵与失败版本。



## 8. 判停标准


### P1 有模板放不进 31 字节，且扫描响应也放不下 → 该模板下线，不做 C5 扩展广播绕路（P7 再说）

。

P2 hex 不一致 → 先查控制器是否改写 Flags/公司 ID，不改就停，不进入效果测试。
P3 换地址臂与固定地址臂无差异 → 泛洪的"列表污染"机制不成立，只保留空口占用结论。
P4 所有平台、所有模板都不弹，且对照组行为相同 → 结论写"当前 OS 版本未观测到弹窗"，停止调参；不把"没弹"解释成"载荷一定错"。
P5 共存跌幅超过包线 → 两个能力标成互斥，不为了"同时开"调参数。
任何阶段出现 conn_refused 之外的连接建立 → 立即停，查连接终止路径。

## 9. 提交拆分与工期

| 提交 | 内容 |
| --- | --- |
| feat(ble): HAL 增加广播占用仲裁与原子轮换 | hal_ble.{h,c} + 计数器 + 间隔常量 |
| feat(ble_frame): AD 模板库与 Service Data 构造 | payload.{h,c}、adv.{h,c}、host tests |
| feat(ble): 广播泛洪与弹窗模板攻击模块 | attacks/blespam/*、注册、CMake、UI BLE 页 |
| test(ble): 载荷字节与板端回执用例 | selftest.py、aircheck.py |
| docs(ble): 实验矩阵与共存标定数据 | 报告 + README + AGENTS 白名单 |
总量约 5–6 个工作日，其中实验占一半。不要把 P3/P4 的长时泛洪写进 unittest——按仓库纪律，长跑放 lab/ 或 tools/，人工执行。


## 10. 第一步

从 P0 开始，改动最小、可回退：先改 hal_ble.h 的间隔常量与 hal_ble_stats_t，再实现 hal_ble_adv_claim/release/owner 和 hal_ble_adv_cycle，用 blespam.test 之前的临时命令（ble.adv raw=... itvl=20）在 COM5 上量轮换耗时。这一步不碰攻击表、不碰 UI，编译和回执都不变，selftest.py 应该零差异通过。

如果这一步的数字（轮换耗时、20ms 是否被接受、堆余量）不达标，后面所有"每秒多少个唯一 MAC"的估算都要重算——所以它是整条路线唯一的硬前置。
