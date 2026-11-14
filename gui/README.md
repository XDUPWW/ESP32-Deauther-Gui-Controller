# 上位机 gui（Windows / tkinter）

配套固件：[`../firmware`](../firmware)。这个程序只做两件事：
**把界面上的操作翻译成协议行**，**把固件回来的行解析成界面状态**。攻击逻辑全在固件里。

- 纯 Python，依赖只有 `pyserial`（tkinter 是标准库自带的）
- 协议解析在 `protocol.py`（纯函数，可单测），界面在 `main.py`

---

## 1. 运行

```powershell
cd gui
pip install -r requirements.txt
python main.py                 # 启动后选串口
python main.py --port COM5     # 启动即连接
python main.py --self-test     # 只建界面然后退出（CI 冒烟）
```

串口固定 **115200 8N1**。连接时故意不拉低 DTR/RTS，否则 CH340 会把 ESP32 按在复位或下载模式里。

---

## 2. 界面结构

一级是**攻击方式/功能**；二级是 Deauth 的四种模式；这些模式页本身就是工作页——
扫描、选目标（弹窗）、开始、停止、统计都在一处。

```
一级  [Deauth 攻击] [Probe 攻击] [CSA 欺骗]
      [DELBA 欺骗]  [BA 会话攻击] [Evil Twin] [设备状态] [日志]

二级  Deauth 攻击 -> [单个 AP] [全部 AP] [只打勾选] [排除勾选]

三级  Deauth · 只打勾选
      [扫描 AP] [选择目标…]   共 21 个 AP  已勾选 2：0,2
      reason：[1 - Unspecified] 或自定义：[   ]   [开始攻击] [停止]
      每 AP 发包数（STATS）[刷新]
```

`← 返回` 回上一级（模式页 → Deauth 菜单 → 主菜单）。

### 2.1 选择目标（弹窗）

点 `选择目标…` 弹出模态窗口：

```
┌─────────── 选择目标 AP（勾选，可多选）───────────┐
│ 过滤 SSID：[        ] [重新扫描]  共 21 个 AP     │
│  选    #   SSID        BSSID       频段 信道 RSSI │
│  ✓     0   HomeWiFi    8C:AA:...   2.4G   1  -40 │
│        1   Guest       8C:AA:...   2.4G   6  -55 │
│  ✓     2   Cafe        8C:AA:...   2.4G  11  -70 │
│ 已勾选 2 个：0,2                                  │
│ [全选] [清空] [反选]                [取消] [确定] │
└──────────────────────────────────────────────────┘
```

- **双击一行** = 勾选/取消；单选模式下双击直接确定
- 点行首“选”列 = 勾选（多选）；单选模式点行 = 选中
- `过滤 SSID` 边打边过滤（SSID 或 BSSID，不区分大小写）
- `重新扫描` 不用关窗口，扫完就地刷新
- `全选 / 清空 / 反选` 只作用于**当前过滤出来的行**

### 2.2 各模式的映射

| 模式 | 弹窗模式 | 选择结果 | 发出的命令 |
| --- | --- | --- | --- |
| 单个 AP | 单选 `●` | 一个 AP | `DEAUTH <idx> <reason>` |
| 全部 AP | 不用选 | 全部 AP | `DEAUTH_ALL <reason>` |
| 只打勾选 | 多选 `✓` | 白名单 | `DEAUTH_ONLY 0,2 <reason>` |
| 排除勾选 | 多选 `✓` | 黑名单 | `DEAUTH_EXCEPT 0,2 <reason>` |
| Evil Twin | 单选 `●` | 一个 AP | `EVILTWIN <idx>` |

### 2.6 reason code

下拉框里除了预设值，还有两项：

| 选项 | 行为 |
| --- | --- |
| 预设 / `custom - 自定义` | 发固定值：`DEAUTH ... <n>`。选了"自定义"就必须在右侧输入框填 `1..65535` |
| `random - 每次随机` | 发 `DEAUTH ... random`，固件每束从标准定义值（1–11、13–24）里重掷一个 |

防呆规则：

- 空值、非整数、`0`、负数、`>65535` → 弹错误框并**不发送**命令（不会像早先那样静默按 1 处理）
- 用了标准集合外的值（比如 99）→ 先弹确认框说明"客户端可能忽略"，确认后才发
- 底栏会显示固件当前的 `reason：`（`random` 模式显示 `random`，实际值看 `STATUS` 的 `rlast=`）

底栏另外还有 `模式 / Deauth 帧 / Probe 帧 / 网络数 / 堆 / 双频(5G)`，攻击中每 2 秒自动拉一次 `STATS`。

### 2.3 CSA 欺骗

`CSA 欺骗` 页：`扫描 AP` → `选择目标…`（单选）→ `开始 CSA`。**不用选信道**：

- 2.4G 的 AP 会被通告到一个随机 5G 信道；5G 的 AP 反之
- 每轮（5 轮 countdown ≈ 0.5 s + 新信道顶 5 s 克隆 beacon）结束后自动开始下一轮，循环到 `停止`
- 命令：`CSA <idx>`，`停止` 发 `CSASTOP`；底栏显示 `CSA：idle/announce/hold (帧数)`

想指定信道做单次播报仍可用串口：`CSA <idx> <ch> [count] [hold]`。

### 2.4 DELBA 欺骗

`DELBA 欺骗` 页：`扫描 AP` → `选择目标…`（单选）→ 选 reason → `开始 DELBA` / `停止`。

- 命令：`DELBA <idx> <reason>`，停止发 `DELBASTOP`
- reason 下拉只给真实对端会用到的 5 个值（37 缺省：`37 - 不再使用该机制`），
  填了别的值固件会直接回 `ERR`（这是有意为之：非法 reason 的 DELBA 会被驱动丢掉）
- 底栏显示 `DELBA：on/off (帧数 / TID 位图)`，`设备状态` 页另外给出
  `delbac`（学到的客户端数）、`delbab`（收到的 ADDBA）、`delbtr`（按 ADDBA 精确补刀次数）
- 这一页不需要选信道：攻击板会停到目标 AP 的信道上去

攻击会持续到点 `停止`；期间被攻击的客户端**不会掉线**，只是吞吐量塌到单帧确认
（实验室实测 -99%，见 [固件测试报告](../firmware/测试报告.md)）。

### 2.5 BA 会话攻击

`BA 会话攻击` 页：`扫描 AP` → `选择目标…`（单选）→ 选 SN 步进 → `开始 BA 攻击` / `停止`。

- 命令：`BAATTACK <idx> <step>`，停止发 `BASTOP`
- 步进下拉：`512 / 256 / 1024 / 2047 / 0（对照组，SSN 不推窗口）`；越界值在界面侧就拦住
- 底栏显示 `BA：on/off (BAR 帧数 / 最后写入的 SSN)`；`设备状态` 页另有
  `baaddba`（ADDBA 帧数）、`badlba`（DELBA 帧数）、`baerr`（驱动拒收帧数）
- 实验室结论：只发 2 帧伪造 ADDBA 就能让该 TID 冻结且不自愈（需重新关联）；
  "窗口被推走"这一步未单独证明（见 [测试报告](../firmware/测试报告.md)）

### 2.6 Probe 攻击

只有一种：`开始泛洪` → `PROBE_BROADCAST`（**不需要扫描**，广播泛洪与环境无关）。
固件持续广播 Beacon（子类型 8）+ Probe Response（5），SSID/BSSID 全随机，每 120 ms 跳信道。
帧数看底栏 `Probe 帧：`。

### 2.4 设备状态 / 日志

- 设备状态：`STATUS` 的逐字段展示（模式、帧数、网络数、堆、`caps`、信道、`rx/rxm`）
- 日志：带时间戳的分色输出（`>>` 是本机发出的命令，红色是 `ERR`/捕获到的凭据）

### 2.5 底栏

`模式 / Deauth 帧 / Probe 帧 / reason / 网络数 / 堆 / 双频(5G)`，攻击中每 2 秒自动拉一次 `STATS`。

---

## 3. 代码结构

| 文件 | 职责 |
| --- | --- |
| `main.py` | 串口收发线程、三级菜单、目标弹窗、STATS/状态渲染 |
| `protocol.py` | `classify()` 行分类 + `parse_net/parse_status/parse_cred/parse_caps`（纯函数，无 Tk 无 IO） |
| `requirements.txt` | `pyserial` |

加新功能时的顺序建议：先在 `protocol.py` 里加解析 + 单测，再在 `main.py` 里加控件。

---

## 4. 注意事项

- 列表序号只在最近一次扫描内有效；重扫会清空勾选与单选（固件里也是这个语义）。
- `打全部 AP`、`Evil Twin` 会弹确认框，请只在自有网络上使用。
- 固件没有 `ui=` 能力位或 `caps` 里没有 `eviltwin` 时，对应按钮会自动禁用。
- 协议细节见 [`../firmware/README.md`](../firmware/README.md#4-串口协议)。
