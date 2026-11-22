# attacks

各类无线攻击。每种攻击一个目录，一个 `.c` 里同时放攻击行为和总线对象。

已实现（目录名就是总线对象名，命令写成 `对象.方法`）：

| 目录 | 干什么 | 主要命令 |
|---|---|---|
| `deauth` | deauth / disassoc 洪泛，多 AP 轮跳信道 | `deauth.start` `deauth.all` `deauth.list` `deauth.stop` |
| `probe` | 假 AP 洪泛（beacon + probe response） | `probe.start` `probe.stop` |
| `csa` | 克隆 beacon / Spectrum action 公告换信道 | `csa.start` `csa.stop` |
| `delba` | 伪造 DELBA 拆聚合会话 | `delba.start` `delba.stop` |
| `ba` | ADDBA 种窗口 + BAR + DELBA 三件套 | `ba.start` `ba.stop` |
| `eapol` | EAPOL-Start / Logoff 洪泛 | `eapol.start` `eapol.stop` |
| `authflood` | Auth / Assoc 洪泛，WPA3 目标可转 SAE | `authflood.start` `authflood.stop` |
| `sae` | SAE Commit 洪泛，回显 anti-clogging token | `sae.start` `sae.stop` |

每个模块都有 `<对象>.test`，不发射，只 dump 组出来的帧字节。

`tim` 不做了；PS-Poll 那条路换成了单播 QoS Null，见 `qosnull/`。

公共件：

- `src/attack_common.c`：目标表查询（`idx` 就是 `scan.list` 显示的序号，从 1 开始）、
  射频独占、信道租约、速率统计、SAE Commit 组帧
- `include/attacks/attack.h`：模块描述符 `attack_driver_t` 和注册表
- `src/attacks.c`：唯一的注册清单

模块边界：只调 `hal_wifi_tx` 发帧，不直接碰驱动；组帧全部走 `wifi_frame`。
