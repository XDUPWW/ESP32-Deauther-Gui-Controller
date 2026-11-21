# attacks

各类无线攻击。每种攻击一个目录，包含策略、节拍、计数器和总线对象声明。

目录：

`deauth`、`probe`、`csa`、`delba`、`ba`、`wnm`、`tim`、`eapol`、`pspoll`、`sae`、`authflood`、`evil_twin`，
外加 `common`（reason code 池、目标视图）与 `include/attack.h`（攻击契约）。

每个目录的结构：

- `<name>.cpp`：攻击行为、节拍、计数
- `<name>_object.cpp`：总线对象声明（方法、参数、事件）
- `frames_<name>.cpp`：该攻击独有的组帧

`src/registry.cpp` 是唯一的注册清单。

边界：不直接操作驱动、不打印、不自己拼字节。
