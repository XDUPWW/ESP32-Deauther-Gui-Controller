# wifi_frame

802.11 帧的字节层：构造与解析。

职责：

- 构造管理帧、控制帧、数据帧（deauth、beacon、action、EAPOL 数据帧、BAR、auth 等）
- 解析元素：RSN（AKM/MFPR）、Extended Capabilities、TIM、CSA、Block Ack
- 提供帧结构体定义

接口：`include/frame_build.h`、`ie_parse.h`、`frames.h`。

边界：纯 C，无驱动、无打印、无节拍；可脱离硬件在 PC 上编译与单测。
