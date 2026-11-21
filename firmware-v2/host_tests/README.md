# host_tests

在 PC 上跑的单元测试，验证帧构造与 IE 解析，不需要硬件。

- `mock_hal/`：驱动接口的桩，记录发送次数与帧字节
- `test_frames.c`：各帧型的字节比对
- `test_ie.c`：元素解析用例
- `run.sh`：直接调用系统编译器
