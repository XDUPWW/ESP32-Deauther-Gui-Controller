# board_cyd

ESP32-2432S028R（CYD，俗称“廉价彩屏板”）的屏幕与触摸后端。

| 部件 | 总线 | 引脚 |
| --- | --- | --- |
| ILI9341 | SPI3 | MISO12 MOSI13 SCLK14 CS15 DC2 RST-1，背光 GPIO21 \| 320x240 |
| XPT2046 | SPI2 | MOSI32 MISO39 SCLK25 CS33 \| 独立总线，没有 PENIRQ |

对外只有一个函数：

```c
const plat_display_ops_t *board_cyd_display_ops(void);   // 关掉 WB_BOARD_CYD 时返回 NULL
```

`main.c` 起来后 `plat_display_bind(board_cyd_display_ops())` 一次，`platform` 就把
`plat_lcd_init` / `plat_touch_read` 这些转发到这里。

## 为什么单独一个组件

- 面板驱动（`esp_lcd_ili9341`）只在这里声明，不支持这块板的芯片根本不会被拉进来；
  UI 层因此可以跨芯片编译。
- 屏幕旋转（`swap_xy` / `mirror_x` / `mirror_y`）是板子属性，通过 `plat_lcd_t` 交给
  `wireless_ui`，UI 里不再写死。
- 关掉 `CONFIG_WB_BOARD_CYD` 只编 `board_cyd.c`（返回 NULL），固件照常跑，无屏。

触摸的原始值映射不在这里做。XPT2046 给的是 0..4095 的 ADC 值，转屏幕坐标靠
`wireless_ui` 里的四点校准（`ui.touch_cal`），结果存 NVS。
