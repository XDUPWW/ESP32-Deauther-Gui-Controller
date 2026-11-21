# platform

与射频、与具体屏幕都无关的板级底座。

- `plat_console`：UART0 控制台
- `plat_display`：显示/触摸的**接口**，本身不实现面板
- `plat_storage`：flash 键值存储（注入速率、触摸校准）
- `plat_led`：状态灯

## 显示与触摸是接口，不是实现

`plat_display.h` 里定了四个函数和一张 `plat_display_ops_t` 表：

```c
plat_display_bind(&some_board_ops);   // 谁有屏谁绑，没绑就是无屏
plat_lcd_init(&lcd);                  // 拿 panel/io/分辨率/旋转
plat_lcd_backlight(true);
plat_touch_init();
plat_touch_read(&raw_x, &raw_y);
```

`platform` 只做转发，没 bind 时 `plat_lcd_init()` 返回 `ESP_ERR_NOT_SUPPORTED`。
具体面板在板级组件里，例如 `components/board_cyd/`（ILI9341 + XPT2046）。

换板子接屏：复制一份 `board_cyd`，把这四个函数对着自己的面板写一遍，实现
`board_xxx_display_ops()`，再在 `main.c` 里 bind 掉那一行。

边界：不含无线概念，不依赖任何攻击模块，也不依赖 LVGL。
