set(board_srcs "src/board_cyd.c")
set(board_priv "")

if(CONFIG_WB_BOARD_CYD)
    list(APPEND board_srcs
        "src/board_cyd_lcd.c"
        "src/board_cyd_touch.c"
    )
    # 面板驱动只在真的要用这块板时才拉进来
    list(APPEND board_priv esp_lcd esp_lcd_ili9341)
endif()

idf_component_register(
    SRCS ${board_srcs}
    INCLUDE_DIRS "include"
    REQUIRES platform esp_driver_gpio esp_driver_spi
    PRIV_REQUIRES ${board_priv}
)
