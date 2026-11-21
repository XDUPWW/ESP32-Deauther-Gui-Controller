set(ui_srcs "src/wireless_ui_stub.c")
if(CONFIG_WB_LVGL)
    set(ui_srcs
        "src/wireless_ui.c"
        "src/ui_port.c"
        "src/ui_calib.c"
        "src/ui_home.c"
    )
endif()

idf_component_register(
    SRCS ${ui_srcs}
    INCLUDE_DIRS "include"
    REQUIRES platform transport lvgl esp_lvgl_port esp_lcd_ili9341
    PRIV_REQUIRES esp_lcd esp_timer
)
