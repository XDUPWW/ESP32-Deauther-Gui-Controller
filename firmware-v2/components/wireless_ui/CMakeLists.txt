set(ui_srcs "src/wireless_ui_stub.c")
set(ui_reqs platform transport)

if(CONFIG_WB_LVGL)
    set(ui_srcs
        "src/wireless_ui.c"
        "src/ui_port.c"
        "src/ui_calib.c"
        "src/ui_home.c"
        "src/ui_touch_cal.c"
    )
    list(APPEND ui_reqs lvgl esp_lvgl_port esp_lcd)
endif()

idf_component_register(
    SRCS ${ui_srcs}
    INCLUDE_DIRS "include"
    REQUIRES ${ui_reqs}
    PRIV_REQUIRES esp_timer
)
