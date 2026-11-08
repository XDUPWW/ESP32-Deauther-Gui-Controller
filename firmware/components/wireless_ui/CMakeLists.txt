if(CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT)
    set(UI_SRCS "src/ui.c" "src/ui_port.c" "src/calib.c")
    if(CONFIG_WIRELESS_UI_CJK_CUSTOM AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/fonts/lv_font_ui_cjk.c")
        list(APPEND UI_SRCS "fonts/lv_font_ui_cjk.c")
    endif()

    idf_component_register(
        SRCS ${UI_SRCS}
        INCLUDE_DIRS "include"
        REQUIRES lvgl esp_lvgl_port esp_lcd_ili9341
        PRIV_REQUIRES esp_lcd driver esp_timer
    )
    if(CONFIG_WIRELESS_UI_CJK_CUSTOM)
        # lv_font_conv wraps the generated file in "#if LV_FONT_UI_CJK".
        target_compile_definitions(${COMPONENT_LIB} PRIVATE LV_FONT_UI_CJK=1)
    endif()
else()
    # Option off: the component still exists (so includes keep working) but is empty.
    idf_component_register(INCLUDE_DIRS "include")
endif()
