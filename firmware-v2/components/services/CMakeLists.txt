idf_component_register(
    SRCS
        "src/services.c"
        "src/system_object.c"
        "src/ui_object.c"
        "src/radio_object.c"
        "src/scan_object.c"
    INCLUDE_DIRS "include"
    REQUIRES wbus platform esp_timer hal_wifi wtarget wifi_frame
)
