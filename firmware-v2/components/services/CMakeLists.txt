idf_component_register(
    SRCS
        "src/system_object.c"
        "src/ui_object.c"
    INCLUDE_DIRS "include"
    REQUIRES wbus platform esp_timer
)
