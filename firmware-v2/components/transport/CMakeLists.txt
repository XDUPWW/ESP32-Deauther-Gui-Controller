idf_component_register(
    SRCS
        "src/transport.c"
        "src/plugins/serial_text.c"
        "src/plugins/ble_text.c"
    INCLUDE_DIRS "include"
    REQUIRES wbus platform hal_ble
)
