idf_component_register(
    SRCS
        "src/transport.c"
        "src/plugins/serial_text.c"
    INCLUDE_DIRS "include"
    REQUIRES wbus platform
)
