idf_component_register(
    SRCS "src/hal_ble.c"
    INCLUDE_DIRS "include"
    REQUIRES ble_frame
    PRIV_REQUIRES bt
)
