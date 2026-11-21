idf_component_register(
    SRCS "main.c"
    REQUIRES
        platform
        board_cyd
        transport
        services
        wireless_ui
        wbus
        wtarget
        attacks
        hal_wifi
        hal_ble
        wifi_frame
        ble_frame
)
