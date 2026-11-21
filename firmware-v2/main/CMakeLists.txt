idf_component_register(
    SRCS "main.c"
    REQUIRES
        platform
        transport
        services
        wireless_ui
        wbus
        wtarget
        attacks
        hal_wifi
        wifi_frame
)
