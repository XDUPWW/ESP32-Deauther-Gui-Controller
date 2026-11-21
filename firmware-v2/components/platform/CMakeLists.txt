idf_component_register(
    SRCS
        "src/plat_console.c"
        "src/plat_display.c"
        "src/plat_storage.c"
        "src/plat_led.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash esp_driver_uart esp_driver_gpio esp_driver_spi esp_timer
)
