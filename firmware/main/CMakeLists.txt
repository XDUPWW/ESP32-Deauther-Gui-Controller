set(SRCS
    "../src/main.cpp"
    "../src/deauth.cpp"
    "../src/general.cpp"
    "../src/evil_twin.cpp"
    "../src/serial_console.cpp"
    "../src/csa.cpp"
    "../src/delba.cpp"
    "../src/storage.cpp"
)

# wireless_ui is always a dependency: with CONFIG_WIRELESS_ATTACK_LVGL_SUPPORT
# off it registers as an interface-only component, so main.cpp can keep the
# include without pulling LVGL into the build.
idf_component_register(
    SRCS ${SRCS}
    INCLUDE_DIRS "../include"
    REQUIRES arduino-esp32 wireless_ui nvs_flash
)
