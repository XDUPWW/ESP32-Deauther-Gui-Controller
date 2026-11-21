idf_component_register(
    SRCS "src/attacks.c"
    INCLUDE_DIRS "include"
    REQUIRES wifi_frame hal_wifi wtarget wbus platform
)
