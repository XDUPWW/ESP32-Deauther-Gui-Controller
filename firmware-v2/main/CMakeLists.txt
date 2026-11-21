idf_component_register(
    SRCS "main.c"
    REQUIRES hal_wifi wifi_frame wbus services wtarget attacks transport platform
)
