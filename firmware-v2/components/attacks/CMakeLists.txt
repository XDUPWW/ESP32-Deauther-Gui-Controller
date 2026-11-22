idf_component_register(
    SRCS
        "src/attacks.c"
        "src/attack_common.c"
        "authflood/authflood.c"
        "ba/ba.c"
        "csa/csa.c"
        "deauth/deauth.c"
        "delba/delba.c"
        "eapol/eapol.c"
        "btm/btm.c"
        "qosnull/qosnull.c"
        "probe/probe.c"
        "sae/sae.c"
    INCLUDE_DIRS "include"
    REQUIRES wifi_frame hal_wifi wtarget wbus platform esp_timer esp_hw_support
)
