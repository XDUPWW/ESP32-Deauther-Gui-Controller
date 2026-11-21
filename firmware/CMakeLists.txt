cmake_minimum_required(VERSION 3.16)

# The project lives under a long path with spaces; arduino-esp32 adds ~40 library
# include directories, which pushes the final compile command past the Windows
# command-line limit. Force CMake to use response files.
set(CMAKE_NINJA_FORCE_RESPONSE_FILE ON)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# arduino-esp32 4.0.0-rc1 is tested against ESP-IDF 6.0; ESP-IDF 6.1 added new
# fields to structs such as i2s_chan_config_t, which trips the default -Werror
# inside the Arduino core. Keep -Werror everywhere else.
idf_build_set_property(COMPILE_OPTIONS "-Wno-error=missing-field-initializers" APPEND)

# src/deauth.cpp overrides ieee80211_raw_frame_sanity_check() from libnet80211.a
# to allow raw 802.11 frame injection; the duplicate definition must not fail the link.
idf_build_set_property(LINK_OPTIONS "-Wl,-z,muldefs" APPEND)

# The C5 board only breaks out the native USB port, so Arduino's Serial has to
# be the USB-Serial-JTAG CDC device rather than UART0. Both macros must be
# visible to the Arduino core and to main, hence the global definition.
if("${IDF_TARGET}" STREQUAL "esp32c5" OR "${SDKCONFIG}" MATCHES "sdkconfig\\.c5$")
    idf_build_set_property(COMPILE_DEFINITIONS "ARDUINO_USB_MODE=1" APPEND)
    idf_build_set_property(COMPILE_DEFINITIONS "ARDUINO_USB_CDC_ON_BOOT=1" APPEND)
endif()

project(wireless_attack)
