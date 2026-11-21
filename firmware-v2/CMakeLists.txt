cmake_minimum_required(VERSION 3.16)

# 路径里带空格，编译命令行会超长，强制用响应文件
set(CMAKE_NINJA_FORCE_RESPONSE_FILE ON)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# hal_wifi 覆盖 libnet80211 里的 ieee80211_raw_frame_sanity_check()，否则伪造帧发不出去。
# 同名符号重复定义要靠 muldefs 放过。
idf_build_set_property(LINK_OPTIONS "-Wl,-z,muldefs" APPEND)

project(wireless_attack_v2)
