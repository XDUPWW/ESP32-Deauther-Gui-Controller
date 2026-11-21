#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 XDUPWW
#
# 脱机测试：用系统编译器编译纯逻辑（wbus / wifi_frame），不需要开发板和 ESP-IDF。
# 用法：sh host_tests/run.sh      （$CC 可覆盖编译器，默认 gcc）

set -e

cd "$(dirname "$0")/.."

CC="${CC:-gcc}"
CFLAGS="-std=c11 -Wall -Wextra -Werror -O1"

mkdir -p build/host

echo "== build =="
"$CC" $CFLAGS \
    -I host_tests/mock \
    -I components/wbus/include \
    host_tests/test_wbus.c \
    components/wbus/src/wbus.c \
    -o build/host/test_wbus

"$CC" $CFLAGS \
    -I components/wifi_frame/include \
    host_tests/test_frame.c \
    components/wifi_frame/src/frame_build.c \
    components/wifi_frame/src/ie_build.c \
    components/wifi_frame/src/ie_parse.c \
    components/wifi_frame/src/mac.c \
    -o build/host/test_frame

"$CC" $CFLAGS \
    -I components/ble_frame/include \
    host_tests/test_ble_frame.c \
    components/ble_frame/src/adv.c \
    components/ble_frame/src/addr.c \
    -o build/host/test_ble_frame

echo "== run =="
./build/host/test_wbus
./build/host/test_frame
./build/host/test_ble_frame
