#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 XDUPWW
#
# 脱机测试：用系统编译器直接编译 wbus 与各层纯逻辑，不需要 ESP-IDF 与开发板。
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

echo "== run =="
./build/host/test_wbus
