// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>

typedef void (*transport_mirror_fn)(void *ctx, const char *line);

typedef int (*transport_command_fn)(const char *args);

void transport_console_start(void);

int transport_console_register(const char *verb, transport_command_fn fn);

int transport_console_submit(const char *line);

void transport_console_set_mirror(transport_mirror_fn fn, void *ctx);

void transport_console_out(const char *line);
