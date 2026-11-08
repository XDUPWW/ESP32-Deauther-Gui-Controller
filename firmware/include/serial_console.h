#ifndef SERIAL_CONSOLE_H
#define SERIAL_CONSOLE_H

void init_serial_console();
void handle_serial_console();

// Runs one protocol line through the same dispatcher the serial console uses.
// The local LVGL UI calls this, so the UI can only do what a serial client can.
void wireless_console_execute(const char* line);

#endif
