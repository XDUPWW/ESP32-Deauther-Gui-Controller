#ifndef DEFINITIONS_H
#define DEFINITIONS_H

// The old control AP is gone (the firmware never beacons); kept for the evil twin module.
#define AP_SSID "ESP32-Deauther"
#define AP_PASS "esp32wroom32"

// ESP32-2432S028R: GPIO2 is the LCD D/C line, so the status LED has to live on the
// on-board RGB LED instead (4/16/17), which is wired active low.
#define LED 4
#define LED_ACTIVE_LOW 1

// The serial console stream must stay machine readable, keep debug prints off.
// #define SERIAL_DEBUG

#define CHANNEL_MAX 13
// UART RX ring. The default 256 bytes overruns as soon as the host sends a burst
// of commands (300 PINGs ≈ 1.8 KB), which silently drops whole lines.
#define SERIAL_RX_BUFFER_SIZE 4096
// Frames per sniffed hit. Unicast deauth frames are ACKed by the peer, so each
// queued frame holds a TX buffer until its ACK timeouts: 16-frame bursts kept the
// buffers full and made ~2/3 of the injections fail with ESP_ERR_NO_MEM.
// A client drops on the *first* valid deauth, so a small burst repeated on every
// subsequent hit is both faster and more reliable than one huge burst.
#define NUM_FRAMES_PER_DEAUTH 2
#define NUM_BROADCAST_PER_DEAUTH 1
// Blind fallback period: a broadcast deauth to the current AP even when no client
// frame could be sniffed (idle client, or a Wi-Fi 6 client an 11n radio cannot
// decode). 500 ms keeps it cheap while still being felt by the client.
#define BLIND_DEAUTH_PERIOD_MS 500
#define DEAUTH_BLINK_TIMES 2
#define DEAUTH_BLINK_DURATION 20
#define DEAUTH_TYPE_SINGLE 0
#define DEAUTH_TYPE_ALL 1

#ifdef SERIAL_DEBUG
#define DEBUG_PRINT(...) Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#endif
#ifndef SERIAL_DEBUG
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif
#ifdef LED
#define BLINK_LED(num_times, blink_duration) blink_led(num_times, blink_duration)
#endif
#ifndef LED
#define BLINK_LED(...)
#endif

void blink_led(int num_times, int blink_duration);

#endif
