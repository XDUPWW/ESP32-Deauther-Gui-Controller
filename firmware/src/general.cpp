#include <Arduino.h>

#include "definitions.h"

#ifdef LED
#ifndef LED_ACTIVE_LOW
#define LED_ACTIVE_LOW 0
#endif

#if LED_ACTIVE_LOW
#define LED_ON LOW
#define LED_OFF HIGH
#else
#define LED_ON HIGH
#define LED_OFF LOW
#endif

void blink_led(int num_times, int blink_duration) {
  for (int i = 0; i < num_times; i++) {
    digitalWrite(LED, LED_ON);
    delay(blink_duration / 2);
    digitalWrite(LED, LED_OFF);
    delay(blink_duration / 2);
  }
}
#endif
