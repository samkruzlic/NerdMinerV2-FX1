#ifndef SCREEN_SLEEP_TEST_ARDUINO_H
#define SCREEN_SLEEP_TEST_ARDUINO_H
// Just enough Arduino for src/drivers/displays/display.cpp on the host: a
// settable clock, recorded pin levels and a silent Serial.
#include <cstdint>

#define HIGH 1
#define LOW 0

namespace fake {
extern unsigned long nowMillis;
extern int pinLevel[64];
extern int pinWrites[64];
}
inline unsigned long millis() { return fake::nowMillis; }
inline void digitalWrite(uint8_t pin, uint8_t level) {
  fake::pinLevel[pin] = level;
  fake::pinWrites[pin]++;
}
struct FakeSerial { void println(const char *) {} };
extern FakeSerial Serial;

#endif
