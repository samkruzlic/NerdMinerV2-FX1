// Host test for button screen sleep (BUTTON_SCREEN_SLEEP_SECONDS) in
// src/drivers/displays/display.cpp and the SCREEN_WAKE_OR button wrapper.
// Build and mutation check: tools/run_screen_sleep_tests.sh
#include <cstdio>
#include <cstdlib>
#include <TFT_eSPI.h>  // test stub: Arduino fakes, TFT_BL
#include "drivers/displays/display.h"

namespace fake {
unsigned long nowMillis = 0;
int pinLevel[64];
int pinWrites[64];
}
FakeSerial Serial;

static int draws = 0, animations = 0, actions = 0;
static void cyclicScreen(unsigned long) { draws++; }
static void animate(unsigned long) { animations++; }
static void noop() {}
static void buttonAction() { actions++; }  // stands in for switchToNextScreen, reset_configuration, ...
static CyclicScreenFunction screens[] = {cyclicScreen};
DisplayDriver tDisplayDriver = {noop, noop, noop, noop, noop, screens, animate, nullptr, 1, 0, 340, 170};
DisplayDriver tDisplayV1Driver = tDisplayDriver;

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { std::fprintf(stderr, "line %d: %s\n", __LINE__, #cond); failures++; } } while (0)

static const unsigned long kSleepMs = BUTTON_SCREEN_SLEEP_SECONDS * 1000UL;
static bool lit() { return fake::pinLevel[TFT_BL] == TFT_BACKLIGHT_ON; }
// One monitor-task frame: 1 if it drew, 2 if it animated, 3 for both.
static int frame() {
  const int d = draws, a = animations;
  drawCurrentScreen(1000);
  animateCurrentScreen(0);
  return (draws - d) + 2 * (animations - a);
}
static bool drawsNow() { return frame() == 3; }
static bool drawsNothing() { return frame() == 0; }
static void at(unsigned long t) { fake::nowMillis = t; screenSleepTick(); }
static void press(unsigned long t) {  // one OneButton event (click, double, multi or long press)
  fake::nowMillis = t;
  SCREEN_WAKE_OR(buttonAction)();
}

int main() {
  fake::pinLevel[TFT_BL] = TFT_BACKLIGHT_ON;  // TFT_eSPI::init leaves the backlight on

  // No timer before the mining screens start (a setup portal can take minutes).
  for (unsigned long t = 0; t <= 10 * kSleepMs; t += 50) at(t);
  CHECK(lit());
  CHECK(fake::pinWrites[TFT_BL] == 0);

  // The timer starts with the first mining frame.
  unsigned long t0 = 20 * kSleepMs;
  fake::nowMillis = t0;
  CHECK(drawsNow());
  at(t0);
  at(t0 + kSleepMs - 1);
  CHECK(lit());
  CHECK(drawsNow());
  at(t0 + kSleepMs);
  CHECK(!lit());
  CHECK(drawsNothing());  // dark: no frame and no animation at all
  at(t0 + 5 * kSleepMs);
  CHECK(!lit());
  CHECK(drawsNothing());

  // Any button event while dark only wakes; the action is not run.
  unsigned long t1 = t0 + 6 * kSleepMs;
  press(t1);
  CHECK(actions == 0);
  CHECK(lit());
  CHECK(drawsNow());
  // The wake restarts the timer.
  at(t1 + kSleepMs - 1);
  CHECK(lit());

  // While lit, a button event acts and restarts the timer.
  unsigned long t2 = t1 + kSleepMs - 1;
  press(t2);
  CHECK(actions == 1);
  at(t2 + kSleepMs - 1);
  CHECK(lit());
  at(t2 + kSleepMs);
  CHECK(!lit());
  CHECK(drawsNothing());

  // Pressing repeatedly while dark (e.g. a long press from a dark screen):
  // the first wakes, the next one acts.
  unsigned long t3 = t2 + 2 * kSleepMs;
  press(t3);
  CHECK(actions == 1);
  press(t3 + 100);
  CHECK(actions == 2);

  // "Screen off" (alternateScreenState) sleeps at once and stops drawing;
  // called again it wakes.
  alternateScreenState();
  CHECK(!lit());
  CHECK(drawsNothing());
  alternateScreenState();
  CHECK(lit());
  CHECK(drawsNow());

  // The timer survives millis() wrapping round.
  unsigned long t4 = 0xFFFFFFFFUL - kSleepMs / 2;
  press(t4);
  CHECK(actions == 3);
  at(0xFFFFFFFFUL);
  at(kSleepMs / 2 - 2);
  CHECK(lit());
  at(kSleepMs / 2 - 1);
  CHECK(!lit());

  if (failures) { std::fprintf(stderr, "%d check(s) failed\n", failures); return EXIT_FAILURE; }
  std::printf("screen sleep: all checks passed\n");
  return EXIT_SUCCESS;
}
