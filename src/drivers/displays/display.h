#ifndef DISPLAY_H
#define DISPLAY_H

#include "displayDriver.h"

extern DisplayDriver *currentDisplayDriver;

void initDisplay();
void alternateScreenState();
void alternateScreenRotation();
void switchToNextScreen();
void resetToFirstScreen();
void drawLoadingScreen();
void drawSetupScreen();
void drawCurrentScreen(unsigned long mElapsed);
void animateCurrentScreen(unsigned long frame);
void doLedStuff(unsigned long frame);
// Temporarily lend the off-screen scratch buffer to secure statistics work.
// The LCD keeps its last complete frame; no mining task depends on this lock.
void beginStatsDisplayMemoryWindow();
void endStatsDisplayMemoryWindow();
#ifdef BUTTON_SCREEN_SLEEP_SECONDS
// Button screen sleep (loop task). screenSleepButtonEvent() returns true when a
// button event only woke the screen and must not be acted on.
bool screenSleepButtonEvent();
void screenSleepTick();
// Button callback wrapper: while the screen sleeps every button event, a long
// press included, only wakes it, so nothing (least of all a configuration
// reset) acts on a dark screen.
#define SCREEN_WAKE_OR(fn) [] { if (!screenSleepButtonEvent()) fn(); }
#else
#define SCREEN_WAKE_OR(fn) fn
#endif

#endif // DISPLAY_H
