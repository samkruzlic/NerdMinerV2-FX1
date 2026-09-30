#include "display.h"
#include <esp_heap_caps.h>
#if defined(ESP32_2432S028_2USB)
#include <atomic>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
namespace {
StaticSemaphore_t screenMutexStorage;
SemaphoreHandle_t screenMutex = nullptr;
std::atomic<bool> statsMemoryWindow{false};
}
extern void releaseCydScreenScratch();
extern bool restoreCydScreenScratch();
#endif

#ifdef NO_DISPLAY
DisplayDriver *currentDisplayDriver = &noDisplayDriver;
#endif

#ifdef M5STACK_DISPLAY
DisplayDriver *currentDisplayDriver = &m5stackDisplayDriver;
#endif

#ifdef WT32_DISPLAY
DisplayDriver *currentDisplayDriver = &wt32DisplayDriver;
#endif

#ifdef LED_DISPLAY
DisplayDriver *currentDisplayDriver = &ledDisplayDriver;
#endif

#ifdef OLED_042_DISPLAY
DisplayDriver *currentDisplayDriver = &oled042DisplayDriver;
#endif

#ifdef T_DISPLAY
DisplayDriver *currentDisplayDriver = &tDisplayDriver;
#endif

#ifdef AMOLED_DISPLAY
DisplayDriver *currentDisplayDriver = &amoledDisplayDriver;
#endif

#ifdef DONGLE_DISPLAY
DisplayDriver *currentDisplayDriver = &dongleDisplayDriver;
#endif

#ifdef ESP32_2432S028R
DisplayDriver *currentDisplayDriver = &esp32_2432S028RDriver;
#endif

#ifdef ESP32_2432S028_2USB
DisplayDriver *currentDisplayDriver = &esp32_2432S028RDriver;
#endif

#ifdef T_QT_DISPLAY
DisplayDriver *currentDisplayDriver = &t_qtDisplayDriver;
#endif

#ifdef V1_DISPLAY
DisplayDriver *currentDisplayDriver = &tDisplayV1Driver;
#endif

#ifdef M5STICKC_DISPLAY
DisplayDriver *currentDisplayDriver = &m5stickCDriver;
#endif

#ifdef M5STICKCPLUS_DISPLAY
DisplayDriver *currentDisplayDriver = &m5stickCPlusDriver;
#endif

#ifdef T_HMI_DISPLAY
DisplayDriver *currentDisplayDriver = &t_hmiDisplayDriver;
#endif

#ifdef ST7735S_DISPLAY
DisplayDriver *currentDisplayDriver = &sp_kcDisplayDriver;
#endif

#ifdef OLED_SSD1306_128X64_DISPLAY
DisplayDriver *currentDisplayDriver = &ssd1306DisplayDriver;
#endif


// Initialize the display
void initDisplay()
{
#if defined(ESP32_2432S028_2USB)
  screenMutex = xSemaphoreCreateMutexStatic(&screenMutexStorage);
#endif
  currentDisplayDriver->initDisplay();
}

void beginStatsDisplayMemoryWindow() {
#if defined(ESP32_2432S028_2USB)
  statsMemoryWindow.store(true, std::memory_order_release);
  xSemaphoreTake(screenMutex, portMAX_DELAY);
  releaseCydScreenScratch();
  xSemaphoreGive(screenMutex);
#endif
}

void endStatsDisplayMemoryWindow() {
#if defined(ESP32_2432S028_2USB)
  if (!statsMemoryWindow.load(std::memory_order_acquire)) return;
  xSemaphoreTake(screenMutex, portMAX_DELAY);
  restoreCydScreenScratch();
  xSemaphoreGive(screenMutex);
  statsMemoryWindow.store(false, std::memory_order_release);
#endif
}

// Alternate screen state
void alternateScreenState()
{
  currentDisplayDriver->alternateScreenState();
}

// Alternate screen rotation
void alternateScreenRotation()
{
  currentDisplayDriver->alternateScreenRotation();
}

// Draw the loading screen
void drawLoadingScreen()
{
  currentDisplayDriver->loadingScreen();
}

// Draw the setup screen
void drawSetupScreen()
{
  currentDisplayDriver->setupScreen();
}

// Reset the current cyclic screen to the first one
void resetToFirstScreen()
{
  currentDisplayDriver->current_cyclic_screen = 0;
}

// Switches to the next cyclic screen without drawing it
void switchToNextScreen()
{
  currentDisplayDriver->current_cyclic_screen = (currentDisplayDriver->current_cyclic_screen + 1) % currentDisplayDriver->num_cyclic_screens;
}

// Draw the current cyclic screen
#ifdef CYD_SCREEN_SLEEP_SECONDS
bool cydScreenAsleep();
#endif

void drawCurrentScreen(unsigned long mElapsed)
{
#ifdef CYD_SCREEN_SLEEP_SECONDS
  if (cydScreenAsleep()) return;
#endif
#if defined(ESP32_2432S028_2USB)
  if (statsMemoryWindow.load(std::memory_order_acquire)) return;
  // Nonblocking: never queue UI frames behind a network operation.
  if (xSemaphoreTake(screenMutex, 0) != pdTRUE) return;
  if (statsMemoryWindow.load(std::memory_order_acquire) ||
      !restoreCydScreenScratch()) {
    xSemaphoreGive(screenMutex);
    return;
  }
  // Defer a frame, not mining or accounting, during TLS's byte-heap peak.
  // Font queues throw on allocation failure. Keep the previous complete frame
  // until there is room for their transient allocations; appearance is unchanged.
  if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) < 12000 ||
      heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) < 4096) {
    xSemaphoreGive(screenMutex);
    return;
  }
#endif
  currentDisplayDriver->cyclic_screens[currentDisplayDriver->current_cyclic_screen](mElapsed);
#if defined(ESP32_2432S028_2USB)
  xSemaphoreGive(screenMutex);
#endif
}

// Animate the current cyclic screen
void animateCurrentScreen(unsigned long frame)
{
  currentDisplayDriver->animateCurrentScreen(frame);
}

// Do LED stuff
void doLedStuff(unsigned long frame)
{
  currentDisplayDriver->doLedStuff(frame);
}
