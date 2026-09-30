#include "PoolStatsService.h"

#include <Arduino.h>
#include <WiFi.h>
#include <string.h>
#include <time.h>
#include <esp_heap_caps.h>

#include "PoolRegistry.h"
#include "PoolStatsPolicy.h"
#include "PoolStatsProvider.h"
#include "../drivers/displays/display.h"
#include "../crypto/ShaResourcePolicy.h"

#ifdef CYD_SCREEN_SLEEP_SECONDS
bool cydScreenAsleep();
#endif

namespace {

constexpr uint32_t WIFI_RECHECK_MS = 5UL * 1000UL;
constexpr uint32_t CLOCK_RECHECK_MS = 5UL * 1000UL;
constexpr const char *NTP_SERVER = "pool.ntp.org";
constexpr uint32_t MIN_FREE_HEAP = 45000;
// Two TLS record buffers must fit before the handshake's smaller allocations.
// A measured 32 KiB largest block was insufficient despite 60 KiB total free.
constexpr uint32_t MIN_LARGEST_HEAP_BLOCK = 36000;
// TLS setup in WiFiClientSecure exceeds 10 KiB on classic ESP32. Keep the
// network-only statistics task isolated from mining with a bounded 16 KiB stack.
constexpr uint32_t SERVICE_TASK_STACK = 16384;
// Above the CPU-bound software miner, below Stratum and display tasks.
constexpr UBaseType_t SERVICE_TASK_PRIORITY = 2;

portMUX_TYPE snapshotMux = portMUX_INITIALIZER_UNLOCKED;
PoolIdentity identity{};
PoolStatsSnapshot snapshot{};
TaskHandle_t serviceTaskHandle = nullptr;
char lastModified[48] = {};
uint32_t nextAttemptMs = 0;
bool timeSyncStarted = false;

void copyText(char *destination, size_t destinationSize, const char *source) {
  if (destinationSize == 0) return;
  snprintf(destination, destinationSize, "%s", source == nullptr ? "" : source);
}

void setUnavailableValues(PoolStatsSnapshot &value) {
  copyText(value.bestDifficulty, sizeof(value.bestDifficulty), "N/A");
  copyText(value.workersCount, sizeof(value.workersCount), "N/A");
  copyText(value.totalHashRate, sizeof(value.totalHashRate), "N/A");
  value.hasData = false;
}

bool timeReached(uint32_t now, uint32_t target) {
  return static_cast<int32_t>(now - target) >= 0;
}

bool needsTlsClock() {
  return strncmp(identity.definition.apiBaseUrl, "https://", 8) == 0;
}

void publishSnapshot(PoolStatsSnapshot value) {
  portENTER_CRITICAL(&snapshotMux);
  value.revision = snapshot.revision + 1;
  snapshot = value;
  portEXIT_CRITICAL(&snapshotMux);
}

void refreshStats(uint32_t now) {
  PoolStatsProvider *provider = providerFor(identity.definition.provider);
  if (provider == nullptr) return;

  PoolStatsSnapshot current = getPoolStatsSnapshot();
  current.lastAttemptMs = now;
  publishSnapshot(current);

  // Release only reusable rendering scratch, never configuration or job data.
  // Cold TLS setup borrows scratch only until the verified HTTP headers arrive.
  // The provider releases the window then; this guard handles early errors.
  struct DisplayMemoryWindow {
    explicit DisplayMemoryWindow(bool enabled) : enabled(enabled) {
      if (enabled) beginStatsDisplayMemoryWindow();
    }
    ~DisplayMemoryWindow() { if (enabled) endStatsDisplayMemoryWindow(); }
    bool enabled;
  } displayMemoryWindow(!poolStatsHasReusableTransport());

  const uint32_t heapCaps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
  const uint32_t freeBytes = heap_caps_get_free_size(heapCaps);
  const uint32_t largestBlock = heap_caps_get_largest_free_block(heapCaps);
  Serial.printf("[PoolStats] byte heap free=%u max=%u min=%u\n", freeBytes,
    largestBlock, heap_caps_get_minimum_free_size(heapCaps));
  const uint32_t requiredFree = displayMemoryWindow.enabled ? MIN_FREE_HEAP : 24000;
  const uint32_t requiredBlock = displayMemoryWindow.enabled ? MIN_LARGEST_HEAP_BLOCK : 8192;
  if (freeBytes < requiredFree || largestBlock < requiredBlock) {
    Serial.printf("[PoolStats] memory gate heap=%u max=%u\n", freeBytes, largestBlock);
    const PoolUpdateDecision decision = updatePoolSnapshotAfterFetch(
        getPoolStatsSnapshot(), current,
        {PoolFetchStatus::RetryableError, 0}, now);
    publishSnapshot(decision.snapshot);
    nextAttemptMs = now + decision.nextDelayMs;
    return;
  }

  PoolStatsSnapshot candidate = current;
  const uint32_t fallbackUs = shaFallbackMicroseconds().load(std::memory_order_relaxed);
  const uint32_t fallbackNonces = shaFallbackNonces().load(std::memory_order_relaxed);
  const uint32_t cpuWindowUs = shaCpuWindowMicroseconds().load(std::memory_order_relaxed);
  const uint32_t handshakeWindowUs = shaHandshakeWindowMicroseconds().load(std::memory_order_relaxed);
  const PoolFetchResult result =
      provider->fetch(identity, candidate, lastModified, sizeof(lastModified));
  Serial.printf("[PoolStats] hardware fallback us=%u nonces=%u\n",
    shaFallbackMicroseconds().load(std::memory_order_relaxed) - fallbackUs,
    shaFallbackNonces().load(std::memory_order_relaxed) - fallbackNonces);
  Serial.printf("[PoolStats] fetch result=%u HTTP=%d hasData=%u\n",
    static_cast<unsigned>(result.status), result.httpStatus, candidate.hasData);
  Serial.printf("[PoolStats] idle CPU windows us=%u handshakeUs=%u\n",
    shaCpuWindowMicroseconds().load(std::memory_order_relaxed) - cpuWindowUs,
    shaHandshakeWindowMicroseconds().load(std::memory_order_relaxed) - handshakeWindowUs);
  if (result.status == PoolFetchStatus::Success) {
    Serial.printf("[PoolStats] verified snapshot best=%s workers=%s rate=%s\n",
      candidate.bestDifficulty, candidate.workersCount, candidate.totalHashRate);
  }

  const PoolUpdateDecision decision =
      updatePoolSnapshotAfterFetch(current, candidate, result, millis());
  publishSnapshot(decision.snapshot);
  // A slow TLS computation must not consume its own retry delay and cause
  // immediately repeated requests when the network call finally returns.
  nextAttemptMs = millis() + decision.nextDelayMs;
}

void poolStatsTask(void *) {
  for (;;) {
    const uint32_t now = millis();
    if (WiFi.status() != WL_CONNECTED) {
      PoolStatsSnapshot current = getPoolStatsSnapshot();
      const PoolMetricState expected =
          current.hasData ? PoolMetricState::Stale : PoolMetricState::Error;
      if (current.state != expected) {
        current.state = expected;
        publishSnapshot(current);
      }
      nextAttemptMs = now + WIFI_RECHECK_MS;
#ifdef CYD_SCREEN_SLEEP_SECONDS
    } else if (cydScreenAsleep()) {
      // Nobody can see the panel: skip TLS refreshes, keeping the deadline
      // current so the first loop after a wake fetches straight away.
      nextAttemptMs = now;
#endif
    } else if (timeReached(now, nextAttemptMs)) {
      const PoolClockAction clockAction = poolStatsClockAction(
          needsTlsClock(), static_cast<int64_t>(time(nullptr)), timeSyncStarted);
      if (clockAction != PoolClockAction::Fetch) {
        if (clockAction == PoolClockAction::StartSync) {
          configTime(0, 0, NTP_SERVER);
          timeSyncStarted = true;
        }
        nextAttemptMs = now + CLOCK_RECHECK_MS;
      } else {
        refreshStats(now);
      }
    }
    vTaskDelay(pdMS_TO_TICKS(250));
  }
}

}  // namespace

void beginPoolStatsService(const char *host, uint16_t port,
                           const char *username) {
  if (serviceTaskHandle != nullptr) return;

  identity.definition = resolvePoolDefinition(host, port);
  extractPoolWallet(username, identity.wallet, sizeof(identity.wallet));

  PoolStatsSnapshot initial{};
  copyText(initial.poolName, sizeof(initial.poolName),
           identity.definition.displayName);
  setUnavailableValues(initial);
  initial.state = PoolMetricState::Unavailable;
  initial.revision = 1;

  if (identity.definition.provider == PoolProviderKind::Testnet) {
    copyText(initial.bestDifficulty, sizeof(initial.bestDifficulty), "TESTNET");
    copyText(initial.workersCount, sizeof(initial.workersCount), "1");
    copyText(initial.totalHashRate, sizeof(initial.totalHashRate), "TESTNET");
    initial.state = PoolMetricState::Current;
    initial.hasData = true;
  } else if (providerFor(identity.definition.provider) != nullptr) {
    initial.state = PoolMetricState::Loading;
  }
  publishSnapshot(initial);

  if (providerFor(identity.definition.provider) == nullptr) return;

#if CONFIG_FREERTOS_UNICORE
  const BaseType_t created =
      xTaskCreate(poolStatsTask, "PoolStats", SERVICE_TASK_STACK, nullptr,
                  SERVICE_TASK_PRIORITY, &serviceTaskHandle);
#else
  const BaseType_t created = xTaskCreatePinnedToCore(
      poolStatsTask, "PoolStats", SERVICE_TASK_STACK, nullptr,
      SERVICE_TASK_PRIORITY, &serviceTaskHandle, 1);
#endif
  if (created != pdPASS) {
    serviceTaskHandle = nullptr;
    PoolStatsSnapshot failed = getPoolStatsSnapshot();
    failed.state = PoolMetricState::Error;
    publishSnapshot(failed);
  }
}

PoolStatsSnapshot getPoolStatsSnapshot() {
  PoolStatsSnapshot copy;
  portENTER_CRITICAL(&snapshotMux);
  copy = snapshot;
  portEXIT_CRITICAL(&snapshotMux);

  if (copy.hasData && copy.state == PoolMetricState::Current &&
      copy.lastSuccessMs != 0 &&
      millis() - copy.lastSuccessMs > POOL_STATS_STALE_AFTER_MS) {
    copy.state = PoolMetricState::Stale;
  }
  return copy;
}

const char *poolMetricStateLabel(PoolMetricState state) {
  switch (state) {
    case PoolMetricState::Loading:
      return "WAIT";
    case PoolMetricState::Stale:
      return "STALE";
    case PoolMetricState::Error:
      return "ERROR";
    case PoolMetricState::Unavailable:
      return "N/A";
    default:
      return "";
  }
}
