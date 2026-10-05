// Development-only W390 kernel soak (env ESP32_2432S028_2USB_W390_SOAK):
// >100 M nonces per load through the PRODUCTION runClassicHardwareSequential,
// timed kernel vs polled kernel, plus software re-hashes. Never mines.
// Included into mining.cpp after ClassicShaDiagnostics.h (same translation unit).
#pragma once
#include <SPI.h>
#include <WiFi.h>
#include <esp_random.h>
#include "W390SoakCompare.h"

namespace {

constexpr uint64_t kSoakNoncesPerLoad = 100000000ULL;
constexpr uint64_t kSoakProgressEvery = 10000000ULL;
constexpr uint32_t kSoakHeaderEvery = 1U << 20;  // new random header per 2^20 nonces
constexpr unsigned kSoakMismatchLines = 5;       // printed per load

enum SoakLoad : uint32_t { kLoadSw = 1, kLoadSpi = 2, kLoadWifi = 4 };
struct SoakLoadDef { const char *name; uint32_t mask; };
constexpr SoakLoadDef kSoakLoads[] = {
  {"none", 0}, {"sw", kLoadSw}, {"spi", kLoadSpi}, {"wifi", kLoadWifi},
  {"all", kLoadSw | kLoadSpi | kLoadWifi}};
constexpr unsigned kSoakLoadCount = sizeof(kSoakLoads) / sizeof(kSoakLoads[0]);

std::atomic<uint32_t> s_soak_load_mask(0);
std::atomic<uint32_t> s_soak_sw_compressions(0);
std::atomic<uint32_t> s_soak_spi_buffers(0);
std::atomic<uint32_t> s_soak_wifi_scans(0);
std::atomic<uint32_t> s_soak_wifi_networks(0);
std::atomic<bool> s_soak_done(false);

// ---- loads, each its own task on core 1 (FX1's display/network core) ----
void soakSwLoad(void *)
{
  uint8_t block[64];
  for (unsigned i = 0; i < sizeof(block); ++i) block[i] = static_cast<uint8_t>(i);
  for (;;) {
    if (!(s_soak_load_mask.load() & kLoadSw)) { vTaskDelay(10); continue; }
    // Software SHA-256 (not the shared engine): ~ten 64-byte messages, then a
    // one-tick yield so core 1's idle task still runs.
    for (unsigned i = 0; i < 200; ++i) {
      uint8_t digest[32];
      mining_validation::referenceSha256(block, sizeof(block), digest);
      memcpy(block, digest, sizeof(digest));
    }
    s_soak_sw_compressions.fetch_add(200 * 2);  // 64-byte message = 2 compressions
    vTaskDelay(1);
  }
}

void soakSpiLoad(void *)
{
  // CYD display pins on HSPI: SCK 14, MISO 12, MOSI 13, CS 15, DC 2.
  constexpr size_t kBytes = 4096;
  uint8_t *const buffer = static_cast<uint8_t *>(malloc(kBytes));
  if (!buffer) { Serial.println("W390 SOAK ABORT: no memory for the SPI load"); vTaskDelete(nullptr); }
  for (unsigned i = 0; i < kBytes; ++i) buffer[i] = static_cast<uint8_t>(i * 7);
  SPIClass spi(HSPI);
  spi.begin(14, 12, 13, 15);
  pinMode(15, OUTPUT); digitalWrite(15, HIGH);
  pinMode(2, OUTPUT);
  bool dc = false;
  for (;;) {
    if (!(s_soak_load_mask.load() & kLoadSpi)) { vTaskDelay(10); continue; }
    for (unsigned i = 0; i < 4; ++i) {
      dc = !dc;
      digitalWrite(2, dc ? HIGH : LOW);
      digitalWrite(15, LOW);
      spi.beginTransaction(SPISettings(40000000, MSBFIRST, SPI_MODE0));
      spi.writeBytes(buffer, kBytes);
      spi.endTransaction();
      digitalWrite(15, HIGH);
      s_soak_spi_buffers.fetch_add(1);
    }
    vTaskDelay(1);
  }
}

void soakWifiLoad(void *)
{
  bool started = false;
  for (;;) {
    if (!(s_soak_load_mask.load() & kLoadWifi)) { vTaskDelay(10); continue; }
    if (!started) {
      WiFi.persistent(false);  // no credentials, nothing written to NVS
      WiFi.mode(WIFI_STA);
      started = true;
    }
    const int found = WiFi.scanNetworks(false, true);
    if (found >= 0) s_soak_wifi_networks.fetch_add(static_cast<uint32_t>(found));
    WiFi.scanDelete();
    s_soak_wifi_scans.fetch_add(1);
    vTaskDelay(1);
  }
}

// ---- the soak itself, on core 0 (where the miner runs) ----
struct SoakJob {
  JobRequest job{};
  alignas(4) uint8_t buffer[128] = {};
};

void soakNewHeader(SoakJob &soak)
{
  for (unsigned i = 0; i < 80; i += 4) {
    const uint32_t r = esp_random();
    memcpy(soak.job.raw_header + i, &r, sizeof(r));
  }
  memset(soak.buffer, 0, sizeof(soak.buffer));
  memcpy(soak.buffer, soak.job.raw_header, 80);
  soak.buffer[80] = 0x80; soak.buffer[126] = 0x02; soak.buffer[127] = 0x80;
  for (unsigned i = 0; i < 32; ++i)
    reinterpret_cast<uint32_t *>(soak.buffer)[i] =
        __builtin_bswap32(reinterpret_cast<uint32_t *>(soak.buffer)[i]);
}

// One kernel over one 1,024-nonce range; the per-nonce records land in
// s_diag_samples through the kernel's own diagRecordNonce hook.
uint32_t soakRun(SoakJob &soak, int32_t kernel, JobResult &result, uint32_t &cycles)
{
  uint8_t hash[32];
  s_soak_kernel = kernel;
  s_diag_burst_count = 0;
  result = JobResult{};
  const uint32_t began = classic_sha::cycleCount();
  runClassicHardwareSequential(&soak.job, &result, soak.buffer, hash);
  cycles = classic_sha::cycleCount() - began;
  s_soak_kernel = -1;
  return s_diag_burst_count;
}

struct SoakLoadTotals {
  w390_soak::Totals totals;
  uint64_t timedCycles = 0, polledCycles = 0;
  unsigned lines = 0;
};

DiagSample *s_soak_timed = nullptr;  // heap: the static DRAM segment is full
SoakLoadTotals s_soak_results[kSoakLoadCount];

void soakPrintProgress(const char *label, const char *load, const SoakLoadTotals &r)
{
  const w390_soak::Totals &t = r.totals;
  Serial.printf("W390 SOAK %s load=%s nonces=%llu timed_vs_polled=%u timed_vs_sw=%u polled_vs_sw=%u "
                "sw_checked=%u hits=%u digest_mismatch=%u coverage=%u timed_cyc_per_nonce=%u polled_cyc_per_nonce=%u "
                "sw_compressions=%u spi_buffers=%u wifi_scans=%u wifi_networks=%u\n",
                label, load, static_cast<unsigned long long>(t.compared), t.timedPolled, t.timedSoftware,
                t.polledSoftware, t.softwareChecked, t.hits, t.digest, t.coverage,
                t.compared ? static_cast<unsigned>(r.timedCycles / t.compared) : 0,
                t.compared ? static_cast<unsigned>(r.polledCycles / t.compared) : 0,
                s_soak_sw_compressions.load(), s_soak_spi_buffers.load(),
                s_soak_wifi_scans.load(), s_soak_wifi_networks.load());
}

void soakTask(void *)
{
  s_diag_force_digest = false;  // as production: full digest only on filter hits
  SoakJob soak;
  soak.job.difficulty = 1e300;  // no candidate: a filter hit never ends the range
  // network_target stays all zero: no hash meets it.
  for (unsigned l = 0; l < kSoakLoadCount; ++l) {
    const SoakLoadDef &load = kSoakLoads[l];
    SoakLoadTotals &r = s_soak_results[l];
    s_soak_sw_compressions.store(0); s_soak_spi_buffers.store(0);
    s_soak_wifi_scans.store(0); s_soak_wifi_networks.store(0);
    const uint32_t samplesBefore = s_classic_kernel.samples();
    const uint32_t netMismatchesBefore = s_classic_kernel.mismatches();
    s_soak_load_mask.store(load.mask);
    if (load.mask) vTaskDelay(500);  // let the loads start
    Serial.printf("W390 SOAK LOAD START load=%s\n", load.name);
    uint64_t done = 0, nextProgress = kSoakProgressEvery;
    while (done < kSoakNoncesPerLoad) {
      if ((done & (kSoakHeaderEvery - 1)) == 0) soakNewHeader(soak);
      soak.job.generation = s_working_generation.load(std::memory_order_acquire);
      soak.job.nonce_start = esp_random();
      soak.job.nonce_count = CLASSIC_SHA_GROUP_NONCES;
      JobResult timedResult, polledResult;
      uint32_t timedCycles, polledCycles;
      const uint32_t timedRecords = soakRun(soak, 1, timedResult, timedCycles);
      memcpy(s_soak_timed, s_diag_samples, sizeof(s_diag_samples));
      const uint32_t polledRecords = soakRun(soak, 0, polledResult, polledCycles);
      r.timedCycles += timedCycles;
      r.polledCycles += polledCycles;
      w390_soak::compareGroup(soak.job.raw_header, soak.job.nonce_start, CLASSIC_SHA_GROUP_NONCES,
          s_soak_timed, timedRecords, timedResult.nonce_count,
          s_diag_samples, polledRecords, polledResult.nonce_count,
          esp_random(), r.totals,
          [&](w390_soak::Kind kind, uint32_t nonce, uint32_t timedWord, uint32_t polledWord, uint32_t software) {
            if (r.lines++ < kSoakMismatchLines)
              Serial.printf("W390 SOAK MISMATCH load=%s kind=%s nonce=%08x timed=%08x polled=%08x software=%08x\n",
                            load.name, w390_soak::kindName(kind), nonce, timedWord, polledWord, software);
          });
      done += CLASSIC_SHA_GROUP_NONCES;
      if (done >= nextProgress) {
        soakPrintProgress("PROGRESS", load.name, r);
        nextProgress += kSoakProgressEvery;
      }
    }
    s_soak_load_mask.store(0);
    soakPrintProgress("LOAD DONE", load.name, r);
    Serial.printf("W390 SOAK NET load=%s samples=%u mismatches=%u kernel=%s\n", load.name,
                  s_classic_kernel.samples() - samplesBefore,
                  s_classic_kernel.mismatches() - netMismatchesBefore,
                  classic_kernel::kernelName(s_classic_kernel.active()));
  }
  bool pass = true;
  for (unsigned l = 0; l < kSoakLoadCount; ++l)
    // The plan runs whole 1,024-nonce groups, so a load compares the first
    // multiple of 1,024 at or above kSoakNoncesPerLoad (100,000,768).
    pass = pass && s_soak_results[l].totals.mismatches() == 0 &&
           s_soak_results[l].totals.compared ==
               (kSoakNoncesPerLoad + CLASSIC_SHA_GROUP_NONCES - 1) / CLASSIC_SHA_GROUP_NONCES * CLASSIC_SHA_GROUP_NONCES;
  Serial.printf("W390 SOAK COMPLETE result=%s", pass ? "PASS" : "FAIL");
  for (unsigned l = 0; l < kSoakLoadCount; ++l) {
    const SoakLoadTotals &r = s_soak_results[l];
    const w390_soak::Totals &t = r.totals;
    Serial.printf(" %s:compared=%llu,timed_vs_polled=%u,timed_vs_sw=%u,polled_vs_sw=%u,sw_checked=%u,"
                  "hits=%u,digest_mismatch=%u,coverage=%u,timed_cpn=%u",
                  kSoakLoads[l].name, static_cast<unsigned long long>(t.compared), t.timedPolled,
                  t.timedSoftware, t.polledSoftware, t.softwareChecked, t.hits, t.digest, t.coverage,
                  t.compared ? static_cast<unsigned>(r.timedCycles / t.compared) : 0);
  }
  Serial.println();
  s_soak_done.store(true);
  vTaskDelete(nullptr);
}

}  // namespace

void runW390KernelSoak()
{
#ifdef W390_SOAK_BREAK_LATCH
  Serial.println("W390 SOAK BROKEN BUILD: no latch wait after START; mismatches are EXPECTED");
#endif
  esp_chip_info_t chip;
  esp_chip_info(&chip);
  const uint32_t cpuMhz = getCpuFrequencyMhz();
  if (!classic_kernel::timedKernelEligible(cpuMhz, chip.revision)) {
    Serial.printf("W390 SOAK ABORT: timed kernel not eligible (cpu=%u MHz, chip rev %u)\n", cpuMhz, chip.revision);
    return;
  }
  if (!s_classic_kernel.timed()) {
#ifdef W390_SOAK_BREAK_LATCH
    Serial.println("W390 SOAK BROKEN BUILD: timed kernel failed its boot test as expected; forcing it anyway");
#else
    Serial.printf("W390 SOAK ABORT: timed kernel not selected at boot (kernel=%s mismatches=%u)\n",
                  classic_kernel::kernelName(s_classic_kernel.active()), s_classic_kernel.mismatches());
    return;
#endif
  }
  s_soak_timed = static_cast<DiagSample *>(malloc(sizeof(s_diag_samples)));
  if (!s_soak_timed) {
    Serial.println("W390 SOAK ABORT: no memory for the timed records");
    return;
  }
  if (!tryReserveClassicSha()) {
    Serial.println("W390 SOAK ABORT: SHA engines unavailable");
    return;
  }
  Serial.printf("W390 SOAK BEGIN: %llu nonces per load, loads none,sw,spi,wifi,all; full_padding=%u latch=%u%s\n",
                static_cast<unsigned long long>(kSoakNoncesPerLoad), s_classic_full_padding,
                classic_kernel::kLatchWaitCycles,
#ifdef W390_SOAK_BREAK_LATCH
                " (SKIPPED: broken build)"
#else
                ""
#endif
                );
  xTaskCreatePinnedToCore(soakSwLoad, "SoakSw", 4096, nullptr, 1, nullptr, 1);
  xTaskCreatePinnedToCore(soakSpiLoad, "SoakSpi", 4096, nullptr, 1, nullptr, 1);
  xTaskCreatePinnedToCore(soakWifiLoad, "SoakWifi", 8192, nullptr, 1, nullptr, 1);
  xTaskCreatePinnedToCore(soakTask, "SoakKernel", 16384, nullptr, 3, nullptr, 0);
  while (!s_soak_done.load()) delay(1000);
  releaseClassicSha();
}
