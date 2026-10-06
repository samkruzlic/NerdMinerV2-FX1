// Development-only physical differential test of the production ESP32-S3/C3 SHA
// kernel (NERDMINER_SHA_DIAGNOSTICS). Included from mining.cpp after the kernel.
//
// For the kernel the boot self-test selects, under three loads and three public headers:
//   loads: none / software SHA-256 / peripheral register traffic. Dual core (S3): on the
//   other core, continuously. Single core (C3): a higher-priority task preempting the
//   kernel every tick for ~300 us, and for register traffic also a 20 kHz timer
//   interrupt (Wi-Fi/stratum/display-like interruptions);
//   - every nonce's final digest word vs the reference SHA-256d, over ranges that
//     are not multiples of the batch, start unaligned and wrap through 0;
//   - candidate mode (every 16-bit filter pass is a candidate): each candidate's
//     full hash is validated, ranges are resumed exactly as finishWorkerRange
//     does, and completed counts must add up with no gap or overlap;
//   - SHA_TEXT is scribbled before every range, as another SHA user would.
#pragma once
#include <driver/periph_ctrl.h>
#include <soc/gpio_reg.h>

#ifndef NERDMINER_BATCHED_SHA_DIAG_NONCES
#define NERDMINER_BATCHED_SHA_DIAG_NONCES 250000
#endif
#if SOC_CPU_CORES_NUM > 1
static inline uint32_t batchedDiagCycles() { uint32_t c; __asm__ __volatile__("rsr %0, ccount" : "=a"(c)); return c; }
#else
#include <hal/cpu_hal.h>
static inline uint32_t batchedDiagCycles() { return cpu_hal_get_cycle_count(); }
#endif

namespace {
static std::atomic<int> s_bdiag_load(0);        // 0 none, 1 software SHA, 2 register traffic
static std::atomic<bool> s_bdiag_stop(false);
static std::atomic<bool> s_bdiag_done(false);
static volatile uint32_t s_bdiag_sink;

static volatile uint32_t s_bdiag_irqs;
static void IRAM_ATTR batchedDiagTimerIsr()
{
  const uint32_t i = s_bdiag_irqs;
  REG_WRITE(DR_REG_SPI2_BASE + 0x98 + 4 * (i & 15), i);
  s_bdiag_sink = REG_READ(DR_REG_SPI2_BASE + 0x98 + 4 * ((i + 5) & 15)) ^ REG_READ(GPIO_IN_REG);
  s_bdiag_irqs = i + 1;
}

static void batchedDiagOtherCore(void *)
{
  uint8_t input[128] = {}, digest[32];
  uint32_t i = 0;
  uint32_t sliceStart = micros();
  while (!s_bdiag_stop.load()) {
    const int load = s_bdiag_load.load();
#if SOC_CPU_CORES_NUM == 1
    // Single core: work in ~300 us slices once per tick, preempting the kernel.
    if (load == 0 || micros() - sliceStart > 300) { vTaskDelay(1); sliceStart = micros(); continue; }
#endif
    if (load == 1) {
      memcpy(input, &i, sizeof(i));
      mining_validation::referenceSha256(input, sizeof(input), digest);
      s_bdiag_sink = digest[0];
    } else if (load == 2) {
      // SPI2 data buffer + GPIO input: register traffic like a display driver's
      REG_WRITE(DR_REG_SPI2_BASE + 0x98 + 4 * (i & 15), i);
      s_bdiag_sink = REG_READ(DR_REG_SPI2_BASE + 0x98 + 4 * ((i + 7) & 15));
      s_bdiag_sink = REG_READ(GPIO_IN_REG);
    } else if ((i & 1023) == 0) {
      vTaskDelay(1);
    }
    ++i;
  }
  s_bdiag_done.store(true);
  vTaskDelete(nullptr);
}

static uint32_t s_bdiag_words[4096];
static uint32_t s_bdiag_checked = 0, s_bdiag_errors = 0, s_bdiag_passes = 0, s_bdiag_candidates = 0;

struct BatchedDiagRecorder {
  uint32_t first, count;
  inline void operator()(uint32_t nonce, uint32_t word) {
    const uint32_t i = nonce - first;
    if (i < 4096) s_bdiag_words[i] = word;
    ++count;
  }
};

// Recording instantiations of the production kernels, in IRAM like production.
static BatchedDiagRecorder *s_bdiag_rec;
static uint32_t IRAM_ATTR __attribute__((noinline)) batchedDiagG32(const JobRequest *job, JobResult *result)
{ return runBatchedRange<BatchedShaEngineG32>(job, result, *s_bdiag_rec); }
static uint32_t IRAM_ATTR __attribute__((noinline)) batchedDiagF32(const JobRequest *job, JobResult *result)
{ return runBatchedRange<BatchedShaEngineF32>(job, result, *s_bdiag_rec); }

static bool batchedDiagCompare(const JobRequest &job, uint32_t first, uint32_t count)
{
  alignas(4) uint8_t header[80], reference[32];
  memcpy(header, job.raw_header, 80);
  for (uint32_t i = 0; i < count; ++i) {
    const uint32_t nonce = first + i;
    memcpy(header + 76, &nonce, 4);
    mining_validation::referenceSha256d(header, 80, reference);
    uint32_t word;
    memcpy(&word, reference + 28, 4);
    ++s_bdiag_checked;
    if ((word >> 16) == 0) ++s_bdiag_passes;
    if (word != s_bdiag_words[i]) {
      if (++s_bdiag_errors <= 5)
        Serial.printf("SHA DIAG MISMATCH nonce=%08x hardware=%08x reference=%08x\n", nonce, s_bdiag_words[i], word);
    }
  }
  return true;
}

// One recorded range through the production kernel; returns completed nonces.
static uint32_t batchedDiagRecordedRange(JobRequest &job, uint32_t first, uint32_t count)
{
  static JobResult result;
  memset(&result, 0, sizeof(result));
  job.nonce_start = first; job.nonce_count = count;
  result.nonce_count = count;
  BatchedDiagRecorder rec{first, 0};
  esp_sha_acquire_hardware();
  scribbleShaText();
  s_bdiag_rec = &rec;
  result.nonce_count = s_batched_sha_kernel == BATCHED_SHA_G32 ? batchedDiagG32(&job, &result) : batchedDiagF32(&job, &result);
  esp_sha_release_hardware();
  if (result.nonce_count != count || rec.count != count || result.has_candidate) {
    ++s_bdiag_errors;
    Serial.printf("SHA DIAG RANGE ERROR start=%08x count=%u completed=%u recorded=%u\n",
                  first, count, result.nonce_count, rec.count);
  }
  batchedDiagCompare(job, first, rec.count < count ? rec.count : count);
  return result.nonce_count;
}
}  // namespace

void runBatchedShaDiagnostics()
{
  Serial.println("SHA DIAG BEGIN (" CONFIG_IDF_TARGET "): production kernel vs reference SHA-256d; public Bitcoin headers only");
  selectBatchedShaKernel();
  if (s_batched_sha_kernel == BATCHED_SHA_ORIGINAL) {
    Serial.println("SHA DIAG: original loop selected; it has no per-nonce hook. Nothing to check.");
    return;
  }
  periph_module_enable(PERIPH_SPI2_MODULE);
  TaskHandle_t other = nullptr;
#if SOC_CPU_CORES_NUM > 1
  const int otherCore = xPortGetCoreID() == 0 ? 1 : 0;
  const UBaseType_t otherPriority = 2;
#else
  const int otherCore = 0;
  const UBaseType_t otherPriority = uxTaskPriorityGet(nullptr) + 2;  // preempts the kernel
  hw_timer_t *timer = timerBegin(0, 80, true);                       // 1 MHz
  timerAttachInterrupt(timer, &batchedDiagTimerIsr, true);
  timerAlarmWrite(timer, 50, true);                                   // 20 kHz
#endif
  if (xTaskCreatePinnedToCore(batchedDiagOtherCore, "ShaOther", 4096, nullptr, otherPriority, &other, otherCore) != pdPASS) {
    Serial.println("SHA DIAG concurrent task unavailable");
    return;
  }

  // Production-kernel cycle cost (no per-nonce hook), other core idle.
  {
    static JobRequest job; static JobResult result;
    memset(&job, 0, sizeof(job)); memset(&result, 0, sizeof(result));
    for (int i = 0; i < 80; ++i) job.raw_header[i] = (uint8_t)(i * 37 + 11);
    memcpy(job.sha_buffer, job.raw_header, 80);
    job.generation = s_working_generation.load(); job.difficulty = 1e100;
    job.nonce_start = 0xda54e700U; job.nonce_count = 16384; result.nonce_count = job.nonce_count;
    esp_sha_acquire_hardware();
    batchedHardwareMidstate(job);
    const uint32_t t0 = batchedDiagCycles();
    runBatchedShaRange(s_batched_sha_kernel, &job, &result);
    const uint32_t cycles = batchedDiagCycles() - t0;
    esp_sha_release_hardware();
    Serial.printf("SHA DIAG production kernel: %u cycles/nonce over 16384 nonces = %.1f kH/s at %u MHz\n",
                  cycles / 16384, getCpuFrequencyMhz() * 1e3 / (cycles / 16384.0), getCpuFrequencyMhz());
  }

  const char *headers[] = {
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
    "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
    "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122bc7f5d74df2b9441a42a14695"};
  const uint32_t boundaries[] = {0, 1, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffe5};
  const uint32_t kRecorded = NERDMINER_BATCHED_SHA_DIAG_NONCES;  // per header and load

  for (int load = 0; load < 3; ++load) {
    s_bdiag_load.store(load);
#if SOC_CPU_CORES_NUM == 1
    if (load == 2) timerAlarmEnable(timer); else timerAlarmDisable(timer);
#endif
    vTaskDelay(10);
    for (int h = 0; h < 3; ++h) {
      static JobRequest job;
      memset(&job, 0, sizeof(job));
      for (int i = 0; i < 80; ++i) { char pair[3] = {headers[h][2*i], headers[h][2*i+1], 0}; job.raw_header[i] = strtoul(pair, nullptr, 16); }
      memcpy(job.sha_buffer, job.raw_header, 80);
      esp_sha_acquire_hardware();
      batchedHardwareMidstate(job);
      esp_sha_release_hardware();
      job.generation = s_working_generation.load();
      job.difficulty = 1e100;
      memset(job.network_target, 0, sizeof(job.network_target));
      uint32_t known; memcpy(&known, job.raw_header + 76, 4);

      // Boundary and partial-batch ranges.
      for (uint32_t b : boundaries)
        for (uint32_t count : {1U, 33U, 95U}) batchedDiagRecordedRange(job, b, count);
      batchedDiagRecordedRange(job, known - 40, 81);

      // Bulk: unaligned ranges of 4093 (not a multiple of 32), random start.
      uint32_t start = esp_random(), done = 0;
      while (done < kRecorded && s_bdiag_errors == 0) {
        const uint32_t count = kRecorded - done < 4093 ? kRecorded - done : 4093;
        done += batchedDiagRecordedRange(job, start + done, count);
        vTaskDelay(1);
      }

      // Candidate mode over the first 131072 nonces of the bulk range.
      job.difficulty = 0;
      const uint32_t passesBefore = s_bdiag_passes;
      uint32_t candidates = 0, completed = 0;
      {
        // reference filter passes for the same nonces
        alignas(4) uint8_t header[80], reference[32];
        memcpy(header, job.raw_header, 80);
        uint32_t refPasses = 0;
        for (uint32_t i = 0; i < 131072; ++i) {
          const uint32_t nonce = start + i;
          memcpy(header + 76, &nonce, 4);
          mining_validation::referenceSha256d(header, 80, reference);
          if (reference[30] == 0 && reference[31] == 0) ++refPasses;
          if ((i & 4095) == 0) vTaskDelay(1);
        }
        static JobResult result;
        job.nonce_start = start; job.nonce_count = 131072;
        while (job.nonce_count > 0) {
          memset(&result, 0, sizeof(result));
          result.nonce_count = job.nonce_count;
          esp_sha_acquire_hardware();
          scribbleShaText();
          runBatchedShaRange(s_batched_sha_kernel, &job, &result);
          esp_sha_release_hardware();
          completed += result.nonce_count;
          if (result.has_candidate) {
            ++candidates;
            bool block = false;
            if (mining_validation::validateCandidate(job.generation, job.generation, result.raw_header, result.hash,
                    job.network_target, &block) != mining_validation::CandidateValidationResult::Valid ||
                result.nonce != job.nonce_start + result.nonce_count - 1) {
              ++s_bdiag_errors;
              Serial.printf("SHA DIAG CANDIDATE ERROR nonce=%08x\n", result.nonce);
            }
          }
          if (!mining_validation::resumeCompletedPrefix(job, result.nonce_count, job.generation)) break;
          vTaskDelay(1);
        }
        if (completed != 131072 || candidates != refPasses) {
          ++s_bdiag_errors;
          Serial.printf("SHA DIAG CANDIDATE COUNT ERROR completed=%u candidates=%u reference passes=%u\n",
                        completed, candidates, refPasses);
        }
      }
      (void)passesBefore;
      s_bdiag_candidates += candidates;
      Serial.printf("SHA DIAG load=%d header=%d checked=%u filter passes=%u candidates=%u (completed %u) errors=%u\n",
                    load, h, s_bdiag_checked, s_bdiag_passes, s_bdiag_candidates, completed, s_bdiag_errors);
      if (s_bdiag_errors) break;
    }
    if (s_bdiag_errors) break;
  }
  s_bdiag_stop.store(true);
#if SOC_CPU_CORES_NUM == 1
  timerAlarmDisable(timer);
#endif
  while (!s_bdiag_done.load()) vTaskDelay(1);
  Serial.printf("SHA DIAG COMPLETE kernel=%s timer irqs=%u checked=%u filter passes=%u candidates=%u errors=%u\n",
                kBatchedShaKernelNames[s_batched_sha_kernel], s_bdiag_irqs, s_bdiag_checked, s_bdiag_passes, s_bdiag_candidates,
                s_bdiag_errors);
}
