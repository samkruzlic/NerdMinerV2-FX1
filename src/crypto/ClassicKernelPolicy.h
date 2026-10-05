#pragma once
#include <atomic>
#include <stdint.h>
#include <string.h>

#include "ReferenceSha256.h"

// Platform-independent policy for the classic ESP32 "timed" SHA-256d kernel:
// which chips may use it, which nonces the runtime net re-hashes in software,
// and the one-way fallback to the polled kernel. The kernel itself lives in
// mining.cpp; everything here is exercised by the native test suite.
namespace classic_kernel {

// Waits of the timed kernel, in CPU cycles at 240 MHz, measured from a
// `rsr ccount` taken right after the command store. Measured on a classic
// ESP32 rev 3.1 (CYD) with the other CPU stalled and interrupts masked
// (our classic bench, 25 M nonces under five loads, 0 wrong):
//  - START/CONTINUE -> next command: 56 clean, 54 wrong for every nonce.
//  - LOAD -> next command or digest read: 2 clean, 1 wrong.
//  - CONTINUE -> block-3 padding store (words 8 and 15): >= 2 clean.
// All 16 SHA_TEXT words latch within 10 cycles of START/CONTINUE (bench
// latch probe). The bench's "0 cycles" still spent one counter read (~4
// cycles); writing with no wait at all after START gave every nonce wrong in
// FX1 (2026-10-04), so every write window waits kLatchWaitCycles first. The
// writes still finish inside the 64-cycle compression, so it costs nothing. BUSY reads idle 11 cycles after START
// with the stall, so it is NOT a usable clock and the kernel never polls it.
constexpr uint32_t kCommandWaitCycles = 64;  // START/CONTINUE -> next command
constexpr uint32_t kLoadWaitCycles = 6;      // LOAD -> next command / read
constexpr uint32_t kPaddingWaitCycles = 16;  // CONTINUE -> block-3 padding
constexpr uint32_t kLatchWaitCycles = 16;    // START -> next block's words

// The fixed waits are cycle counts, so they hold only at this clock.
constexpr uint32_t kRequiredCpuMhz = 240;
// esp_chip_info_t::revision is the wafer major version on ESP-IDF 4.4.
constexpr uint32_t kMinimumChipRevision = 3;

inline bool timedKernelEligible(uint32_t cpuMhz, uint32_t chipRevision) {
  return cpuMhz == kRequiredCpuMhz && chipRevision >= kMinimumChipRevision;
}

// About one nonce in 4,096 is re-hashed in software, after the locked group:
// one locked group in 4 is sampled, at an offset that rotates over all 1,024
// positions (the stride is odd), so the first and last nonce of a group (which
// take different write paths) and every nonce just after a stall are covered.
// groupIndex counts locked groups; an offset at or beyond the group's length
// (kNoSample, or a group cut short) means no sample in that group.
constexpr uint32_t kGroupNonces = 1024;  // CLASSIC_SHA_GROUP_NONCES
constexpr uint32_t kSampleGroupEvery = 4;
constexpr uint32_t kSampleStride = 337;
constexpr uint32_t kNoSample = kGroupNonces;
inline uint32_t sampleOffset(uint32_t groupIndex) {
  if (groupIndex % kSampleGroupEvery != 0) return kNoSample;
  return (groupIndex / kSampleGroupEvery * kSampleStride) % kGroupNonces;
}

// The word the kernel reads from SHA_TEXT[7] after the final LOAD (H7 of the
// second SHA-256, as a SHA word), computed with the reference SHA-256d.
inline uint32_t referenceFinalWord(const uint8_t rawHeader[80], uint32_t nonce) {
  uint8_t header[80], digest[32];
  memcpy(header, rawHeader, sizeof(header));
  memcpy(header + 76, &nonce, sizeof(nonce));  // little-endian, as submitted
  mining_validation::referenceSha256d(header, sizeof(header), digest);
  return (static_cast<uint32_t>(digest[28]) << 24) |
         (static_cast<uint32_t>(digest[29]) << 16) |
         (static_cast<uint32_t>(digest[30]) << 8) | digest[31];
}

// A known-answer range starts this many nonces before the block's own nonce,
// so the kernel must hash and reject them, then stop exactly on it.
constexpr uint32_t kKnownAnswerLead = 3;

enum class KnownAnswer { Pass, Fail, Cancelled };

// A range cut short by a job change (no nonce hashed, generation moved) says
// nothing about the kernel; anything else must be exactly the block's hit.
inline KnownAnswer classifyKnownAnswer(bool hit, uint32_t hitNonce, uint32_t completed,
                                       uint32_t knownNonce, bool hashMatches,
                                       bool generationChanged) {
  if (!hit && completed == 0 && generationChanged) return KnownAnswer::Cancelled;
  return hit && hitNonce == knownNonce && completed == kKnownAnswerLead + 1 && hashMatches
             ? KnownAnswer::Pass : KnownAnswer::Fail;
}

enum class Kernel : uint32_t { Polled = 0, Timed = 1 };

// One-way state: once a known answer, a sample or a submitted candidate
// disagrees, the timed kernel stays off until reboot; nothing can turn it back
// on. Counters are read by the monitor on the other CPU.
class FallbackState {
 public:
  // Boot: an eligible chip runs `count` known answers on the timed kernel
  // (run(i) -> KnownAnswer) and keeps it only if every one passes. Refused
  // once the timed kernel has ever been switched off.
  template <typename RunKnownAnswer>
  bool enableIfKnownAnswersPass(bool eligible, unsigned count, RunKnownAnswer &&run) {
    if (!eligible || disabled_.load(std::memory_order_acquire)) return false;
    active_.store(static_cast<uint32_t>(Kernel::Timed), std::memory_order_release);
    bool passed = count > 0;
    for (unsigned i = 0; i < count; ++i)
      if (run(i) != KnownAnswer::Pass) passed = false;
    if (!passed) disable();
    return passed;
  }
  // Once per new job while the timed kernel is active: one known answer, the
  // header rotating over `count`. A check cancelled by a job change is retried
  // on the next job; a failure switches to the polled kernel.
  template <typename RunKnownAnswer>
  void checkJob(uint32_t generation, unsigned count, RunKnownAnswer &&run) {
    if (!jobCheckDue(generation) || count == 0) return;
    const KnownAnswer outcome = run(nextHeader_ % count);
    if (outcome == KnownAnswer::Cancelled) return;
    nextHeader_ = (nextHeader_ + 1) % count;
    jobChecked(generation);
    if (outcome == KnownAnswer::Fail && timed()) disable();
  }
  // A candidate failed the pre-submit reference re-check. From the timed
  // kernel that proves the kernel wrong; returns whether this switched it off.
  bool invalidCandidate(bool fromTimedKernel) {
    if (!fromTimedKernel || !timed()) return false;
    disable();
    return true;
  }
  Kernel active() const {
    return static_cast<Kernel>(active_.load(std::memory_order_acquire));
  }
  bool timed() const { return active() == Kernel::Timed; }
  // Records one software comparison; returns whether it matched.
  bool recordSample(bool matched) {
    samples_.fetch_add(1, std::memory_order_relaxed);
    if (!matched) disable();
    return matched;
  }
  // Once per new job, while the timed kernel is active.
  bool jobCheckDue(uint32_t generation) const {
    return timed() && (!jobChecked_ || checkedGeneration_ != generation);
  }
  bool everDisabled() const { return disabled_.load(std::memory_order_acquire); }
  uint32_t samples() const { return samples_.load(std::memory_order_relaxed); }
  uint32_t mismatches() const { return mismatches_.load(std::memory_order_relaxed); }
  // The kernel reads this word once per locked group.
  const std::atomic<uint32_t> &activeWord() const { return active_; }

 private:
  void jobChecked(uint32_t generation) {
    checkedGeneration_ = generation;
    jobChecked_ = true;
  }
  void disable() {
    disabled_.store(true, std::memory_order_release);
    mismatches_.fetch_add(1, std::memory_order_relaxed);
    active_.store(static_cast<uint32_t>(Kernel::Polled), std::memory_order_release);
  }
  std::atomic<uint32_t> active_{static_cast<uint32_t>(Kernel::Polled)};
  std::atomic<uint32_t> samples_{0};
  std::atomic<uint32_t> mismatches_{0};
  std::atomic<bool> disabled_{false};
  uint32_t checkedGeneration_ = 0;
  unsigned nextHeader_ = 0;
  bool jobChecked_ = false;
};

inline const char *kernelName(Kernel kernel) {
  return kernel == Kernel::Timed ? "timed" : "polled";
}

}  // namespace classic_kernel
