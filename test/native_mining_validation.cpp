#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chrono>
#include <vector>

#include "../src/crypto/ReferenceSha256.h"
#include "../src/crypto/MiningRangePolicy.h"
#include "../src/crypto/ShaResourcePolicy.h"
#include "../src/crypto/ClassicKernelPolicy.h"
#include "../src/crypto/W390SoakCompare.h"
#include "../src/ShaTests/nerdSHA256plus.h"

namespace {
void require(bool condition, const char *message) {
  if (!condition) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}

bool decodeHex(const char *hex, uint8_t *out, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    unsigned value = 0;
    if (sscanf(hex + i * 2, "%2x", &value) != 1) return false;
    out[i] = static_cast<uint8_t>(value);
  }
  return true;
}

void requireDigest(const uint8_t *data, size_t length, const char *expected) {
  uint8_t actual[32], wanted[32];
  require(decodeHex(expected, wanted, 32), "invalid test vector");
  mining_validation::referenceSha256(data, length, actual);
  require(memcmp(actual, wanted, 32) == 0, "SHA-256 vector mismatch");
}

void requireDoubleDigest(const char *headerHex, const char *expected) {
  uint8_t header[80], actual[32], wanted[32];
  require(decodeHex(headerHex, header, sizeof(header)), "invalid block header vector");
  require(decodeHex(expected, wanted, sizeof(wanted)), "invalid block hash vector");
  mining_validation::referenceSha256d(header, sizeof(header), actual);
  require(memcmp(actual, wanted, sizeof(actual)) == 0, "historical block hash mismatch");
}

void testReferenceVectors() {
  requireDigest(reinterpret_cast<const uint8_t *>(""), 0,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  requireDigest(reinterpret_cast<const uint8_t *>("abc"), 3,
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  uint8_t actual[32], wanted[32];
  mining_validation::referenceSha256d(nullptr, 0, actual);
  require(decodeHex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456", wanted, 32), "invalid SHA-256d vector");
  require(memcmp(actual, wanted, 32) == 0, "SHA-256d vector mismatch");

  uint8_t genesis[80];
  require(decodeHex(
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
      "29ab5f49ffff001d1dac2b7c", genesis, 80), "invalid genesis header");
  mining_validation::referenceSha256d(genesis, 80, actual);
  require(decodeHex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000", wanted, 32), "invalid genesis hash");
  require(memcmp(actual, wanted, 32) == 0, "genesis hash mismatch");

  requireDoubleDigest(
      "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000"
      "0982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649"
      "ffff001d01e36299",
      "4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000");
  requireDoubleDigest(
      "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd0020000000000"
      "6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d"
      "4c86041b0f2b5710",
      "06e533fd1ada86391f3f6c343204b0d278d4aaec1c0b20aa27ba030000000000");
  requireDoubleDigest(
      "04e0ff3feb36c62f0471cee034811019e43b14f459b50e00cea30a000000000000000000"
      "659cecf4a06ed500031b741384e87d40ce5c16c3ec8c09b09ffe4b863c218d1f282d3c61"
      "e4480f17d767c2ab",
      "59a90c771a9e84e9372b0b223485273a19ba3e0ffc9005000000000000000000");
}

void testTargetComparison() {
  uint8_t hash[32] = {}, target[32] = {};
  require(mining_validation::hashMeetsTarget(hash, target), "zero equality");
  memset(target, 0xff, 32);
  require(mining_validation::hashMeetsTarget(hash, target), "zero below maximum");
  memset(hash, 0xff, 32); memset(target, 0, 32);
  require(!mining_validation::hashMeetsTarget(hash, target), "maximum above zero");
  memset(target, 0xff, 32);
  require(mining_validation::hashMeetsTarget(hash, target), "maximum equality");
  for (int position = 0; position < 32; ++position) {
    memset(hash, 0x5a, 32); memset(target, 0x5a, 32);
    hash[position] = 0x59;
    for (int lower = 0; lower < position; ++lower) hash[lower] = 0xff;
    require(mining_validation::hashMeetsTarget(hash, target), "byte below target");
    hash[position] = 0x5b;
    for (int lower = 0; lower < position; ++lower) hash[lower] = 0;
    require(!mining_validation::hashMeetsTarget(hash, target), "byte above target");
  }
}

void testCandidateValidation() {
  uint8_t header[80] = {}, hash[32], target[32];
  mining_validation::referenceSha256d(header, sizeof(header), hash);
  memset(target, 0xff, sizeof(target));
  bool meets = false;
  require(mining_validation::validateCandidate(7, 7, header, hash, target, &meets) ==
              mining_validation::CandidateValidationResult::Valid && meets,
          "valid candidate rejected");
  require(mining_validation::validateCandidate(7, 8, header, hash, target, &meets) ==
              mining_validation::CandidateValidationResult::StaleGeneration,
          "stale candidate accepted");
  hash[0] ^= 1;
  require(mining_validation::validateCandidate(8, 8, header, hash, target, &meets) ==
              mining_validation::CandidateValidationResult::HashMismatch,
          "corrupt candidate accepted");
  mining_validation::referenceSha256d(header, sizeof(header), hash);
  memset(target, 0, sizeof(target));
  require(mining_validation::validateCandidate(0xffffffffU, 0xffffffffU,
              header, hash, target, &meets) ==
              mining_validation::CandidateValidationResult::Valid && !meets,
          "generation boundary or target result incorrect");
  require(mining_validation::validateCandidate(0xffffffffU, 0,
              header, hash, target, &meets) ==
              mining_validation::CandidateValidationResult::StaleGeneration,
          "wrapped generation accepted stale candidate");
}

void testForcedCandidateGate() {
  uint8_t header[80] = {}, hash[32], corrupt[32], target[32];
  for (uint32_t nonce = 0; nonce < 10000; ++nonce) {
    memcpy(header + 76, &nonce, sizeof(nonce));
    mining_validation::referenceSha256d(header, sizeof(header), hash);

    memcpy(target, hash, sizeof(target));
    bool meets = false;
    require(mining_validation::validateCandidate(42, 42, header, hash,
                target, &meets) == mining_validation::CandidateValidationResult::Valid && meets,
            "forced exact-target candidate rejected");

    memcpy(corrupt, hash, sizeof(corrupt));
    corrupt[nonce % sizeof(corrupt)] ^= 1;
    require(mining_validation::validateCandidate(42, 42, header, corrupt,
                target, &meets) == mining_validation::CandidateValidationResult::HashMismatch,
            "forced corrupt candidate accepted");
    require(mining_validation::validateCandidate(42, 43, header, hash,
                target, &meets) == mining_validation::CandidateValidationResult::StaleGeneration,
            "forced stale candidate accepted");
  }
}

void testGenerationAndRanges() {
  uint32_t nonce = 0xda54e700U;
  uint64_t expected = nonce;
  for (uint32_t range = 0; range < 100000; ++range) {
    const uint32_t count = (range & 1U) ? 16384U : 4096U;
    require(nonce == static_cast<uint32_t>(expected), "nonce range overlap or gap");
    nonce += count;
    expected += count;
  }

  uint8_t header[80] = {}, hash[32], target[32];
  memset(target, 0xff, sizeof(target));
  mining_validation::referenceSha256d(header, sizeof(header), hash);
  for (uint32_t generation = 1; generation < 100000; ++generation) {
    bool meets = false;
    require(mining_validation::validateCandidate(generation, generation + 1,
              header, hash, target, &meets) ==
              mining_validation::CandidateValidationResult::StaleGeneration,
            "rapid replacement accepted stale candidate");
  }
}

void testCandidateRangeResume() {
  uint8_t filterTarget[32] = {};
  require(!mining_validation::requiresFullDigest(1.0 / 65536.0, filterTarget), "filter threshold");
  require(mining_validation::requiresFullDigest(1e-6, filterTarget), "easy share bypasses filter");
  filterTarget[30] = 1;
  require(mining_validation::requiresFullDigest(1, filterTarget), "easy network target bypasses filter");
  require(mining_validation::candidateEligible(true, 1, 100), "network block suppressed by pool target");
  require(mining_validation::candidateEligible(false, 1, 1), "equal pool difficulty rejected");
  require(!mining_validation::candidateEligible(false, 1, 2), "under-difficulty share accepted");
  uint32_t millions = 7, remainder = 999999;
  uint64_t expected = 7999999;
  const uint32_t counts[] = {16384U, 4096U, 0xffffffffU};
  for (uint32_t count : counts) {
    expected += count;
    mining_validation::accumulateCompleted(millions, remainder, count);
    require(static_cast<uint64_t>(millions) * 1000000 + remainder == expected,
            "completed-work carry/overflow");
  }
  struct Range { uint32_t generation, nonce_start, nonce_count; };
  const uint32_t starts[] = {0U, 0xfffffff0U, 0xffffffffU};
  for (uint32_t prefixLimit : {7U, 64U}) for (uint32_t start : starts) {
    Range job{42, start, 4096};
    uint32_t completed = 0;
    while (job.nonce_count > 0) {
      require(job.nonce_start == start + completed, "candidate resume gap/overlap");
      const uint32_t prefix = job.nonce_count > prefixLimit ? prefixLimit : job.nonce_count;
      completed += prefix;
      if (!mining_validation::resumeCompletedPrefix(job, prefix, 42)) break;
    }
    require(completed == 4096, "candidate resume dropped suffix");
    require(!mining_validation::resumeCompletedPrefix(job, 1, 43), "stale suffix resumed");
    require(!mining_validation::resumeCompletedPrefix(job, 0, 42), "zero work resumed");
  }
  char text[9];
  mining_validation::formatSubmitNonce(text, 0);
  require(strcmp(text, "00000000") == 0, "zero nonce submission width");
  mining_validation::formatSubmitNonce(text, 1);
  require(strcmp(text, "00000001") == 0, "low nonce submission width");
  mining_validation::formatSubmitNonce(text, 0xffffffffU);
  require(strcmp(text, "ffffffff") == 0, "maximum nonce submission width");
}

uint64_t nextRandom(uint64_t &state) {
  state ^= state >> 12; state ^= state << 25; state ^= state >> 27;
  return state * 0x2545f4914f6cdd1dULL;
}

void testOptimizedDifferential(uint32_t cases) {
  uint64_t random = 0x4e6572644d696e65ULL;
  uint32_t filterPasses = 0;
  uint8_t padded[128], reference[32], optimized[32];
  uint32_t midstate[8], bake[17];
  for (uint32_t test = 0; test < cases; ++test) {
    for (size_t i = 0; i < 80; i += 8) {
      const uint64_t value = nextRandom(random);
      memcpy(padded + i, &value, 8);
    }
    memset(padded + 80, 0, 48); padded[80] = 0x80;
    padded[126] = 0x02; padded[127] = 0x80;
    nerd_mids(midstate, padded);
    nerd_sha256_bake(midstate, padded + 64, bake);
    const bool passed = nerd_sha256d_baked(midstate, padded + 64, bake, optimized);
    mining_validation::referenceSha256d(padded, 80, reference);
    const bool expected = reference[30] == 0 && reference[31] == 0;
    require(passed == expected, "early filter false result");
    if (passed) {
      ++filterPasses;
      require(memcmp(optimized, reference, 32) == 0, "optimized SHA mismatch");
    }
  }
  printf("Differential cases: %u; exact filter passes: %u\n", cases, filterPasses);
}

void benchmarkOptimized(uint32_t cases) {
  uint8_t padded[128] = {}, hash[32];
  uint32_t midstate[8], bake[17], passes = 0;
  padded[80] = 0x80; padded[126] = 0x02; padded[127] = 0x80;
  nerd_mids(midstate, padded);
  nerd_sha256_bake(midstate, padded + 64, bake);
  const auto start = std::chrono::steady_clock::now();
  for (uint32_t nonce = 0; nonce < cases; ++nonce) {
    memcpy(padded + 76, &nonce, sizeof(nonce));
    passes += nerd_sha256d_baked(midstate, padded + 64, bake, hash) ? 1U : 0U;
  }
  const double seconds = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - start).count();
  printf("Host optimized benchmark: %.0f nonce/s; passes=%u\n", cases / seconds, passes);
}
// Classic ESP32 timed kernel: gating, runtime-net sampling, known-answer
// verdicts and the one-way fallback (src/crypto/ClassicKernelPolicy.h).
void testClassicKernelPolicy() {
  using namespace classic_kernel;
  // Waits keep a margin over the bench's clean thresholds (56, 2 and 2 cycles).
  require(kCommandWaitCycles >= 56 && kLoadWaitCycles >= 2 && kPaddingWaitCycles >= 2,
          "timed waits below the measured clean thresholds");
  // Busy-engine writes wait for the latch: all words latch within 10 cycles of
  // START/CONTINUE (bench probe), and no wait at all failed on a rev 3.1 CYD.
  // Keep a margin over 10, for CONTINUE (padding) as for START.
  require(kLatchWaitCycles >= 10 + 4, "latch wait without margin over the measured 10 cycles");
  require(kPaddingWaitCycles >= kLatchWaitCycles, "padding written before CONTINUE has latched");
  // The writes after the latch (16 block-2 stores, up to 8 padding stores, at
  // least a cycle each) must still finish inside the 64-cycle compression they
  // overlap, or the overlap (and the kernel's gain) is gone.
  require(kLatchWaitCycles + 16 <= kCommandWaitCycles && kPaddingWaitCycles + 8 <= kCommandWaitCycles,
          "write window does not fit inside the compression");

  require(timedKernelEligible(240, 3), "240 MHz rev 3 is eligible");
  require(timedKernelEligible(240, 4), "later revisions are eligible");
  require(!timedKernelEligible(240, 2) && !timedKernelEligible(240, 1) && !timedKernelEligible(240, 0),
          "revisions before 3 are not eligible");
  require(!timedKernelEligible(160, 3) && !timedKernelEligible(80, 3) && !timedKernelEligible(241, 3),
          "cycle waits are valid at 240 MHz only");

  // One locked group in 4 is sampled, and over 4,096 consecutive groups (from
  // any counter value, across 2^32 too) every in-group offset exactly once:
  // about one nonce in 4,096, including each group's first and last nonce.
  for (uint32_t first : {0u, 1u, 3u, 0x12345u, 0xfffff000u, 0xffffff01u}) {
    static uint32_t seen[kGroupNonces];
    memset(seen, 0, sizeof(seen));
    uint32_t sampled = 0;
    for (uint32_t g = 0; g < 4 * kGroupNonces; ++g) {
      const uint32_t offset = sampleOffset(first + g);
      if (offset == kNoSample) continue;
      require(offset < kGroupNonces, "sample offset inside the group");
      ++seen[offset];
      ++sampled;
    }
    require(sampled == kGroupNonces, "one sampled group in 4");
    for (uint32_t o = 0; o < kGroupNonces; ++o) require(seen[o] == 1, "every in-group offset sampled once");
  }
  require(sampleOffset(0) == 0 && sampleOffset(1) == kNoSample && sampleOffset(4) == 337,
          "sample schedule");

  // The kernel's final word is H7 of the second SHA-256 as a SHA word; vectors
  // from Python hashlib, independent of the reference implementation.
  uint8_t zero[80] = {}, genesis[80];
  require(referenceFinalWord(zero, 0x12345678U) == 0xf72b47baU, "final word of a zero header");
  require(decodeHex(
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
      "29ab5f49ffff001d1dac2b7c", genesis, 80), "invalid genesis header");
  require(referenceFinalWord(genesis, 0x7c2bac1dU) == 0, "genesis final word");
  require(referenceFinalWord(genesis, 0x7c2bac1eU) == 0x4a7a229bU, "genesis nonce + 1 final word");

  // Known-answer verdicts: only the exact hit after the 3-nonce lead passes; a
  // range cancelled by a job change before any nonce is inconclusive.
  const uint32_t known = 0x7c2bac1dU;
  require(kKnownAnswerLead == 3, "known-answer lead");
  require(classifyKnownAnswer(true, known, 4, known, true, false) == KnownAnswer::Pass, "exact hit passes");
  require(classifyKnownAnswer(true, known, 4, known, true, true) == KnownAnswer::Pass, "completed hit passes after a job change");
  require(classifyKnownAnswer(true, known - 1, 3, known, true, false) == KnownAnswer::Fail, "early false hit fails");
  require(classifyKnownAnswer(true, known, 3, known, true, false) == KnownAnswer::Fail, "wrong completed count fails");
  require(classifyKnownAnswer(true, known, 4, known, false, false) == KnownAnswer::Fail, "wrong digest fails");
  require(classifyKnownAnswer(false, 0xffffffffU, 8, known, false, false) == KnownAnswer::Fail, "missed hit fails");
  require(classifyKnownAnswer(false, 0xffffffffU, 8, known, false, true) == KnownAnswer::Fail, "missed hit fails despite a job change");
  require(classifyKnownAnswer(false, 0xffffffffU, 0, known, false, true) == KnownAnswer::Cancelled, "cancelled range is inconclusive");
  require(classifyKnownAnswer(false, 0xffffffffU, 0, known, false, false) == KnownAnswer::Fail, "empty range without a job change fails");

  // Boot: only an eligible chip whose known answers all pass on the timed
  // kernel keeps it; each answer runs with the timed kernel selected.
  unsigned calls = 0;
  bool ranTimed = true;
  FallbackState state;
  auto passAll = [&](unsigned i) { ranTimed = ranTimed && state.timed(); require(i == calls++, "header order"); return KnownAnswer::Pass; };
  require(state.active() == Kernel::Polled && !state.jobCheckDue(1), "polled until enabled");
  require(!state.enableIfKnownAnswersPass(false, 3, passAll) && calls == 0 && !state.timed(),
          "ineligible chip stays polled, no known answers run");
  require(state.enableIfKnownAnswersPass(true, 3, passAll) && calls == 3 && ranTimed, "known answers run on the timed kernel");
  require(state.timed() && state.activeWord().load() == 1 && state.mismatches() == 0, "eligible chip enables the timed kernel");
  for (KnownAnswer bad : {KnownAnswer::Fail, KnownAnswer::Cancelled}) {
    for (unsigned failing = 0; failing < 3; ++failing) {
      FallbackState boot;
      unsigned runs = 0;
      require(!boot.enableIfKnownAnswersPass(true, 3, [&](unsigned i) {
                ++runs; return i == failing ? bad : KnownAnswer::Pass; }),
              "a failed boot known answer is reported");
      require(!boot.timed() && boot.mismatches() == 1 && boot.everDisabled(), "failed boot known answer selects polled");
      require(runs == 3, "every boot known answer runs and is logged");
    }
  }
  {
    FallbackState none;
    require(!none.enableIfKnownAnswersPass(true, 0, passAll) && !none.timed(), "no known answers, no timed kernel");
  }

  // Per job: one known answer per new job while timed, rotating headers; a
  // cancelled check is retried on the next job; a failure switches to polled.
  std::vector<unsigned> headers;
  KnownAnswer next = KnownAnswer::Pass;
  auto jobRun = [&](unsigned i) { headers.push_back(i); return next; };
  state.checkJob(7, 3, jobRun);
  require(headers.size() == 1 && headers[0] == 0 && !state.jobCheckDue(7), "first job checked with header 0");
  state.checkJob(7, 3, jobRun);
  require(headers.size() == 1, "once per job");
  next = KnownAnswer::Cancelled;
  state.checkJob(8, 3, jobRun);
  require(headers.size() == 2 && headers[1] == 1 && state.jobCheckDue(8) && state.timed(), "cancelled check not counted");
  next = KnownAnswer::Pass;
  state.checkJob(9, 3, jobRun);
  require(headers.size() == 3 && headers[2] == 1 && !state.jobCheckDue(9), "cancelled header retried on the next job");
  state.checkJob(10, 3, jobRun);
  state.checkJob(11, 3, jobRun);
  require(headers.size() == 5 && headers[3] == 2 && headers[4] == 0, "headers rotate");
  require(state.recordSample(true) && state.timed(), "matching sample keeps the timed kernel");
  require(state.samples() == 1 && state.mismatches() == 0, "sample counted");
  auto alwaysPass = [](unsigned) { return KnownAnswer::Pass; };
  {
    FallbackState jobFail;
    require(jobFail.enableIfKnownAnswersPass(true, 3, alwaysPass), "job-check state enabled");
    unsigned runs = 0;
    jobFail.checkJob(1, 3, [&](unsigned) { ++runs; return KnownAnswer::Fail; });
    require(runs == 1 && !jobFail.timed() && jobFail.mismatches() == 1, "failed job known answer selects polled");
    jobFail.checkJob(2, 3, [&](unsigned) { ++runs; return KnownAnswer::Pass; });
    require(runs == 1, "no job checks once polled");
  }

  // Samples and submitted candidates: any mismatch switches to polled for good.
  require(!state.recordSample(false), "mismatching sample reported");
  require(state.active() == Kernel::Polled && state.activeWord().load() == 0, "mismatch selects the polled kernel");
  require(state.samples() == 2 && state.mismatches() == 1, "mismatch counted");
  require(state.recordSample(true) && !state.timed(), "a later match does not restore the timed kernel");
  require(!state.jobCheckDue(12), "no job checks once polled");
  require(strcmp(kernelName(state.active()), "polled") == 0 && strcmp(kernelName(Kernel::Timed), "timed") == 0,
          "kernel names");
  {
    FallbackState candidate;
    require(candidate.enableIfKnownAnswersPass(true, 3, alwaysPass), "candidate state enabled");
    require(!candidate.invalidCandidate(false) && candidate.timed(), "a polled kernel's invalid candidate keeps timed");
    require(candidate.invalidCandidate(true) && !candidate.timed() && candidate.mismatches() == 1,
            "a timed kernel's invalid candidate selects polled");
    require(!candidate.invalidCandidate(true) && candidate.mismatches() == 1, "switched once");
  }

  // One-way in the type: nothing re-enables the timed kernel after a switch.
  unsigned refusedRuns = 0;
  auto counted = [&](unsigned) { ++refusedRuns; return KnownAnswer::Pass; };
  require(!state.enableIfKnownAnswersPass(true, 3, counted) && !state.timed() && refusedRuns == 0,
          "re-enable refused after a sample mismatch");
  {
    FallbackState afterCandidate;
    afterCandidate.enableIfKnownAnswersPass(true, 3, alwaysPass);
    afterCandidate.invalidCandidate(true);
    require(!afterCandidate.enableIfKnownAnswersPass(true, 3, counted) && !afterCandidate.timed() && refusedRuns == 0,
            "re-enable refused after an invalid candidate");
    FallbackState afterBoot;
    afterBoot.enableIfKnownAnswersPass(true, 3, [](unsigned) { return KnownAnswer::Fail; });
    require(!afterBoot.enableIfKnownAnswersPass(true, 3, counted) && !afterBoot.timed() && refusedRuns == 0,
            "re-enable refused after a failed boot known answer");
  }
  puts("Classic timed-kernel policy: gating, sampling, known answers and fallback passed.");
}
// W390 soak comparison (development-only, src/crypto/W390SoakCompare.h): it
// must count every kind of kernel error once, and cover every nonce exactly once.
struct SoakRecord { uint32_t nonce, word; bool hit; uint8_t hash[32]; };

void soakRecords(const uint8_t header[80], uint32_t start, uint32_t count, SoakRecord *out) {
  for (uint32_t i = 0; i < count; ++i) {
    uint8_t full[80], digest[32];
    memcpy(full, header, 80);
    const uint32_t nonce = start + i;
    memcpy(full + 76, &nonce, 4);
    mining_validation::referenceSha256d(full, 80, digest);
    out[i].nonce = nonce;
    out[i].word = (uint32_t(digest[28]) << 24) | (uint32_t(digest[29]) << 16) |
                  (uint32_t(digest[30]) << 8) | digest[31];
    out[i].hit = digest[30] == 0 && digest[31] == 0;
    memcpy(out[i].hash, digest, 32);
  }
}

struct SoakRun {
  w390_soak::Totals totals;
  uint32_t reports = 0;
  w390_soak::Kind lastKind = w390_soak::Kind::Coverage;
  uint32_t lastNonce = 0;
};

SoakRun soakCompare(const uint8_t *header, uint32_t start, uint32_t count,
                    const SoakRecord *timed, uint32_t timedRecords, uint32_t timedCompleted,
                    const SoakRecord *polled, uint32_t polledRecords, uint32_t polledCompleted,
                    uint32_t phase) {
  SoakRun run;
  w390_soak::compareGroup(header, start, count, timed, timedRecords, timedCompleted,
      polled, polledRecords, polledCompleted, phase, run.totals,
      [&](w390_soak::Kind kind, uint32_t nonce, uint32_t, uint32_t, uint32_t) {
        ++run.reports; run.lastKind = kind; run.lastNonce = nonce;
      });
  return run;
}

void testW390SoakCompare() {
  using w390_soak::Kind;
  static SoakRecord good[1024], timed[1024], polled[1024];
  uint8_t genesis[80];
  require(decodeHex(
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
      "29ab5f49ffff001d1dac2b7c", genesis, 80), "invalid genesis header");
  const uint32_t start = 0x7c2bac1dU - 500, count = 1024, phase = 5;
  soakRecords(genesis, start, count, good);
  auto reset = [&] { memcpy(timed, good, sizeof(good)); memcpy(polled, good, sizeof(good)); };

  reset();
  SoakRun run = soakCompare(genesis, start, count, timed, count, count, polled, count, count, phase);
  require(run.totals.mismatches() == 0 && run.reports == 0, "soak: clean group reported a mismatch");
  require(run.totals.compared == count, "soak: clean group not counted once");
  require(run.totals.softwareChecked == count / 64, "soak: one nonce in 64 re-hashed");
  require(run.totals.hits >= 1, "soak: the genesis hit was not seen");
  const uint32_t cleanHits = run.totals.hits;

  const uint32_t plain = 3, sampled = (phase - start) & 63;  // indices: not sampled / sampled
  require(((start + plain) & 63) != phase && ((start + sampled) & 63) == phase, "soak: index choice");
  reset(); timed[plain].word ^= 0x100;
  run = soakCompare(genesis, start, count, timed, count, count, polled, count, count, phase);
  require(run.totals.timedPolled == 1 && run.totals.mismatches() == 1 && run.reports == 1 &&
          run.lastKind == Kind::TimedPolled && run.lastNonce == start + plain, "soak: timed word error");
  reset(); timed[sampled].word ^= 1;
  run = soakCompare(genesis, start, count, timed, count, count, polled, count, count, phase);
  require(run.totals.timedPolled == 1 && run.totals.timedSoftware == 1 && run.totals.polledSoftware == 0,
          "soak: sampled timed error");
  reset(); polled[sampled].word ^= 1;
  run = soakCompare(genesis, start, count, timed, count, count, polled, count, count, phase);
  require(run.totals.timedPolled == 1 && run.totals.polledSoftware == 1 && run.totals.timedSoftware == 0,
          "soak: sampled polled error");
  reset(); timed[sampled].word ^= 1; polled[sampled].word ^= 1;  // both wrong, identically
  run = soakCompare(genesis, start, count, timed, count, count, polled, count, count, phase);
  require(run.totals.timedPolled == 0 && run.totals.timedSoftware == 1 && run.totals.polledSoftware == 1,
          "soak: identical error in both kernels");

  const uint32_t hit = 500;  // the genesis nonce
  require(good[hit].hit, "soak: genesis nonce is a filter hit");
  reset(); timed[hit].hash[0] ^= 1;
  run = soakCompare(genesis, start, count, timed, count, count, polled, count, count, phase);
  require(run.totals.digest == 1 && run.totals.mismatches() == 1, "soak: timed hit digest error");
  reset(); polled[hit].hash[5] ^= 1;
  run = soakCompare(genesis, start, count, timed, count, count, polled, count, count, phase);
  require(run.totals.digest == 1, "soak: polled hit digest error");
  reset(); timed[plain].hit = true;  // a false filter hit
  run = soakCompare(genesis, start, count, timed, count, count, polled, count, count, phase);
  require(run.totals.digest == 1 && run.totals.hits == cleanHits + 1, "soak: false hit");

  reset();
  run = soakCompare(genesis, start, count, timed, count - 1, count, polled, count, count, phase);
  require(run.totals.coverage == 1 && run.totals.compared == 0, "soak: missing record");
  run = soakCompare(genesis, start, count, timed, count, count, polled, count - 1, count, phase);
  require(run.totals.coverage == 1 && run.totals.compared == 0, "soak: missing polled record");
  run = soakCompare(genesis, start, count, timed, count, count - 1, polled, count, count, phase);
  require(run.totals.coverage == 1 && run.totals.compared == 0, "soak: short completed count");
  run = soakCompare(genesis, start, count, timed, count, count, polled, count, count + 1, phase);
  require(run.totals.coverage == 1 && run.totals.compared == 0, "soak: long completed count");
  reset(); timed[700] = timed[699];  // a nonce hashed twice, one skipped
  run = soakCompare(genesis, start, count, timed, count, count, polled, count, count, phase);
  require(run.totals.coverage == 1 && run.totals.compared == 0, "soak: duplicated nonce");
  reset(); polled[0].nonce += 1;
  run = soakCompare(genesis, start, count, timed, count, count, polled, count, count, phase);
  require(run.totals.coverage == 1 && run.totals.compared == 0, "soak: polled nonce out of place");
  puts("W390 soak comparison: word, software, digest and coverage errors all counted.");
}
}  // namespace

int main(int argc, char **argv) {
  require(!secureTransportActive(), "transport initially idle");
  {
    SecureTransportWork plain(false);
    require(!secureTransportActive(), "plain request does not reserve SHA policy");
    SecureTransportWork secure(true);
    require(secureTransportActive(), "secure request selects software fallback");
    {
      SecureTransportWork nested(true);
      require(secureTransportSessions().load() == 2, "nested transport ownership");
    }
    require(secureTransportActive(), "nested cleanup preserves outer ownership");
  }
  require(!secureTransportActive(), "transport cleanup restores hardware eligibility");
  try { SecureTransportWork secure(true); throw 1; }
  catch (int) {}
  require(!secureTransportActive(), "error cleanup restores hardware eligibility");
  require(!secureTransportCpuActive() && !secureTransportHandshakeActive(), "TLS CPU ownership initially idle");
  {
    SecureTransportCpuWork records(true);
    require(secureTransportCpuActive() && !secureTransportHandshakeActive(), "record I/O selects light CPU window");
    {
      SecureTransportCpuWork handshake(true, true);
      require(secureTransportHandshakeActive(), "handshake selects intensive CPU window");
    }
    require(secureTransportCpuActive() && !secureTransportHandshakeActive(), "nested handshake cleanup preserves record owner");
  }
  try { SecureTransportCpuWork handshake(true, true); throw 1; }
  catch (int) {}
  require(!secureTransportCpuActive() && !secureTransportHandshakeActive(), "TLS CPU ownership restored on error");
  uint32_t cases = argc >= 2 ? static_cast<uint32_t>(strtoul(argv[1], nullptr, 10)) : 2000000;
  testReferenceVectors();
  testTargetComparison();
  testCandidateValidation();
  testForcedCandidateGate();
  testGenerationAndRanges();
  testCandidateRangeResume();
  testClassicKernelPolicy();
  testW390SoakCompare();
  testOptimizedDifferential(cases);
  if (argc == 3 && strcmp(argv[2], "--bench") == 0) benchmarkOptimized(cases);
  puts("All mining validation tests passed.");
  return 0;
}
