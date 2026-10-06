// Known-answer windows for the ESP32-S3/C3 boot self-test of the batched SHA kernel
// (batchedKernelKnownAnswers in src/mining.cpp). Platform-independent so that the
// host tests (test/native_batched_sha.cpp) replay exactly the same table.
//
// Each window hashes nonces [nonce - pos, nonce - pos + count - 1] of a real block
// header, so the block's own nonce sits at offset `pos` and must come back as the
// candidate with `pos + 1` nonces completed; the remaining suffix (if any) is then
// hashed again as FX1's candidate hand-off and must finish with no candidate.
//
// No window contains a nonce whose low byte is 0. The kernel checks the job
// generation only after such nonces, so the self-test never consults it: if the
// stratum task starts a new job during the (~1 ms) self-test, the result cannot
// change. Checked at compile time below.
#pragma once
#include <stddef.h>
#include <stdint.h>

#include "crypto/BatchedSha.h"  // via the include path, so a test build can substitute it

namespace batched_sha_self_test {

constexpr int kBlocks = 2;
// Bitcoin genesis block and block 125552: 80-byte header, then its SHA-256d in digest byte order.
static const char *const kHeaders[kBlocks] = {
  "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
  "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122bc7f5d74df2b9441a42a14695"};
static const char *const kHashes[kBlocks] = {
  "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
  "1dbd981fe6985776b644b173a4d0385ddc1aa2a829688d1e0000000000000000"};
// Header bytes 76..79 read as a little-endian word. The self-test rejects a header
// whose nonce differs, so these cannot drift from kHeaders unnoticed.
constexpr uint32_t kNonces[kBlocks] = {0x7c2bac1dU, 0x9546a142U};

struct Window { int block; uint32_t pos, count; };
// Batch slot of the known nonce = pos % 32 (batches start at the window start).
constexpr Window kWindows[] = {
  {0,  0, 40},  // genesis: slot 0 of the first batch
  {0, 17, 57},  //          slot 17 (mid-batch)
  {0, 28, 68},  //          slot 28 (the latest slot reachable without a low-byte-0 nonce)
  {0, 20, 21},  //          last slot of a range that is one partial batch of 21
  {1,  0, 40},  // block 125552: slot 0 of the first batch
  {1, 17, 57},  //               slot 17 (mid-batch)
  {1, 31, 71},  //               slot 31, the last of a full batch
  {1, 35, 75},  //               slot 3 of the second batch
  {1, 40, 41},  //               last slot of a final partial batch (32 + 9)
};
constexpr size_t kWindowCount = sizeof(kWindows) / sizeof(kWindows[0]);

// True if [first, first + count - 1] (modulo 2^32) contains a nonce with low byte 0.
constexpr bool containsLowByteZero(uint32_t first, uint32_t count) {
  return count != 0 && ((0x100U - (first & 0xFFU)) & 0xFFU) < count;
}
constexpr bool windowValid(const Window &w) {
  return w.block >= 0 && w.block < kBlocks && w.pos < w.count &&
         !containsLowByteZero(kNonces[w.block] - w.pos, w.count);
}
constexpr bool isLastOfPartialBatchAfterFull(const Window &w) {
  return w.count > batched_sha::kBatch && w.count % batched_sha::kBatch != 0 && w.pos + 1 == w.count;
}
constexpr bool allValid(size_t i = 0) {
  return i == kWindowCount || (windowValid(kWindows[i]) && allValid(i + 1));
}
constexpr bool anyLastOfPartialBatchAfterFull(size_t i = 0) {
  return i != kWindowCount && (isLastOfPartialBatchAfterFull(kWindows[i]) || anyLastOfPartialBatchAfterFull(i + 1));
}
static_assert(allValid(), "a self-test window contains a low-byte-0 nonce (or is malformed)");
static_assert(anyLastOfPartialBatchAfterFull(), "no self-test hit at the last slot of a final partial batch");

}  // namespace batched_sha_self_test
