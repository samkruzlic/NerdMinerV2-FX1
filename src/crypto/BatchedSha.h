// Batched SHA-256d nonce loop for the ESP32-S3 and ESP32-C3 SHA peripherals.
//
// Platform-independent bookkeeping; the register access is supplied by an
// Engine type (the S3/C3 peripheral on target, a model in test/native_batched_sha.cpp).
//
// Both engines load an arbitrary state from SHA_H, latches SHA_TEXT and SHA_H
// when START/CONTINUE is issued, and never modifies SHA_TEXT. A range is hashed
// in batches of up to kBatch nonces:
//   round 1: kBatch block-2 compressions from the job midstate; only SHA_TEXT[3]
//            (the nonce) changes, and the next nonce is written while BUSY.
//   round 2: kBatch final compressions; only SHA_TEXT[0..7] (the block-2 digest)
//            change, and the next digest is written while BUSY.
//
// Completed-work semantics are exactly those of FX1's sequential S2/S3/C3 loop:
//   - nonces are reported (filter, generation check) in ascending order;
//   - a filter pass for which onFilterPass() returns true ends the range with
//     that nonce counted; later nonces of its batch are discarded uncounted;
//   - after each nonce whose low byte is zero, stale() ends the range with that
//     nonce counted;
//   - the return value is the number of completed nonces (FX1's nonce_count).
//
// Engine requirements (static members):
//   begin()                         select SHA-256, zero SHA_TEXT[9..14]
//   loadBlock2(tail[3], nonce)      SHA_TEXT[0..8], [15] for block 2
//   setNonce(nonce)                 SHA_TEXT[3]
//   setState(midstate[8])           SHA_H[0..7]; engine idle
//   resume() / start()              CONTINUE / START
//   readState(out[8])               wait for idle, read SHA_H[0..7]
//   loadDigest(d[8])                SHA_TEXT[0..7]
//   loadFinalPadding()              SHA_TEXT[8], [15] for the final block
//   finalWord()                     wait for idle, return SHA_H[7]
//   readHead(out[8])                SHA_H[0..6] into out[0..6]; engine idle
#pragma once
#include <stdint.h>

namespace batched_sha {

constexpr uint32_t kBatch = 32;

struct NoRecord {
  inline void operator()(uint32_t, uint32_t) const {}
};

// always_inline: the caller decides placement (IRAM on target) and must not be cloned.
template <class Engine, class OnFilterPass, class OnFinalWord, class Stale>
inline __attribute__((always_inline)) uint32_t hashRange(const uint32_t midstate[8], const uint32_t tail[3],
                          uint32_t nonceStart, uint32_t nonceCount,
                          OnFilterPass &onFilterPass, OnFinalWord &onFinalWord,
                          Stale &stale)
{
  if (nonceCount == 0) return 0;
  uint32_t digests[kBatch][8];
  Engine::begin();
  uint32_t done = 0;
  while (done < nonceCount) {
    const uint32_t remaining = nonceCount - done;
    const uint32_t m = remaining < kBatch ? remaining : kBatch;
    const uint32_t first = nonceStart + done;  // modulo-2^32 nonce arithmetic

    // Round 1: block 2 of each nonce, from the midstate.
    Engine::loadBlock2(tail, first);
    for (uint32_t i = 0; i < m; ++i) {
      Engine::setState(midstate);
      Engine::resume();
      if (i + 1 < m) Engine::setNonce(first + i + 1);
      Engine::readState(digests[i]);
    }

    // Round 2: SHA-256 of each 32-byte block-2 digest.
    Engine::loadFinalPadding();
    Engine::loadDigest(digests[0]);
    Engine::start();
    for (uint32_t i = 0; i < m; ++i) {
      const uint32_t nonce = first + i;
      if (i + 1 < m) Engine::loadDigest(digests[i + 1]);
      const uint32_t word = Engine::finalWord();
      onFinalWord(nonce, word);
      if ((word >> 16) == 0) {  // FX1's 16-bit early filter
        uint32_t hash[8];
        Engine::readHead(hash);
        hash[7] = word;
        if (onFilterPass(nonce, hash)) return done + i + 1;
      }
      if ((nonce & 0xFFU) == 0 && stale()) return done + i + 1;
      if (i + 1 < m) Engine::start();
    }
    done += m;
  }
  return nonceCount;
}

}  // namespace batched_sha
