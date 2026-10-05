#pragma once
#include <stdint.h>
#include <string.h>

#include "ClassicKernelPolicy.h"
#include "ReferenceSha256.h"

// Development-only (W390 kernel soak): compares one group of nonces hashed by
// the timed kernel against the same group hashed by the polled kernel, plus a
// software re-hash of one nonce in 64 and of every 16-bit filter hit.
// Platform-independent so the native suite can feed it broken kernel output.
namespace w390_soak {

constexpr uint32_t kSoftwareMask = 63;  // one nonce in 64 re-hashed in software

enum class Kind { Coverage, TimedPolled, TimedSoftware, PolledSoftware, Digest };

inline const char *kindName(Kind kind) {
  switch (kind) {
    case Kind::Coverage: return "coverage";
    case Kind::TimedPolled: return "timed-vs-polled";
    case Kind::TimedSoftware: return "timed-vs-software";
    case Kind::PolledSoftware: return "polled-vs-software";
    default: return "full-digest";
  }
}

struct Totals {
  uint64_t compared = 0;          // nonces compared timed vs polled, each once
  uint32_t coverage = 0;          // groups with a missing, extra or misplaced nonce
  uint32_t timedPolled = 0;
  uint32_t softwareChecked = 0;
  uint32_t timedSoftware = 0;
  uint32_t polledSoftware = 0;
  uint32_t hits = 0;              // nonces either kernel reported as a filter hit
  uint32_t digest = 0;            // hits whose flags or full digests disagree
  uint32_t mismatches() const {
    return coverage + timedPolled + timedSoftware + polledSoftware + digest;
  }
};

// Record: any type with nonce, word (SHA_TEXT[7] after the final LOAD), hit
// and hash (the kernel's full digest, valid when hit). `timedCompleted` and
// `polledCompleted` are the kernels' own completed-nonce counts. Every nonce of
// [start, start + count) must appear exactly once, in order, in both.
// report(kind, nonce, timedWord, polledWord, softwareWord) is called per mismatch.
template <typename Record, typename Report>
void compareGroup(const uint8_t header[80], uint32_t start, uint32_t count,
                  const Record *timed, uint32_t timedRecords, uint32_t timedCompleted,
                  const Record *polled, uint32_t polledRecords, uint32_t polledCompleted,
                  uint32_t softwarePhase, Totals &totals, Report &&report) {
  if (timedRecords != count || polledRecords != count ||
      timedCompleted != count || polledCompleted != count) {
    ++totals.coverage;
    report(Kind::Coverage, start, timedRecords, polledRecords, count);
    return;
  }
  for (uint32_t i = 0; i < count; ++i) {
    const uint32_t nonce = start + i;
    if (timed[i].nonce != nonce || polled[i].nonce != nonce) {
      ++totals.coverage;
      report(Kind::Coverage, nonce, timed[i].nonce, polled[i].nonce, nonce);
      return;
    }
  }
  totals.compared += count;
  for (uint32_t i = 0; i < count; ++i) {
    const Record &t = timed[i];
    const Record &p = polled[i];
    if (t.word != p.word) {
      ++totals.timedPolled;
      report(Kind::TimedPolled, t.nonce, t.word, p.word, 0);
    }
    if ((t.nonce & kSoftwareMask) == (softwarePhase & kSoftwareMask)) {
      const uint32_t software = classic_kernel::referenceFinalWord(header, t.nonce);
      ++totals.softwareChecked;
      if (t.word != software) {
        ++totals.timedSoftware;
        report(Kind::TimedSoftware, t.nonce, t.word, p.word, software);
      }
      if (p.word != software) {
        ++totals.polledSoftware;
        report(Kind::PolledSoftware, t.nonce, t.word, p.word, software);
      }
    }
    if (t.hit || p.hit) {
      ++totals.hits;
      uint8_t full[80], reference[32];
      memcpy(full, header, sizeof(full));
      memcpy(full + 76, &t.nonce, sizeof(t.nonce));
      mining_validation::referenceSha256d(full, sizeof(full), reference);
      const bool referenceHit = reference[30] == 0 && reference[31] == 0;
      if (t.hit != p.hit || t.hit != referenceHit ||
          (t.hit && memcmp(t.hash, reference, 32) != 0) ||
          (p.hit && memcmp(p.hash, reference, 32) != 0)) {
        ++totals.digest;
        report(Kind::Digest, t.nonce, t.word, p.word,
               classic_kernel::referenceFinalWord(header, t.nonce));
      }
    }
  }
}

}  // namespace w390_soak
