// Host tests for the batched ESP32-S3/C3 SHA-256d loop (src/crypto/BatchedSha.h).
//
// The batch bookkeeping runs against a model of the S3/C3 SHA peripheral and is
// compared, call for call, with a model of FX1's original sequential S2/S3/C3 loop
// whose hashes come from the independent reference SHA-256d:
//   - every nonce's final digest word, in order;
//   - every 16-bit filter pass (nonce and full hash), in order;
//   - the completed-nonce count returned for candidates, generation changes,
//     partial batches, unaligned and wrapping ranges, and stale-on-entry ranges;
//   - a filter pass on the very nonce where the job changes (reported, then stopped);
//   - the boot self-test's window table (src/crypto/BatchedShaSelfTest.h).
// The model returns 0 from SHA_H while busy (as the chip does), keeps SHA_TEXT
// latched at START/CONTINUE, and counts protocol violations (a command or an
// SHA_H write while busy). SHA_TEXT/SHA_H start with garbage before each range.
//
// What this does NOT cover: the real S3/C3 register code (BatchedShaEngine and the
// BSHA_* macros in src/mining.cpp) is never compiled here; ModelEngine below stands
// in for it. Faults in that code (a dropped volatile, SHA_H[0..6] read before the
// BUSY wait, a wrong register offset) pass this suite. They are caught only on the
// chip, by the boot self-test (which then falls back to a slower kernel, silently
// apart from one serial log line) and by the *_SHA_DIAG builds.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <array>
#include <vector>

#include "crypto/BatchedSha.h"
#include "crypto/BatchedShaSelfTest.h"
#include "crypto/ReferenceSha256.h"
#include "crypto/MiningRangePolicy.h"

namespace {
void require(bool condition, const char *message) {
  if (!condition) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}
uint32_t bs(uint32_t v) { return __builtin_bswap32(v); }
uint64_t g_rng = 0x5333426174636821ULL;
uint32_t rnd() { g_rng ^= g_rng >> 12; g_rng ^= g_rng << 25; g_rng ^= g_rng >> 27; return (uint32_t)((g_rng * 0x2545f4914f6cdd1dULL) >> 32); }

// ------------------------------------------------------------- peripheral model
const uint32_t K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
const uint32_t IV[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
void compress(uint32_t s[8], const uint32_t in[16]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) w[i] = in[i];
  for (int i = 16; i < 64; i++)
    w[i] = w[i-16] + (ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3)) + w[i-7] + (ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10));
  uint32_t a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + (ror(e,6)^ror(e,11)^ror(e,25)) + ((e&f)^(~e&g)) + K[i] + w[i];
    uint32_t t2 = (ror(a,2)^ror(a,13)^ror(a,22)) + ((a&b)^(a&c)^(b&c));
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  s[0]+=a;s[1]+=b;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}

struct Peripheral {
  uint32_t H[8], T[16], pending[8];
  uint32_t busy;          // reads left before the running block completes
  uint32_t violations;
  uint64_t blocks;
} P;

void resetPeripheral() {
  for (auto &w : P.H) w = rnd();
  for (auto &w : P.T) w = rnd();   // garbage left by any other SHA user
  P.busy = 0;
}
void tick() { if (P.busy && --P.busy == 0) memcpy(P.H, P.pending, sizeof(P.H)); }
uint32_t readH(int k) { if (P.busy) { tick(); return 0; } return P.H[k]; }
bool readBusy() { if (P.busy) { tick(); return true; } return false; }
void writeH(int k, uint32_t v) { if (P.busy) { ++P.violations; return; } P.H[k] = v; }
void writeT(int k, uint32_t v) { P.T[k] = v; }       // latched at the command: always allowed
void command(bool start) {
  if (P.busy) { ++P.violations; return; }
  uint32_t s[8], w[16];
  for (int i = 0; i < 8; i++) s[i] = start ? IV[i] : bs(P.H[i]);
  for (int i = 0; i < 16; i++) w[i] = bs(P.T[i]);
  compress(s, w);
  for (int i = 0; i < 8; i++) P.pending[i] = bs(s[i]);
  P.busy = 1 + rnd() % 12;  // sometimes longer than the 8-read H7 poll
  ++P.blocks;
}

template <bool HPOLL> struct ModelEngine {
  static void begin() { for (int k = 9; k < 15; k++) writeT(k, 0); }
  static void loadBlock2(const uint32_t t[3], uint32_t nonce) {
    writeT(0, t[0]); writeT(1, t[1]); writeT(2, t[2]); writeT(3, nonce);
    writeT(4, 0x80); writeT(5, 0); writeT(6, 0); writeT(7, 0); writeT(8, 0); writeT(15, 0x80020000);
  }
  static void setNonce(uint32_t nonce) { writeT(3, nonce); }
  static void setState(const uint32_t m[8]) { for (int k = 0; k < 8; k++) writeH(k, m[k]); }
  static void resume() { command(false); }
  static void start() { command(true); }
  static uint32_t waitWord7() {
    uint32_t h7 = 0;
    if (HPOLL) {
      for (int k = 8; k; --k) { h7 = readH(7); if (h7) break; }
      if (!h7) { while (readBusy()) {} h7 = readH(7); }
    } else {
      while (readBusy()) {}
      h7 = readH(7);
    }
    return h7;
  }
  static void readState(uint32_t out[8]) { out[7] = waitWord7(); for (int k = 0; k < 7; k++) out[k] = readH(k); }
  static void loadDigest(const uint32_t d[8]) { for (int k = 0; k < 8; k++) writeT(k, d[k]); }
  static void loadFinalPadding() { writeT(8, 0x80); writeT(15, 0x00010000); }
  static uint32_t finalWord() { return waitWord7(); }
  static void readHead(uint32_t out[8]) { for (int k = 0; k < 7; k++) out[k] = readH(k); }
};

// ------------------------------------------------------------- job + callbacks
struct Job { uint8_t header[80]; uint32_t mid[8], tail[3]; };
void makeJob(Job &j) {
  uint32_t w[16], s[8];
  for (int i = 0; i < 16; i++) { uint32_t v; memcpy(&v, j.header + 4 * i, 4); w[i] = bs(v); }
  memcpy(s, IV, sizeof(s)); compress(s, w);
  for (int i = 0; i < 8; i++) j.mid[i] = bs(s[i]);   // SHA_H register form
  memcpy(j.tail, j.header + 64, 12);
}
void randomJob(Job &j) { for (int i = 0; i < 80; i++) j.header[i] = (uint8_t)rnd(); makeJob(j); }

struct Hit { uint32_t nonce; uint32_t hash[8]; };
struct Recorder {
  std::vector<uint32_t> finalNonce, finalWord;
  std::vector<Hit> hits;
  std::vector<uint32_t> candidates;   // filter passes that end the range
  bool everyPassIsCandidate = false;
  size_t staleAfter = SIZE_MAX;       // stale() true once this many final words were seen
  bool onFilter(uint32_t nonce, const uint32_t *h) {
    Hit hit; hit.nonce = nonce; memcpy(hit.hash, h, 32); hits.push_back(hit);
    if (everyPassIsCandidate) return true;
    for (uint32_t c : candidates) if (c == nonce) return true;
    return false;
  }
  void onFinal(uint32_t nonce, uint32_t word) { finalNonce.push_back(nonce); finalWord.push_back(word); }
  bool stale() const { return finalNonce.size() >= staleAfter; }
};

// FX1's original S2/S3/C3 loop (src/mining.cpp, a357445), hashes from the reference.
uint32_t originalRange(const Job &j, uint32_t start, uint32_t count, Recorder &r) {
  uint8_t header[80], hash[32];
  memcpy(header, j.header, 80);
  for (uint32_t offset = 0; offset < count; ++offset) {
    const uint32_t n = start + offset;
    memcpy(header + 76, &n, 4);
    mining_validation::referenceSha256d(header, 80, hash);
    uint32_t words[8]; memcpy(words, hash, 32);
    r.onFinal(n, words[7]);
    if ((uint16_t)(words[7] >> 16) == 0 && r.onFilter(n, words)) return offset + 1;
    if ((uint8_t)(n & 0xFF) == 0 && r.stale()) return n - start + 1;
  }
  return count;
}

template <bool HPOLL>
uint32_t batchedRange(const Job &j, uint32_t start, uint32_t count, Recorder &r) {
  resetPeripheral();
  auto onFilter = [&](uint32_t n, const uint32_t *h) { return r.onFilter(n, h); };
  auto onFinal = [&](uint32_t n, uint32_t w) { r.onFinal(n, w); };
  auto stale = [&]() { return r.stale(); };
  const uint32_t violations = P.violations;
  const uint32_t done = batched_sha::hashRange<ModelEngine<HPOLL>>(j.mid, j.tail, start, count, onFilter, onFinal, stale);
  require(P.violations == violations, "command or SHA_H write while the engine was busy");
  require(P.busy == 0, "range returned with the engine busy");
  return done;
}

uint64_t g_cases = 0, g_nonces = 0;
void sameAsOriginal(const Job &j, uint32_t start, uint32_t count, const Recorder &setup, const char *what) {
  Recorder a = setup, b = setup, c = setup;
  const uint32_t r0 = originalRange(j, start, count, a);
  const uint32_t r1 = batchedRange<true>(j, start, count, b);
  const uint32_t r2 = batchedRange<false>(j, start, count, c);
  for (const Recorder *x : {&b, &c}) {
    const uint32_t r = (x == &b) ? r1 : r2;
    if (r != r0 || x->finalNonce != a.finalNonce || x->finalWord != a.finalWord || x->hits.size() != a.hits.size()) {
      fprintf(stderr, "%s: start=%08x count=%u -> completed %u vs original %u, finals %zu vs %zu, hits %zu vs %zu (%s)\n",
              what, start, count, r, r0, x->finalNonce.size(), a.finalNonce.size(), x->hits.size(), a.hits.size(),
              x == &b ? "H7 polling" : "BUSY polling");
      require(false, what);
    }
    for (size_t i = 0; i < a.hits.size(); i++)
      require(x->hits[i].nonce == a.hits[i].nonce && !memcmp(x->hits[i].hash, a.hits[i].hash, 32), what);
  }
  ++g_cases; g_nonces += r0;
}

// ------------------------------------------------------------- tests
void testKnownAnswers() {
  struct { const char *header, *hash; } v[] = {
    {"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
     "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"},
    {"0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122bc7f5d74df2b9441a42a14695",
     "1dbd981fe6985776b644b173a4d0385ddc1aa2a829688d1e0000000000000000"}};
  for (auto &t : v) {
    Job j; uint8_t want[32];
    for (int i = 0; i < 80; i++) { unsigned x; sscanf(t.header + 2 * i, "%2x", &x); j.header[i] = (uint8_t)x; }
    for (int i = 0; i < 32; i++) { unsigned x; sscanf(t.hash + 2 * i, "%2x", &x); want[i] = (uint8_t)x; }
    makeJob(j);
    uint32_t nonce; memcpy(&nonce, j.header + 76, 4);
    for (uint32_t pos : {0u, 17u, 31u, 35u}) {
      Recorder setup; setup.candidates.push_back(nonce);
      Recorder r = setup;
      const uint32_t done = batchedRange<true>(j, nonce - pos, pos + 40, r);
      require(done == pos + 1, "known answer: candidate not the completed-range end");
      require(!r.hits.empty() && r.hits.back().nonce == nonce && !memcmp(r.hits.back().hash, want, 32),
              "known answer: block hash mismatch");
      sameAsOriginal(j, nonce - pos, pos + 40, setup, "known answer range");
    }
  }
}

void testDifferential() {
  const uint32_t counts[] = {0, 1, 2, 5, 31, 32, 33, 63, 64, 65, 95, 100, 257, 1000, 4093};
  for (int t = 0; t < 120; t++) {
    Job j; randomJob(j);
    const uint32_t count = counts[t % (sizeof(counts) / sizeof(counts[0]))];
    uint32_t start = rnd();
    if (t % 5 == 1) start = 0xffffffffu - (rnd() % 64);   // wraps through 0
    if (t % 5 == 2) start = rnd() & ~0xFFu;                // aligned
    Recorder setup;
    sameAsOriginal(j, start, count, setup, "differential range");
  }
}

// Ranges with real 16-bit filter passes at chosen positions of a batch.
std::vector<uint32_t> findFilterPasses(const Job &j, uint32_t from, uint32_t span) {
  std::vector<uint32_t> found;
  uint8_t header[80], hash[32];
  memcpy(header, j.header, 80);
  for (uint32_t i = 0; i < span; i++) {
    const uint32_t n = from + i;
    memcpy(header + 76, &n, 4);
    mining_validation::referenceSha256d(header, 80, hash);
    if (hash[30] == 0 && hash[31] == 0) found.push_back(n);
  }
  return found;
}

void testHitPlacement(const Job &j, const std::vector<uint32_t> &passes) {
  require(passes.size() >= 8, "too few filter passes to test placement");
  for (size_t h = 0; h < 8; h++) {
    const uint32_t hit = passes[h];
    for (uint32_t pos : {0u, 1u, 15u, 16u, 30u, 31u, 32u, 33u, 47u, 63u}) {
      for (uint32_t extra : {0u, 1u, 7u, 31u, 32u, 40u}) {
        const uint32_t start = hit - pos, count = pos + 1 + extra;   // extra 0: hit is the last nonce of the range
        Recorder candidate; candidate.candidates.push_back(hit);
        sameAsOriginal(j, start, count, candidate, "candidate placement");
        Recorder belowShare;                                          // filter pass below the share difficulty
        sameAsOriginal(j, start, count, belowShare, "sub-difficulty filter pass placement");
      }
    }
  }
  // Long range through every pass: every pass reported, none dropped.
  Recorder all; all.everyPassIsCandidate = false;
  sameAsOriginal(j, passes.front() - 5, passes.back() - passes.front() + 11, all, "all filter passes");
}

void testGeneration() {
  Job j; randomJob(j);
  const uint32_t starts[] = {0x12345600u, 0x12345601u, 0x123456e0u, 0x123456ffu, 0xffffff10u, 0x12345680u};
  const uint32_t counts[] = {1, 31, 32, 33, 300, 600};
  const size_t after[] = {0, 1, 2, 31, 32, 33, 255, 256, 257, 300, 1000};
  for (uint32_t s : starts) for (uint32_t c : counts) for (size_t a : after) {
    Recorder setup; setup.staleAfter = a;
    sameAsOriginal(j, s, c, setup, "generation change");
  }
}

// FX1's hand-off: a range ending on a candidate resumes its exact suffix.
void testResume(const Job &j, const std::vector<uint32_t> &passes) {
  struct Range { uint32_t generation, nonce_start, nonce_count; };
  for (uint32_t base : {passes[0] - 3, passes[2] - 31, passes[4]}) {
    Range range{7, base, passes[7] - base + 100};
    const uint32_t total = range.nonce_count;
    Recorder r; r.everyPassIsCandidate = true;
    uint32_t completed = 0, rounds = 0;
    for (;;) {
      Recorder part; part.everyPassIsCandidate = true;
      const uint32_t done = batchedRange<true>(j, range.nonce_start, range.nonce_count, part);
      r.finalNonce.insert(r.finalNonce.end(), part.finalNonce.begin(), part.finalNonce.end());
      r.hits.insert(r.hits.end(), part.hits.begin(), part.hits.end());
      completed += done; ++rounds;
      if (!mining_validation::resumeCompletedPrefix(range, done, 7)) break;
    }
    require(completed == total, "resumed ranges lost or double-counted nonces");
    require(r.finalNonce.size() == total, "a nonce was hashed twice or never");
    for (uint32_t i = 0; i < total; i++) require(r.finalNonce[i] == base + i, "resumed nonce order gap");
    size_t expected = 0;
    for (uint32_t p : passes) if ((uint32_t)(p - base) < total) ++expected;
    require(r.hits.size() == expected, "resumed ranges lost a candidate");
    require(rounds == expected + 1 || rounds == expected, "unexpected number of hand-offs");
    ++g_cases; g_nonces += total;
  }
}

// A 16-bit filter pass on a nonce whose low byte is 0, with the job generation
// changing at that same nonce. Contract: the filter pass is reported first (and a
// candidate there ends the range as a candidate); only then does the generation
// check end the range. Both ways the nonce is counted.
void testFilterPassAtGenerationChange() {
  Job j; randomJob(j);
  uint32_t hit = 0;
  bool found = false;
  uint8_t header[80], hash[32];
  memcpy(header, j.header, 80);
  for (uint32_t k = 0x200000u; k < 0x200000u + (1u << 22) && !found; ++k) {   // low-byte-0 nonces only
    const uint32_t n = k << 8;
    memcpy(header + 76, &n, 4);
    mining_validation::referenceSha256d(header, 80, hash);
    if (hash[30] == 0 && hash[31] == 0) { hit = n; found = true; }
  }
  require(found, "no low-byte-0 filter pass found");
  for (uint32_t pos : {0u, 1u, 17u, 31u, 32u, 40u, 63u}) {
    for (uint32_t extra : {0u, 1u, 30u}) {
      for (bool isCandidate : {true, false}) {
        for (size_t staleAfter : {(size_t)0, (size_t)pos + 1}) {   // pos < 256: no earlier low-byte-0 nonce
          Recorder setup; setup.staleAfter = staleAfter;
          if (isCandidate) setup.candidates.push_back(hit);
          const uint32_t start = hit - pos, count = pos + 1 + extra;
          for (int poll = 0; poll < 2; ++poll) {
            Recorder r = setup;
            const uint32_t done = poll ? batchedRange<true>(j, start, count, r) : batchedRange<false>(j, start, count, r);
            require(!r.hits.empty() && r.hits.back().nonce == hit,
                    "filter pass on a low-byte-0 nonce dropped when the job changed there");
            require(done == pos + 1, "filter pass at a job change: wrong completed count");
          }
          sameAsOriginal(j, start, count, setup, "filter pass at a job change");
        }
      }
    }
  }
}

// The boot self-test's windows (src/crypto/BatchedShaSelfTest.h), replayed as
// batchedKernelKnownAnswers runs them on the chip, with a generation that changes
// at the first nonce: since no window has a low-byte-0 nonce, it never matters.
void testSelfTestWindows() {
  using namespace batched_sha_self_test;
  bool partialAfterFull = false;
  for (const Window &w : kWindows) {
    Job j; uint8_t want[32];
    for (int i = 0; i < 80; i++) { unsigned x; sscanf(kHeaders[w.block] + 2 * i, "%2x", &x); j.header[i] = (uint8_t)x; }
    for (int i = 0; i < 32; i++) { unsigned x; sscanf(kHashes[w.block] + 2 * i, "%2x", &x); want[i] = (uint8_t)x; }
    makeJob(j);
    uint32_t nonce; memcpy(&nonce, j.header + 76, 4);
    require(nonce == kNonces[w.block], "self-test: kNonces does not match the header");
    const uint32_t first = nonce - w.pos;
    for (uint32_t i = 0; i < w.count; i++)
      require(((first + i) & 0xFFu) != 0, "self-test: window contains a low-byte-0 nonce");
    if (w.count > batched_sha::kBatch && w.count % batched_sha::kBatch != 0 && w.pos == w.count - 1) partialAfterFull = true;
    Recorder setup; setup.candidates.push_back(nonce); setup.staleAfter = 0;
    Recorder r = setup;
    const uint32_t done = batchedRange<true>(j, first, w.count, r);
    require(done == w.pos + 1 && !r.hits.empty() && r.hits.back().nonce == nonce && !memcmp(r.hits.back().hash, want, 32),
            "self-test window: known nonce not the candidate");
    sameAsOriginal(j, first, w.count, setup, "self-test window");
    if (w.pos + 1 < w.count) {
      Recorder rest = setup;   // FX1's hand-off: the suffix after the candidate
      require(batchedRange<false>(j, nonce + 1, w.count - w.pos - 1, rest) == w.count - w.pos - 1,
              "self-test window: suffix not completed");
      sameAsOriginal(j, nonce + 1, w.count - w.pos - 1, setup, "self-test window suffix");
    }
  }
  require(partialAfterFull, "self-test: no hit at the last slot of a final partial batch");
}
}  // namespace

int main() {
  testKnownAnswers();
  testDifferential();
  Job j; randomJob(j);
  const auto passes = findFilterPasses(j, 0x40000000u, 1u << 20);
  testHitPlacement(j, passes);
  testGeneration();
  testResume(j, passes);
  testFilterPassAtGenerationChange();
  testSelfTestWindows();
  printf("Batched SHA: %llu cases, %llu completed nonces, %zu filter passes used, %llu model blocks, 0 failures\n",
         (unsigned long long)g_cases, (unsigned long long)g_nonces, passes.size(), (unsigned long long)P.blocks);
  return 0;
}
