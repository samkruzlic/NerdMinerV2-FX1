#!/bin/bash
# Host tests for the batched ESP32-S3/C3 SHA loop, then mutation check: each
# deliberately broken copy of src/crypto/BatchedSha.h must make the tests fail.
# Usage: tools/run_batched_sha_tests.sh   (needs a C++17 compiler: c++ / clang++ / g++)
#
# Scope: this tests the platform-independent loop in BatchedSha.h (and the boot
# self-test's window table) against a model of the SHA peripheral. It does not
# compile the S3/C3 register code in src/mining.cpp (BatchedShaEngine, BSHA_*), and
# the mutants below only touch BatchedSha.h. Faults in the register code pass here;
# only the on-chip boot self-test and the *_SHA_DIAG builds can catch them.
set -u
cd "$(dirname "$0")/.."
CXX=${CXX:-c++}
BUILD=test/.build
mkdir -p "$BUILD"
SOURCES="test/native_batched_sha.cpp src/crypto/ReferenceSha256.cpp"

build() {  # $1 include dir searched first, $2 output
  $CXX -std=c++17 -O2 -Wall -Wextra -I "$1" -I src $SOURCES -o "$2"
}

echo "== unmodified kernel"
build src "$BUILD/batched_sha" || exit 1
"$BUILD/batched_sha" || { echo "FAIL: tests fail on the unmodified kernel"; exit 1; }

# name | perl substitution applied to BatchedSha.h
MUTANTS=(
  "skip last nonce of a partial batch|s/for \(uint32_t i = 0; i < m; \+\+i\) \{\n      const uint32_t nonce/for (uint32_t i = 0; i < m - (m < kBatch); ++i) {\n      const uint32_t nonce/"
  "drop a filter pass mid-batch|s/if \(\(word >> 16\) == 0\) \{/if ((word >> 16) == 0 \&\& i != m \/ 2) {/"
  "candidate count off by one|s/if \(onFilterPass\(nonce, hash\)\) return done \+ i \+ 1;/if (onFilterPass(nonce, hash)) return done + i;/"
  "candidate counts the whole batch|s/if \(onFilterPass\(nonce, hash\)\) return done \+ i \+ 1;/if (onFilterPass(nonce, hash)) return done + m;/"
  "generation check on batch start only|s/if \(\(nonce & 0xFFU\) == 0 && stale\(\)\)/if ((first \& 0xFFU) == 0 \&\& i == 0 \&\& stale())/"
  "generation stop not counted|s/if \(\(nonce & 0xFFU\) == 0 && stale\(\)\) return done \+ i \+ 1;/if ((nonce \& 0xFFU) == 0 \&\& stale()) return done + i;/"
  "last nonce of each batch not written|s/if \(i \+ 1 < m\) Engine::setNonce/if (i + 2 < m) Engine::setNonce/"
  "next digest written one batch slot late|s/if \(i \+ 1 < m\) Engine::loadDigest\(digests\[i \+ 1\]\);/if (i + 1 < m) Engine::loadDigest(digests[i]);/"
  "final padding not written|s/Engine::loadFinalPadding\(\);//"
  "partial batch rounded up|s/remaining < kBatch \? remaining : kBatch/kBatch/"
  "midstate written once per batch|s/      Engine::setState\(midstate\);\n      Engine::resume\(\);/      if (i == 0) Engine::setState(midstate);\n      Engine::resume();/"
  "generation check skipped on a batch's last nonce|s/if \(\(nonce & 0xFFU\) == 0 && stale\(\)\)/if ((nonce \& 0xFFU) == 0 \&\& i + 1 < m \&\& stale())/"
  "job-change check before candidate check|s/(      if \(\(word >> 16\) == 0\) \{.*?\n      \}\n)(      if \(\(nonce & 0xFFU\) == 0 && stale\(\)\) return done \+ i \+ 1;\n)/\$2\$1/s"
)
killed=0; survived=0
for entry in "${MUTANTS[@]}"; do
  name=${entry%%|*}; expr=${entry#*|}
  dir=$(mktemp -d); mkdir -p "$dir/crypto"
  perl -0pe "$expr" src/crypto/BatchedSha.h > "$dir/crypto/BatchedSha.h"
  if cmp -s src/crypto/BatchedSha.h "$dir/crypto/BatchedSha.h"; then
    echo "MUTANT NOT APPLIED: $name"; survived=$((survived + 1)); rm -rf "$dir"; continue
  fi
  if ! build "$dir" "$BUILD/batched_mutant" 2>/dev/null; then
    echo "MUTANT DOES NOT COMPILE (not counted): $name"; survived=$((survived + 1))
  elif "$BUILD/batched_mutant" >/dev/null 2>"$BUILD/batched_mutant.err"; then
    echo "MUTANT SURVIVED: $name"; survived=$((survived + 1))
  else
    echo "killed: $name -- $(head -1 "$BUILD/batched_mutant.err")"; killed=$((killed + 1))
  fi
  rm -rf "$dir"
done
echo "mutants killed $killed, survived $survived"
[ "$survived" -eq 0 ]
