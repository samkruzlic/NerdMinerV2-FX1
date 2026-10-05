# Pool statistics tests

`native_poolstats.cpp` exercises the platform-independent production registry,
JSON parsers, HTTP-status policy, cache state transitions, and retry policy.
The JSON files in `fixtures` contain synthetic data only.

The test is intentionally desktop-native: it provides deterministic coverage
without requiring network access or a connected board. Network, TLS, display,
and FreeRTOS behavior still require target-board validation.

`native_mining_validation.cpp` covers the independent SHA-256/SHA-256d
implementation, exact target comparison, candidate validation, generation and
range behavior, and fixed-seed differential comparison with the optimized
software mining SHA. Its block-header vectors cover genesis and heights 1,
100000, and 700000.

It also covers the classic ESP32 timed-kernel policy
(`src/crypto/ClassicKernelPolicy.h`): chip/clock gating, the one-in-4,096
runtime sample, known-answer verdicts and the one-way fallback to the polled
kernel. The kernel's emitted code is checked by
`tools/validate_classic_sha_codegen.py` (both kernels).
