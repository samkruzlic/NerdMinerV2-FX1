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

`native_screen_sleep.cpp` covers the button screen sleep built with
`BUTTON_SCREEN_SLEEP_SECONDS` (the `*_SCREEN_SLEEP` environments): the timer
starts with the first mining frame, nothing is drawn or animated while dark,
every button event while dark only wakes the screen, and the timer survives the
`millis()` wrap. Run `tools/run_screen_sleep_tests.sh`; it also checks that
deliberately broken copies fail. Button timing, the real backlight pin and the
hashrate gain need the board.
