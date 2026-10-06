#!/bin/bash
# Host test for button screen sleep (src/drivers/displays/display.cpp built with
# BUTTON_SCREEN_SLEEP_SECONDS, plus the SCREEN_WAKE_OR wrapper in display.h), for
# both board configurations that use it, then a mutation check: each deliberately
# broken copy must make the test fail.
# Usage: tools/run_screen_sleep_tests.sh   (needs a C++17 compiler: c++ / clang++ / g++)
#
# Scope: the sleep/wake state machine, the drawing gate and the wrapper. It does not
# cover the OneButton timing, the real backlight pin or the hashrate gain; those
# need the board.
set -u
cd "$(dirname "$0")/.."
CXX=${CXX:-c++}
BUILD=test/.build
mkdir -p "$BUILD"
BOARDS=("-DNERDMINERV2=1" "-DNERDMINER_T_DISPLAY_V1=1 -DIDEASPARK_114=1")

build() {  # $1 src dir, $2 board defines, $3 output
  $CXX -std=c++17 -O1 -Wall -Wextra -DBUTTON_SCREEN_SLEEP_SECONDS=30 $2 \
    -I test/screen_sleep_stubs -I "$1" test/native_screen_sleep.cpp \
    "$1/drivers/displays/display.cpp" -o "$3"
}

for board in "${BOARDS[@]}"; do
  echo "== unmodified ($board)"
  build src "$board" "$BUILD/screen_sleep" || exit 1
  "$BUILD/screen_sleep" || { echo "FAIL: tests fail on the unmodified code"; exit 1; }
done

# name | file under src/drivers/displays | perl substitution
MUTANTS=(
  "draws while dark|display.cpp|s/(miningScreensStarted.store\(true\);\n)  if \(screenAsleep.load\(\)\) return;\n/\$1/"
  "animates while dark|display.cpp|s/(void animateCurrentScreen\(unsigned long frame\)\n\{\n#ifdef BUTTON_SCREEN_SLEEP_SECONDS\n)  if \(screenAsleep.load\(\)\) return;\n/\$1/"
  "timer runs before the mining screens|display.cpp|s/    if \(!miningScreensStarted.load\(\)\) return;\n//"
  "sleeps a tick late|display.cpp|s/>= BUTTON_SCREEN_SLEEP_SECONDS/> BUTTON_SCREEN_SLEEP_SECONDS/"
  "backlight left on when dark|display.cpp|s/  screenAsleep.store\(true\);\n  digitalWrite\(TFT_BL, !TFT_BACKLIGHT_ON\);/  screenAsleep.store(true);/"
  "button does not restart the timer|display.cpp|s/bool screenSleepButtonEvent\(\) \{\n  lastButtonMillis = millis\(\);\n/bool screenSleepButtonEvent() {\n/"
  "waking event also acted on|display.cpp|s/  Serial.println\(\"\[Screen\] wake\"\);\n  return true;/  Serial.println(\"[Screen] wake\");\n  return false;/"
  "screen off only darkens|display.cpp|s/else sleepScreen\(\);/else digitalWrite(TFT_BL, !TFT_BACKLIGHT_ON);/"
  "timer not safe across the millis() wrap|display.cpp|s/uint32_t\(millis\(\)\) - lastButtonMillis >= BUTTON_SCREEN_SLEEP_SECONDS \* 1000UL/uint32_t(millis()) >= lastButtonMillis + BUTTON_SCREEN_SLEEP_SECONDS * 1000UL/"
  "wrapper always acts|display.h|s/if \(!screenSleepButtonEvent\(\)\) fn\(\);/screenSleepButtonEvent(); fn();/"
)
killed=0; survived=0
for board in "${BOARDS[@]}"; do
  for entry in "${MUTANTS[@]}"; do
    name=${entry%%|*}; rest=${entry#*|}; file=${rest%%|*}; expr=${rest#*|}
    dir=$(mktemp -d); cp -R src/drivers "$dir/drivers"
    perl -0pe "$expr" "src/drivers/displays/$file" > "$dir/drivers/displays/$file"
    if cmp -s "src/drivers/displays/$file" "$dir/drivers/displays/$file"; then
      echo "MUTANT NOT APPLIED: $name"; survived=$((survived + 1)); rm -rf "$dir"; continue
    fi
    if ! build "$dir" "$board" "$BUILD/screen_sleep_mutant" 2>/dev/null; then
      echo "MUTANT DOES NOT COMPILE (not counted): $name"; survived=$((survived + 1))
    elif "$BUILD/screen_sleep_mutant" >/dev/null 2>"$BUILD/screen_sleep_mutant.err"; then
      echo "MUTANT SURVIVED: $name"; survived=$((survived + 1))
    else
      echo "killed: $name -- $(head -1 "$BUILD/screen_sleep_mutant.err")"; killed=$((killed + 1))
    fi
    rm -rf "$dir"
  done
done
echo "mutants killed $killed, survived $survived"
[ "$survived" -eq 0 ]
