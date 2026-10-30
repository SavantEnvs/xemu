#!/usr/bin/env bash
#
# mayhem/test.sh — RUN xemu's own unit tests (built by build.sh in build/test): the nv2a PTIMER and
# vertex-shader carry-over tests plus QEMU's JSON/dict/cutils/bitops/keyval/base64/iov suites. Every
# binary must report exactly its expected number of passing glib TAP subtests, so an exit(0) no-op
# (which prints nothing) cannot pass.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BT=build/test
passed=0 failed=0 skipped=0

# binary  expected-count  a-subtest-name-that-must-pass
SUITES="
tests/xbox/ptimer/test-nv2a-ptimer 20 /xbox/nv2a/ptimer/polling_after_multiple_missed_periods_while_masked
tests/xbox/vsh_carryover/test-nv2a-vsh-carryover 6 /xbox/vsh_carryover/multi_program_cache
tests/unit/check-qjson 31 /errors/limits/nesting
tests/unit/test-cutils 179 /cutils/strtosz/metric
tests/unit/test-bitops 6 /bitops/half_unshuffle64
tests/unit/test-keyval 13 /keyval/merge/conflict
tests/unit/check-qdict 15 /errors/get_not_exists
tests/unit/test-base64 4 /util/base64/invalid-chars
tests/unit/test-iov 6 /basic/iov/discard-back-undo
"

while read -r bin want name; do
  [ -n "$bin" ] || continue
  if [ ! -x "$BT/$bin" ]; then
    echo "missing test binary $BT/$bin (build.sh should have built it)" >&2
    failed=$((failed + 1))
    continue
  fi
  out=$(cd "$BT" && "./$bin" --tap -k 2>&1); rc=$?
  ok=$(printf '%s\n' "$out" | grep -c '^ok [0-9]')
  skip=$(printf '%s\n' "$out" | grep -c '^ok [0-9].* # SKIP')
  bad=$(printf '%s\n' "$out" | grep -c '^not ok')
  echo "$bin: ok=$ok skip=$skip not-ok=$bad rc=$rc (expected $want)"
  if [ "$rc" -ne 0 ] || [ "$bad" -ne 0 ] || [ "$ok" -ne "$want" ] \
     || ! printf '%s\n' "$out" | grep -q "^ok [0-9]* $name\$"; then
    printf '%s\n' "$out" | grep -v '^ok ' | tail -20 >&2
    failed=$((failed + 1))
    continue
  fi
  passed=$((passed + ok - skip))
  skipped=$((skipped + skip))
done <<< "$SUITES"

emit_ctrf "glib-tap" "$passed" "$failed" "$skipped"
