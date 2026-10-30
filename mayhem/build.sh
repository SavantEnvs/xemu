#!/usr/bin/env bash
#
# mayhem/build.sh — build xemu's QEMU generic fuzzer (one binary, per-target dirs), standalone
# reproducers, and the project's own unit tests. Offline and re-runnable: the meson wraps come from
# the in-image stash made by fetch-subprojects.sh.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STASH:=/opt/xemu-subprojects}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# configure reads LIB_FUZZING_ENGINE as a flag-less engine and breaks its probes; QEMU picks
# -fsanitize=fuzzer itself under --enable-fuzzing.
unset LIB_FUZZING_ENGINE

TARGETS="xbox-smbus xbox-lpc xbox-pci pci-ohci mcpx-aci mcpx-apu nvnet"
FUZZ_BIN=qemu-fuzz-i386-target-generic-fuzz

# Meson wraps (downloaded at image build). -n: never clobber tracked files.
if [ -d "$STASH" ]; then
    cp -an "$STASH"/. subprojects/
fi

mkdir -p build/objs
# Glue objects are built WITHOUT sanitizers: configure links throwaway programs against them
# (--extra-ldflags) and those have no sanitizer runtime.
$CC -g -gdwarf-3 -c mayhem/xemu_fuzz_init.c -o build/objs/xemu_fuzz_init.o
$CXX -g -gdwarf-3 -c mayhem/lsan_off.cc -o build/objs/lsan_off.o

ASAN_CFG=""
case "$SANITIZER_FLAGS" in *address*) ASAN_CFG="$ASAN_CFG --enable-asan" ;; esac
case "$SANITIZER_FLAGS" in *undefined*) ASAN_CFG="$ASAN_CFG --enable-ubsan" ;; esac
HALT=""
[ -z "$SANITIZER_FLAGS" ] || HALT="-fno-sanitize-recover=all -fno-omit-frame-pointer"

# 1) fuzz build: whole of QEMU + xemu with sanitizers; reconfigure only when the knobs changed.
STAMP="$SANITIZER_FLAGS|$DEBUG_FLAGS|$CC|$CXX"
if [ ! -f build/fuzz/build.ninja ] || [ "$(cat build/fuzz/.mayhem-stamp 2>/dev/null)" != "$STAMP" ]; then
    rm -rf build/fuzz
    mkdir -p build/fuzz
    (cd build/fuzz && ../../configure --disable-werror --cc="$CC" --cxx="$CXX" \
        --enable-fuzzing $ASAN_CFG --target-list=i386-softmmu \
        --extra-cflags="-DXBOX=1 $HALT $DEBUG_FLAGS" \
        --extra-ldflags="$HALT -Wl,--allow-multiple-definition $SRC/build/objs/xemu_fuzz_init.o $SRC/build/objs/lsan_off.o")
    echo "$STAMP" > build/fuzz/.mayhem-stamp
fi
ninja -C build/fuzz -d keeprsp -j"$MAYHEM_JOBS" qemu-fuzz-i386

# One directory per target: the generic fuzzer picks its target from argv[0] ("-target-generic-fuzz")
# and xemu_fuzz_init.c takes QEMU_FUZZ_OBJECTS from the directory name. Hard links, not symlinks:
# Mayhem resolves a symlinked cmd to its real name, which has no "-target-" and prints only usage.
rm -rf build/targets build/standalone
mkdir -p build/standalone
for t in $TARGETS; do
    mkdir -p "build/targets/$t"
    ln -f build/fuzz/qemu-fuzz-i386 "build/targets/$t/$FUZZ_BIN" \
        || cp build/fuzz/qemu-fuzz-i386 "build/targets/$t/$FUZZ_BIN"
done

# 2) standalone (non-libFuzzer) reproducer: same objects, LLVM's run-once driver instead of libFuzzer.
if [ -n "${STANDALONE_FUZZ_MAIN:-}" ] && [ -f build/fuzz/qemu-fuzz-i386.rsp ]; then
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/objs/standalone_main.o
    sed 's/-fsanitize=fuzzer\([^ -]*\)\?\( \|$\)/ /g' build/fuzz/qemu-fuzz-i386.rsp > build/standalone/link.rsp
    (cd build/fuzz && $CXX -m64 @"$SRC/build/standalone/link.rsp" "$SRC/build/objs/standalone_main.o" \
        -o "$SRC/build/standalone/qemu-fuzz-i386-standalone") \
        || echo "warning: standalone reproducer link failed (not a gated artifact)" >&2
fi

# 3) the project's unit tests, NORMAL flags, independent tree (test.sh only runs them).
TEST_TARGETS="tests/xbox/ptimer/test-nv2a-ptimer tests/xbox/vsh_carryover/test-nv2a-vsh-carryover \
 tests/unit/check-qjson tests/unit/test-cutils tests/unit/test-bitops tests/unit/test-keyval \
 tests/unit/check-qdict tests/unit/test-base64 tests/unit/test-iov"
if [ ! -f build/test/build.ninja ]; then
    rm -rf build/test
    mkdir -p build/test
    (cd build/test && ../../configure --disable-werror --cc="$CC" --cxx="$CXX" \
        --target-list=i386-softmmu --extra-cflags="-DXBOX=1 $COVERAGE_FLAGS" \
        --extra-ldflags="$COVERAGE_FLAGS")
fi
# shellcheck disable=SC2086
ninja -C build/test -j"$MAYHEM_JOBS" $TEST_TARGETS
