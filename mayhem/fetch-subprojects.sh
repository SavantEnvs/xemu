#!/usr/bin/env bash
#
# Image-build step (needs network): let meson download every wrap the fuzz and test builds use, and
# stash the result outside the tree. build.sh restores it, so the (offline, clean-tree) rebuilds
# never fetch.
set -euo pipefail
: "${SRC:=/mayhem}"
: "${STASH:=/opt/xemu-subprojects}"
cd "$SRC"
unset LIB_FUZZING_ENGINE
rm -rf build/fetch
mkdir -p build/fetch
(cd build/fetch && ../../configure --disable-werror --cc=clang --cxx=clang++ \
    --target-list=i386-softmmu --extra-cflags=-DXBOX=1 >/dev/null)
rm -rf build/fetch
mkdir -p build/fetch
(cd build/fetch && ../../configure --disable-werror --cc=clang --cxx=clang++ --enable-fuzzing \
    --target-list=i386-softmmu --extra-cflags=-DXBOX=1 >/dev/null)
rm -rf build/fetch
mkdir -p "$STASH"
cp -a subprojects/. "$STASH"/
