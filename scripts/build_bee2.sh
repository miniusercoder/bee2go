#!/usr/bin/env bash
# Build the pinned bee2 library and its upstream tests out of tree.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/bee2"
BUILD="$ROOT/build/bee2"
TYPE="${BEE2_BUILD_TYPE:-Release}"
COMPILER="${CC:-cc}"
if [[ ! -f "$SRC/CMakeLists.txt" ]]; then
  echo "bee2 missing; run git submodule update --init --recursive" >&2
  exit 1
fi
SHA="$(git -C "$SRC" rev-parse HEAD)"
PIN="$(git -C "$ROOT" ls-tree HEAD bee2 | awk '{print $3}')"
if [[ "$SHA" != "$PIN" ]]; then
  echo "bee2 checkout $SHA differs from pinned $PIN" >&2
  exit 1
fi
IDENTITY="$(printf '%s\n' "$SHA" "$TYPE" "$COMPILER" "$($COMPILER --version)" "${CFLAGS:-}" "${LDFLAGS:-}" | sha256sum | cut -d' ' -f1)"
# A configuration gets its own directory; never reuse a compiler/flag cache.
CONFIG="$ROOT/build/configs/$IDENTITY"
mkdir -p "$CONFIG" "$ROOT/build"
if [[ -e "$BUILD" && ! -L "$BUILD" ]]; then
  echo "$BUILD must be a generated symlink; refusing to replace a directory" >&2
  exit 1
fi
ln -sfn "configs/$IDENTITY" "$BUILD"
cmake -S "$SRC" -B "$CONFIG" -DCMAKE_BUILD_TYPE="$TYPE" \
  -DCMAKE_C_COMPILER="$COMPILER" -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_PIC=ON -DBUILD_TESTS=ON -DBUILD_CMD=OFF -DINSTALL_HEADERS=ON
cmake --build "$CONFIG" --parallel "${BEE2_JOBS:-4}"
printf '%s\n' "$SHA" > "$CONFIG/upstream.sha"
