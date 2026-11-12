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
if ! git -C "$SRC" diff --quiet HEAD --; then
  echo "bee2 has tracked changes; refusing header/library mismatch" >&2
  exit 1
fi
PATCHES="$(find "$ROOT/patches" -maxdepth 1 -name '*.patch' -type f -print | LC_ALL=C sort | xargs -r sha256sum)"
IDENTITY="$(printf '%s\n' "$SHA" "$TYPE" "$COMPILER" "$($COMPILER --version)" "${CFLAGS:-}" "${LDFLAGS:-}" "$PATCHES" "$(sha256sum "$0")" | sha256sum | cut -d' ' -f1)"
# A configuration gets its own directory; never reuse a compiler/flag cache.
CONFIG="$ROOT/build/configs/$IDENTITY"
mkdir -p "$CONFIG" "$ROOT/build"
SOURCE="$CONFIG/source"
if [[ ! -f "$CONFIG/source.ready" ]]; then
  mkdir -p "$SOURCE"
  git -C "$SRC" archive "$SHA" | tar -x -C "$SOURCE"
  for BEE2_PATCH in "$ROOT"/patches/*.patch; do
    patch --batch --forward --fuzz=0 -d "$SOURCE" -p1 < "$BEE2_PATCH"
  done
  printf '%s\n' "$SHA" > "$CONFIG/source.ready"
fi
if [[ -e "$BUILD" && ! -L "$BUILD" ]]; then
  echo "$BUILD must be a generated symlink; refusing to replace a directory" >&2
  exit 1
fi
cmake -S "$SOURCE" -B "$CONFIG" -DCMAKE_BUILD_TYPE="$TYPE" \
  -DCMAKE_C_COMPILER="$COMPILER" -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_PIC=ON -DBUILD_TESTS=ON -DBUILD_CMD=OFF -DINSTALL_HEADERS=ON
cmake --build "$CONFIG" --parallel "${BEE2_JOBS:-4}"
printf '%s\n' "$SHA" > "$CONFIG/upstream.sha"
ln -sfn "configs/$IDENTITY" "$BUILD"
# CGo does not track changes to an externally linked archive. A generated local
# header makes its action cache depend on this exact native configuration.
printf '#define BEE2GO_BUILD_ID "%s"\n' "$IDENTITY" > "$ROOT/internal/native/build_id.h"
