#!/usr/bin/env bash
# Build the bee2 static library required by CGo bindings.
# Run this once before `go build` or `go test`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BEE2_DIR="$SCRIPT_DIR/../bee2"

if [ ! -d "$BEE2_DIR" ]; then
  echo "Error: bee2 submodule not found at $BEE2_DIR" >&2
  echo "Run: git submodule update --init" >&2
  exit 1
fi

BUILD_DIR="$BEE2_DIR/build"
mkdir -p "$BUILD_DIR"

cmake -S "$BEE2_DIR" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBEE2_INSTALL_HEADERS=ON \
  -DCMAKE_INSTALL_PREFIX="$BUILD_DIR/install"

cmake --build "$BUILD_DIR" --config Release -- -j"$(nproc 2>/dev/null || echo 4)"

echo "bee2 built successfully: $BUILD_DIR/src/libbee2_static.a"
