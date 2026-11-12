#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
BEE2_BUILD_TYPE=ASan bash scripts/build_bee2.sh
# Go's ASan mode and the C backend share the same sanitizer runtime. Run Go race
# separately. LeakSanitizer cannot trace Go's managed heap; bounds/UAF and UB
# checks stay enabled across the bridge and the backend.
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
export CGO_CFLAGS="-O1 -g -fsanitize=address,undefined -fno-sanitize=signed-integer-overflow"
export CGO_LDFLAGS="-fsanitize=address,undefined"
export BEE2_TEST_SANITIZERS=1
ctest --test-dir build/bee2 --output-on-failure --no-tests=error
go test -asan -tags slow ./... -count=1 -timeout=20m
