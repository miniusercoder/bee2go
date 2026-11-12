#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# One fuzz target per process; corpus seeds also execute during ordinary tests.
for target in \
  'bake FuzzHandshakeMessages' \
  'btok FuzzBAuthMessages' \
  'belt FuzzFMT' \
  'bash FuzzPRGFragments' \
  'bign FuzzParamsDER' \
  'botp FuzzParseSuite' \
  'bpki FuzzCSR' \
  'bpki FuzzContainers' \
  'btok FuzzCertificate' \
  'btok FuzzSecureMessaging'; do
  read -r package name <<< "$target"
  go test "./$package" -run '^$' -fuzz "^$name$" -fuzztime="${BEE2_FUZZ_TIME:-10s}" -parallel=2
 done
