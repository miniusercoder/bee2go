# Architecture

`github.com/miniusercoder/bee2go/v3` groups public APIs by cryptographic family; the root package defines shared errors. CGo and native state ownership are confined to `internal/native`. Stateful objects expose `Close`, wipe their native allocations, and do not promise concurrent access. Independent objects can be used concurrently. Callers still own returned byte slices and their copies.

The source tree pins bee2 by gitlink. `scripts/build_bee2.sh` checks that checkout and extracts the pinned source and applies the tracked patches without changing the submodule, then creates the native library and upstream tests under `build/configs/<fingerprint>`, with `build/bee2` selecting the build. The fingerprint incorporates the upstream revision, compiler and version, build type, flags, script and patch bytes. CGo therefore requires a local source build before Go tests or consumers compile.

Randomized operations accept an `io.Reader` used as a 64-byte seed source, defaulting to `crypto/rand.Reader`. Each randomized operation initializes a native generator from that seed. `rng.NewWithSource` separately reads a 32-byte contribution before mixing it into the global generator; it rejects short sources even though the C callback can return fewer bytes. It is not a byte-for-byte replay of the reader as the upstream C callback. Callback state uses owned handles; certificate validators receive copies and return a key or error. A production accept-all validator is not provided.

BELT ECB/CBC stream finalization preserves ciphertext stealing. DWP/CHE and BTOK secure messaging withhold plaintext on authentication failure. The BELT authenticated stream bounds buffered payload and associated data before allocation; refresh requires a fresh IV. BELS shares do not authenticate the recovered secret. BIGN and its profiles sign explicit digests and fixed profiles select their own OID.

The legacy staging implementation has been removed after its consumers migrated. The matrix lists implemented paths and their remaining verification work. [Release status](releases.md) records integration gates.
