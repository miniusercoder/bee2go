// Package bee2go provides Go bindings for the bee2 cryptographic library
// (https://github.com/agievich/bee2).
//
// bee2 implements Belarusian national cryptographic standards:
//
//   - bash  — hash function and stream cipher (STB 34.101.77)
//   - belt  — block cipher and MAC (STB 34.101.31), HMAC (STB 34.101.47),
//     PBKDF2 (STB 34.101.45 annex E)
//   - bign  — elliptic-curve digital signature and key transport (STB 34.101.45)
//   - brng  — deterministic pseudorandom number generators (STB 34.101.47)
//   - bake  — authenticated key establishment protocols, BSTS (STB 34.101.66)
//   - rng   — entropy sources, random number generator, FIPS tests
//     (STB 34.101.27)
//
// # Prerequisites
//
// The bee2 C library must be compiled as a static archive before building
// this package. Run scripts/build_bee2.sh from the repository root, or:
//
//	cd bee2 && cmake -B build -DBUILD_SHARED_LIBS=OFF && cmake --build build
//
// # Thread safety
//
// No state is shared between package-level functions. Each object (BashPrg,
// BignParams, BakeBSTS, …) owns its own C-side state and must NOT be used
// concurrently from multiple goroutines without external synchronisation.
//
// # Memory management
//
// Objects that allocate C memory expose a Free() method. Call Free() when
// you are done with an object to avoid leaks. Using an object after Free()
// is undefined behaviour.
package bee2go
