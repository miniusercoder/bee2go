# Migration to v3

The legacy source snapshot and branch retain `github.com/miniusercoder/bee2go` and its root API. v3 uses `github.com/miniusercoder/bee2go/v3` and family packages; the root no longer re-exports the legacy algorithm functions. Update imports and call sites together. Both lines require building the pinned bee2 source; a Go dependency download alone does not build the C archive.

| Legacy root API | v3 API / change |
|---|---|
| `BeltHash`, `BeltHashN`, `BeltHashVerify`, `NewBeltHash` | `belt.Hash`, `HashN`, `HashVerify`, `NewHash` |
| `BeltECBEncr/Decr`, CBC and CFB counterparts, `BeltCTR` | `belt.ECBEncrypt/Decrypt`, CBC/CFB counterparts, `belt.CTR`; streaming ECB/CBC requires a final fragment for ciphertext stealing |
| `BeltMAC`, `BeltHMAC`, `BeltPBKDF2`, `BeltKRP`, `BeltKWPWrap/Unwrap`, `BeltDWPWrap/Unwrap`, `BeltCHEWrap/Unwrap` | Same family operations under `belt`, without the `Belt` prefix; streaming MAC and bounded authenticated streams are available |
| `BashHash`, `NewBashHash`, `NewBashPrg` | `bash.Hash`, `NewHash`, `NewPRG`; PRG command starts and fragments are explicit |
| `Bign*` keys, params, sign, DH, transport, identity | `bign` package methods; `SignDigest` and profile methods take **digests**, not messages. Hash explicitly first. |
| `Bake*` sessions, KDF, SWU, DH | `bake` package; session `Key` replaces `StepG`, and `Run` uses a message transport |
| `BrngCTRRand`, `BrngCTRRandInto`, `BrngHMACRand` | `brng.CTRRand`, `brng.CTRTransform`, `brng.HMACRand`; `Read` generates bytes, `Transform` uses the existing buffer as additional material |
| `RngCreate/StepR/StepR2/Rekey/Close`, entropy and FIPS helpers | `rng.New` or `rng.NewWithSource` (requires 32 bytes), `rng.IsCreated`, owned `Generator` methods, `rng.ReadEntropy`, `TestSource`, `Health`, `Health2`, `TestFIPS1`–`TestFIPS4` |
| `SelfTest*`, `CheckBee2SelfTests` | `selftest.Run`, `RunOne`, and individual diagnostic functions; diagnostics are not certification |
| `Free` on native owners | Idempotent `Close() error`; defer it after successful construction |
| `BakeDefaultRNG`, `BakeAcceptAllCertVal`, raw generator callbacks/pointers | No pointer replacement. Pass an `io.Reader` seed source and a typed validator; validate certificates according to the application’s policy. |
| `BeltH` and native-memory utilities | Internal test/implementation details; no public substitution table or native pointer API. Caller-owned secrets remain the caller’s responsibility. |

Randomized operations accept an `io.Reader`; nil means `crypto/rand.Reader`. The reader seeds an operation-owned native generator and is not an exact native RNG transcript. Methods returning errors report `ErrClosed` after `Close`; standard interfaces without an error return panic on closed state. Stateful objects are not safe for simultaneous use without caller synchronization. For BIGN parameter generation, supply an `OrderCalculator`; bee2 does not supply a general point-counting implementation.

Only the explicitly implemented upstream subset is covered by these packages. See [algorithm coverage](algorithm-coverage.md) for per-symbol status and [releases](releases.md) before adopting an unreleased build.
