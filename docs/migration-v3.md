# Migration to v3

The legacy branch and legacy-2026-11-12 snapshot retain the previous module path and API. v3 uses github.com/miniusercoder/bee2go/v3 and family packages. There are no compatibility exports in the root package.

State owners use Close instead of Free. Constructors return concrete types so Close is visible. Operations after Close return ErrClosed; standard interface methods without errors panic with ErrClosed. Randomized operations accept an io.Reader as a seed source (nil uses crypto/rand.Reader). Certificate validators are typed Go callbacks.

The initial verified platform is Linux amd64 with CGo. Install CMake and a C compiler, initialize bee2, then run make setup and go test ./.... Building from source remains required; go get alone does not build bee2.

BIGN signing accepts digests. Hash messages explicitly before SignDigest; profiles do not hash the digest again.
