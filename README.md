# bee2go v3

Go bindings for [bee2](https://github.com/agievich/bee2), a C implementation of cryptographic algorithms. The v3 module path is `github.com/miniusercoder/bee2go/v3`; algorithms live in family packages such as `belt`, `bash`, `bign`, `bake`, `bels`, `botp`, `bpki`, `brng`, `btok`, `dstu`, `g12s`, `pfok`, and `stb99`. `rng` provides access to the bee2 generator and entropy diagnostics; `selftest` runs selected diagnostic vectors.

**Release status:** v3 is under integration and has not been published. See [algorithm coverage](docs/algorithm-coverage.md) and [release status](docs/releases.md) for remaining verification, including BAuth interoperability and the tracked backend patch. Do not treat the current tree as a completed release.

## Build from source

Linux amd64 with CGo is the initial verified environment. Install Go 1.22 or newer, a C compiler, CMake, Git, and the `patch` utility. Build the exact bee2 version pinned by the repository gitlink:

```sh
git clone --recurse-submodules https://github.com/miniusercoder/bee2go.git
cd bee2go
git submodule update --init --recursive
bash scripts/build_bee2.sh
go test ./...
```

The build script checks that the bee2 checkout matches the gitlink and has no tracked changes, extracts it into a generated source directory, applies the [tracked backend patch](patches/README.md), and builds the static library and upstream tests under `build/configs/`; `build/bee2` points to the selected configuration. `go get` alone does not compile this native library. For local consumers, a Go workspace can include this checkout after its native build. Do not update the submodule independently of the pinned gitlink.

Run `make test-c` for the upstream C test suite, and `go run ./cmd/selftest` for the selected diagnostics. Passing diagnostics is not certification. `make test` and `go test ./...` run the Go suite; additional race, fuzz, slow, sanitizer, and integration checks are tracked in the coverage and release documents.

## Hash and sign a digest

```go
package main

import (
    "fmt"
    "log"

    "github.com/miniusercoder/bee2go/v3/belt"
    "github.com/miniusercoder/bee2go/v3/bign"
)

func main() {
    digest, err := belt.Hash([]byte("hello"))
    if err != nil { log.Fatal(err) }
    private, public, err := bign.Profile128.GenerateKey(nil)
    if err != nil { log.Fatal(err) }
    signature, err := bign.Profile128.SignDigestDeterministic(digest, private, nil)
    if err != nil { log.Fatal(err) }
    if err := bign.Profile128.VerifyDigest(digest, signature, public); err != nil { log.Fatal(err) }
    fmt.Println("signature verified")
}
```

BIGN signing consumes an already computed digest; it does not hash a message. A nil entropy reader uses `crypto/rand.Reader` as a seed source. For streaming hashes and other stateful objects, call `Close` when finished. Objects require caller synchronization. DWP/CHE streaming decryption buffers input and releases plaintext only after authentication; configure its input limit and use a fresh IV for every message. `bels` shares are not authenticated.

See [examples](examples/), [architecture](docs/architecture.md), and the [v3 migration guide](docs/migration-v3.md). The license is in [LICENCE](LICENCE).
