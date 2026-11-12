# Release and legacy policy

The old module path and root API are preserved on `legacy` (baseline `c2df476`, compatible CI commit `845b255`) and snapshot `legacy-2026-11-12`. The v3 line uses `github.com/miniusercoder/bee2go/v3`. Old tags are not moved and legacy fixes must retain its API. New families belong to v3.

The implementation covers every capability mapped from the pinned 17 crypto headers; see [the coverage matrix](algorithm-coverage.md). General utilities and internal mathematics are excluded. The tracked [BAuth patch](../patches/README.md) fixes the pinned backend's challenge-length defect without changing the submodule or wire format.

Source verification on Linux amd64 includes Go1.22.12 and Go1.27.1, the full Go and slow suites, upstream CTest, race, cgocheck2, ten bounded fuzz targets, Clang ASan/UBSan with the full slow suite, ten diagnostic KATs, and sixteen runnable public examples. Independent C fixtures cover all families and every protocol message. Clean source builds and an external consumer were checked for both module lines. This establishes source/build and boundary compatibility, not cryptographic certification or long-duration fuzz coverage.

Independent whole-branch review found two important defects: OTP embedded-NUL truncation and loss of custom BELS parameter associations. Both have failing-then-passing regression tests and are fixed. The earlier callback lifetime and secure-messaging failure-state findings were also fixed. No unresolved review finding is deferred into the candidate.

The v3 implementation was published to `main` after `legacy` and snapshot `legacy-2026-11-12` were published. Branch protection has not been configured by this migration. Versioned releases remain a separate user-controlled step: publish `v3.0.0-rc.1`, verify the remote clean build/consumer and CI gates, then approve `v3.0.0` separately. Keep Go API versions independent of bee2 versions. A diagnostic self-test is not certification.
