# Upstream test provenance

Backend revision: `4341f7a5c300f8e6dc292559e671eb899d831433`, with the explicitly tracked [BAuth correction](../../patches/README.md). Original Bee2 sources and vectors retain their upstream Apache-2.0 provenance. Cryptographic computations remain in Bee2.

Fixed vectors and standalone C reproducers live beside the family tests rather than in a duplicate central corpus:

| Family | Evidence |
|---|---|
| BELT / BASH / BRNG | Original `bee2/test/crypto/*_test.c` constants in adjacent Go tests; `belt/testdata/wbl_reference.c` |
| BIGN / profiles / identity | `bign/testdata/generate_vectors.c` and `vectors.txt` |
| BELS | `bels/testdata/generate_vectors.c`, `generate_remaining_vectors.c` and literal outputs |
| BOTP | Original `botp_test.c` constants; `botp/testdata/generate_time_vectors.c` |
| BPKI | `bpki/testdata/generate_vectors.c` and `vectors.txt`; upstream CSR fixture |
| BTOK CVC / secure messaging | `btok/testdata/generate_cvc_vector.c`; upstream fixed APDU vectors |
| BAKE / BAuth | `tests/integration/testdata/protocol_vectors.c` and literal transcripts; `bake_peer.c` for actual C RunA/RunB interoperability |
| DSTU / G12S / PFOK / STB99 | Each family's `testdata/generate.c`, literal outputs, SHA256SUMS and README |

Seeded fixtures specify a complete 64-byte seed, start raw C BRNG-CTR with its key/IV halves, and zero the callback buffer before each generation. This reproduces the public seed-source contract; it is not an echo RNG exposed to applications. Slow parameter generation uses fixed independent seeds under `-tags slow`. SHA files cover normalized text fixtures and their generators. Corrupted BELS values and explicitly relabeled imports are unauthenticated by design; owned share metadata prevents accidental parameter substitution.
