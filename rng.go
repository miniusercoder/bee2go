package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/bee2/include
#cgo LDFLAGS: -L${SRCDIR}/bee2/build/src -lbee2_static
#include <stdlib.h>
#include "bee2/core/err.h"
#include "bee2/core/rng.h"

// rng_err_kind classifies an err_t into a small code the Go side can switch on.
// Keeping the err.h macro comparisons in C avoids relying on CGo exposing them
// (they expand to casts, not plain integer literals). 0: ok, 1: not enough
// entropy, 2: bad entropy, -1: some other failure.
static int rng_err_kind(err_t rc) {
	if (rc == ERR_OK)                 return 0;
	if (rc == ERR_NOT_ENOUGH_ENTROPY) return 1;
	if (rc == ERR_BAD_ENTROPY)        return 2;
	return -1;
}

// rng_create_wrap casts an opaque source pointer to read_i, which CGo cannot
// do directly.
static err_t rng_create_wrap(void* source, void* source_state) {
	return rngCreate((read_i)source, source_state);
}

// Getters return the generator step functions as gen_i pointers (void*), so
// CGo can map them to unsafe.Pointer for use with APIs that accept a gen_i
// (e.g. NewBakeSettings).
static void* get_rngStepR(void)  { return (void*)rngStepR; }
static void* get_rngStepR2(void) { return (void*)rngStepR2; }
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// Sentinel errors for the documented entropy failure codes. Callers can match
// them with errors.Is, e.g. errors.Is(err, ErrNotEnoughEntropy).
var (
	// ErrNotEnoughEntropy reports that the working entropy sources do not, in
	// aggregate, provide enough randomness (STB 34.101.27 level 1: one physical
	// or at least two distinct alternative sources are required).
	ErrNotEnoughEntropy = errors.New("bee2: not enough entropy")
	// ErrBadEntropy reports that an entropy source failed or did not pass the
	// statistical (FIPS) tests.
	ErrBadEntropy = errors.New("bee2: bad entropy")
)

// rngErr maps a bee2 err_t into a Go error, attaching the operation name and
// preserving the documented sentinels for errors.Is matching.
func rngErr(op string, rc C.err_t) error {
	switch C.rng_err_kind(rc) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("bee2: %s: %w", op, ErrNotEnoughEntropy)
	case 2:
		return fmt.Errorf("bee2: %s: %w", op, ErrBadEntropy)
	default:
		return fmt.Errorf("bee2: %s: %s (code %d)", op, C.GoString(C.errMsg(rc)), uint32(rc))
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Statistical testing — FIPS 140-2 tests (STB 34.101.27)
//
// Each test consumes a 20000-bit (2500-byte) sample. A truly random sample
// fails any single test with probability p ≈ 0.0001.
//
// The tested data is NOT secret and must not be used to build keys.
// ────────────────────────────────────────────────────────────────────────────

// RngTestFIPS1 runs the FIPS monobit test on buf (the first 2500 bytes).
// It counts the number of one-bits S and passes iff 9725 < S < 10275.
// buf must be at least 2500 bytes; a shorter buffer always fails.
func RngTestFIPS1(buf []byte) bool {
	if len(buf) < 2500 {
		return false
	}
	return C.rngTestFIPS1((*C.octet)(unsafe.Pointer(&buf[0]))) != 0
}

// RngTestFIPS2 runs the FIPS poker test on buf (the first 2500 bytes).
// The sample is split into 5000 nibbles; with S_i the count of value i,
// S = 16·Σ S_i² − 5000². It passes iff 10800 < S < 230850.
// buf must be at least 2500 bytes; a shorter buffer always fails.
func RngTestFIPS2(buf []byte) bool {
	if len(buf) < 2500 {
		return false
	}
	return C.rngTestFIPS2((*C.octet)(unsafe.Pointer(&buf[0]))) != 0
}

// RngTestFIPS3 runs the FIPS runs test on buf (the first 2500 bytes),
// checking that the counts of runs of each length (for both zero- and
// one-runs) fall within the FIPS intervals.
// buf must be at least 2500 bytes; a shorter buffer always fails.
func RngTestFIPS3(buf []byte) bool {
	if len(buf) < 2500 {
		return false
	}
	return C.rngTestFIPS3((*C.octet)(unsafe.Pointer(&buf[0]))) != 0
}

// RngTestFIPS4 runs the FIPS long-run test on buf (the first 2500 bytes):
// it passes iff the sample contains no run of length 26 or more.
// buf must be at least 2500 bytes; a shorter buffer always fails.
func RngTestFIPS4(buf []byte) bool {
	if len(buf) < 2500 {
		return false
	}
	return C.rngTestFIPS4((*C.octet)(unsafe.Pointer(&buf[0]))) != 0
}

// ────────────────────────────────────────────────────────────────────────────
// Entropy sources
// ────────────────────────────────────────────────────────────────────────────

// RngESRead reads entropy from the named source into buf and returns the
// number of octets actually written. Supported sources are:
//
//   - "trng":  hardware (physical) random number generator;
//   - "trng2": additional hardware random number generator;
//   - "timer": high-resolution timer (jitter around kernel transitions);
//   - "sys":   operating-system entropy source.
//
// Fewer octets than len(buf) (possibly zero) may be returned even on success,
// for example while observations are still being accumulated; this is not an
// error. A nil/empty buf (count 0) probes for the source's presence.
//
// It returns ErrBadEntropy if the source failed to deliver the full request.
func RngESRead(buf []byte, source string) (int, error) {
	cSource := C.CString(source)
	defer C.free(unsafe.Pointer(cSource))

	var read C.size_t
	var bufPtr unsafe.Pointer
	if len(buf) > 0 {
		bufPtr = unsafe.Pointer(&buf[0])
	}
	rc := C.rngESRead(&read, bufPtr, C.size_t(len(buf)), cSource)
	return int(read), rngErr("rngESRead", rc)
}

// RngESTest statistically tests the named entropy source: it draws data from
// the source and applies all four FIPS tests, succeeding only if every test
// passes. See RngESRead for the list of source names.
func RngESTest(source string) error {
	cSource := C.CString(source)
	defer C.free(unsafe.Pointer(cSource))
	return rngErr("rngESTest", C.rngESTest(cSource))
}

// RngESHealth checks the health of the standard entropy sources: among those
// that pass statistical testing there must be one physical source, or at least
// two distinct alternative ones (STB 34.101.27 level 1).
//
// It returns nil on success, ErrNotEnoughEntropy if exactly one working source
// is missing, and ErrBadEntropy otherwise.
func RngESHealth() error {
	return rngErr("rngESHealth", C.rngESHealth())
}

// RngESHealth2 performs the stronger health check (STB 34.101.27 level 2+):
// among the sources that pass statistical testing there must be a physical one.
// It returns nil on success and ErrBadEntropy otherwise.
func RngESHealth2() error {
	return rngErr("rngESHealth2", C.rngESHealth2())
}

// ────────────────────────────────────────────────────────────────────────────
// Random number generator (process-global singleton)
//
// The library hosts a single generator. It is reference-counted: each
// successful RngCreate must be balanced by a RngClose, and the accumulated
// entropy (including the post-processing key) is destroyed only when the count
// reaches zero. Unlike the other objects in this package, the generator is
// safe for concurrent use from multiple goroutines.
// ────────────────────────────────────────────────────────────────────────────

// RngCreate creates (or re-opens) the global generator, seeding it from every
// available entropy source supported by RngESRead.
//
// It may be called multiple times; previously accumulated entropy is retained
// and the reference count is incremented. Up to 32 octets are requested from
// each source. It returns ErrNotEnoughEntropy if the working sources together
// yield fewer than 32 octets.
func RngCreate() error {
	return rngErr("rngCreate", C.rngCreate(nil, nil))
}

// RngCreateSource is like RngCreate but additionally seeds the generator from a
// caller-supplied source. source must be a C read_i function pointer (defs.h)
// cast to unsafe.Pointer; CGo cannot convert a Go func to a C function pointer.
// sourceState is the opaque state passed back to the source on each read.
// A nil source behaves exactly like RngCreate.
func RngCreateSource(source, sourceState unsafe.Pointer) error {
	return rngErr("rngCreate", C.rng_create_wrap(source, sourceState))
}

// RngIsValid reports whether the global generator is currently created (valid).
func RngIsValid() bool {
	return C.rngIsValid() != 0
}

// RngStepR fills buf with random octets, mixing in fresh data from the entropy
// sources. The generator must be valid (RngCreate called). Suitable for
// occasional use, e.g. while negotiating a shared key before a data exchange.
func RngStepR(buf []byte) {
	if len(buf) == 0 {
		return
	}
	C.rngStepR(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), nil)
}

// RngStepR2 fills buf with random octets WITHOUT drawing on the entropy
// sources. The generator must be valid (RngCreate called). Suitable for
// regular use, e.g. throughout a data exchange.
func RngStepR2(buf []byte) {
	if len(buf) == 0 {
		return
	}
	C.rngStepR2(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), nil)
}

// RngRekey replaces the generator key with freshly generated random numbers
// (without using the entropy sources). Afterwards, numbers generated earlier
// cannot be recovered even if the new key is later compromised. The generator
// must be valid.
func RngRekey() {
	C.rngRekey()
}

// RngClose decrements the generator's reference count. When it reaches zero the
// accumulated entropy and the post-processing key are destroyed. The generator
// must be valid; balance each RngCreate / RngCreateSource with one RngClose.
func RngClose() {
	C.rngClose()
}

// RngStepRGen returns RngStepR as a gen_i function pointer (defs.h), suitable
// for APIs that accept a gen_i such as NewBakeSettings. The generator must be
// valid for the whole time the pointer is in use.
func RngStepRGen() unsafe.Pointer { return C.get_rngStepR() }

// RngStepR2Gen returns RngStepR2 as a gen_i function pointer (defs.h), suitable
// for APIs that accept a gen_i such as NewBakeSettings. The generator must be
// valid for the whole time the pointer is in use.
func RngStepR2Gen() unsafe.Pointer { return C.get_rngStepR2() }
