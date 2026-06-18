package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/bee2/include
#cgo LDFLAGS: -L${SRCDIR}/bee2/build/src -lbee2_static
#include <stdlib.h>
#include "bee2/crypto/brng.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

// ────────────────────────────────────────────────────────────────────────────
// BrngCTR — PRNG in counter mode (STB 34.101.47 §6.2)
// ────────────────────────────────────────────────────────────────────────────

// BrngCTR holds the state for the brng-CTR generator.
type BrngCTR struct {
	state unsafe.Pointer
}

// NewBrngCTR initialises the CTR generator with a 32-byte key and a 32-byte IV.
// iv may be nil (a zero IV is used).
func NewBrngCTR(key, iv []byte) (*BrngCTR, error) {
	if len(key) != 32 {
		return nil, errors.New("bee2: brng-CTR key must be 32 bytes")
	}
	state := C.malloc(C.size_t(C.brngCTR_keep()))
	if state == nil {
		return nil, errors.New("bee2: malloc brngCTR state")
	}
	var ivPtr *C.octet
	if len(iv) >= 32 {
		ivPtr = (*C.octet)(unsafe.Pointer(&iv[0]))
	}
	C.brngCTRStart(state,
		(*C.octet)(unsafe.Pointer(&key[0])),
		ivPtr,
	)
	return &BrngCTR{state: state}, nil
}

// Read fills p with pseudo-random bytes and returns len(p), nil.
// Implements io.Reader.
func (r *BrngCTR) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	C.brngCTRStepR(unsafe.Pointer(&p[0]), C.size_t(len(p)), r.state)
	return len(p), nil
}

// IV returns the current (updated) 32-byte synchronisation value.
// This IV can be used to resume generation with the same key.
func (r *BrngCTR) IV() []byte {
	iv := make([]byte, 32)
	C.brngCTRStepG((*C.octet)(unsafe.Pointer(&iv[0])), r.state)
	return iv
}

// BrngCTRRand generates count pseudo-random bytes using key and iv.
// iv is updated in-place; use the returned slice as the next iv to avoid
// repeating the same output.
func BrngCTRRand(count int, key, iv []byte) ([]byte, []byte, error) {
	if len(key) != 32 {
		return nil, nil, errors.New("bee2: brng-CTR key must be 32 bytes")
	}
	if len(iv) != 32 {
		return nil, nil, errors.New("bee2: brng-CTR iv must be 32 bytes")
	}
	buf := make([]byte, count)
	ivCopy := make([]byte, 32)
	copy(ivCopy, iv)
	rc := C.brngCTRRand(
		unsafe.Pointer(&buf[0]),
		C.size_t(count),
		(*C.octet)(unsafe.Pointer(&key[0])),
		(*C.octet)(unsafe.Pointer(&ivCopy[0])),
	)
	if rc != 0 {
		return nil, nil, errors.New("bee2: brngCTRRand failed")
	}
	return buf, ivCopy, nil
}

// BrngCTRRandInto transforms buf in place using brng-CTR and returns the
// updated IV. The initial contents of buf are part of the generator input.
func BrngCTRRandInto(buf, key, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("bee2: brng-CTR key must be 32 bytes")
	}
	if len(iv) != 32 {
		return nil, errors.New("bee2: brng-CTR iv must be 32 bytes")
	}
	ivCopy := make([]byte, 32)
	copy(ivCopy, iv)
	var bufPtr unsafe.Pointer
	if len(buf) > 0 {
		bufPtr = unsafe.Pointer(&buf[0])
	}
	rc := C.brngCTRRand(
		bufPtr,
		C.size_t(len(buf)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		(*C.octet)(unsafe.Pointer(&ivCopy[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: brngCTRRand failed")
	}
	return ivCopy, nil
}

// Free releases the underlying C state.
func (r *BrngCTR) Free() {
	if r.state != nil {
		C.free(r.state)
		r.state = nil
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BrngHMAC — PRNG in HMAC mode (STB 34.101.47 §6.3)
// ────────────────────────────────────────────────────────────────────────────

// BrngHMAC holds the state for the brng-HMAC generator.
type BrngHMAC struct {
	state unsafe.Pointer
}

// NewBrngHMAC initialises the HMAC generator with key and iv.
// key may be any length (32 bytes recommended); iv may be any length.
func NewBrngHMAC(key, iv []byte) (*BrngHMAC, error) {
	if len(key) == 0 {
		return nil, errors.New("bee2: brng-HMAC key must not be empty")
	}
	state := C.malloc(C.size_t(C.brngHMAC_keep()))
	if state == nil {
		return nil, errors.New("bee2: malloc brngHMAC state")
	}
	var ivPtr *C.octet
	var ivLen C.size_t
	if len(iv) > 0 {
		ivPtr = (*C.octet)(unsafe.Pointer(&iv[0]))
		ivLen = C.size_t(len(iv))
	}
	C.brngHMACStart(state,
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		ivPtr, ivLen,
	)
	return &BrngHMAC{state: state}, nil
}

// Read fills p with pseudo-random bytes. Implements io.Reader.
func (r *BrngHMAC) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	C.brngHMACStepR(unsafe.Pointer(&p[0]), C.size_t(len(p)), r.state)
	return len(p), nil
}

// BrngHMACRand generates count pseudo-random bytes using key and iv.
func BrngHMACRand(count int, key, iv []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("bee2: brng-HMAC key must not be empty")
	}
	buf := make([]byte, count)
	var ivPtr *C.octet
	var ivLen C.size_t
	if len(iv) > 0 {
		ivPtr = (*C.octet)(unsafe.Pointer(&iv[0]))
		ivLen = C.size_t(len(iv))
	}
	rc := C.brngHMACRand(
		unsafe.Pointer(&buf[0]),
		C.size_t(count),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		ivPtr, ivLen,
	)
	if rc != 0 {
		return nil, errors.New("bee2: brngHMACRand failed")
	}
	return buf, nil
}

// Free releases the underlying C state.
func (r *BrngHMAC) Free() {
	if r.state != nil {
		C.free(r.state)
		r.state = nil
	}
}
