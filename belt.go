package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/bee2/include
#cgo LDFLAGS: -L${SRCDIR}/bee2/build/src -lbee2_static
#include <stdlib.h>
#include <string.h>
#include "bee2/crypto/belt.h"
*/
import "C"
import (
	"errors"
	"hash"
	"unsafe"
)

// ────────────────────────────────────────────────────────────────────────────
// belt-hash (hash.Hash, STB 34.101.31 §6.3)
// ────────────────────────────────────────────────────────────────────────────

type beltHash struct {
	state unsafe.Pointer
}

// NewBeltHash returns a new hash.Hash computing belt-hash (32-byte digest).
func NewBeltHash() (hash.Hash, error) {
	state := C.malloc(C.size_t(C.beltHash_keep()))
	if state == nil {
		return nil, errors.New("bee2: malloc beltHash state")
	}
	C.beltHashStart(state)
	return &beltHash{state: state}, nil
}

func (h *beltHash) Write(p []byte) (int, error) {
	if len(p) > 0 {
		C.beltHashStepH(unsafe.Pointer(&p[0]), C.size_t(len(p)), h.state)
	}
	return len(p), nil
}

func (h *beltHash) Sum(b []byte) []byte {
	sz := C.size_t(C.beltHash_keep())
	tmp := C.malloc(sz)
	if tmp == nil {
		panic("bee2: malloc beltHash tmp")
	}
	defer C.free(tmp)
	C.memcpy(tmp, h.state, sz)
	out := make([]byte, 32)
	C.beltHashStepG((*C.octet)(unsafe.Pointer(&out[0])), tmp)
	return append(b, out...)
}

func (h *beltHash) Reset()         { C.beltHashStart(h.state) }
func (h *beltHash) Size() int      { return 32 }
func (h *beltHash) BlockSize() int { return 32 }

// Free releases the underlying C state.
func (h *beltHash) Free() {
	if h.state != nil {
		C.free(h.state)
		h.state = nil
	}
}

// BeltHash computes the belt-hash of src in a single call.
func BeltHash(src []byte) ([]byte, error) {
	h, err := NewBeltHash()
	if err != nil {
		return nil, err
	}
	defer h.(*beltHash).Free()
	_, _ = h.Write(src)
	return h.Sum(nil), nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-ECB (STB 34.101.31 §6.1.1)
// ────────────────────────────────────────────────────────────────────────────

// BeltECBEncr encrypts src in ECB mode under key (16, 24, or 32 bytes).
// src length must be a multiple of 16 and ≥ 16.
func BeltECBEncr(src, key []byte) ([]byte, error) {
	if err := checkBeltKey(key); err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	rc := C.beltECBEncr(
		unsafe.Pointer(&dst[0]),
		unsafe.Pointer(&src[0]),
		C.size_t(len(src)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltECBEncr failed")
	}
	return dst, nil
}

// BeltECBDecr decrypts src in ECB mode under key.
func BeltECBDecr(src, key []byte) ([]byte, error) {
	if err := checkBeltKey(key); err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	rc := C.beltECBDecr(
		unsafe.Pointer(&dst[0]),
		unsafe.Pointer(&src[0]),
		C.size_t(len(src)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltECBDecr failed")
	}
	return dst, nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-CBC (STB 34.101.31 §6.1.2)
// ────────────────────────────────────────────────────────────────────────────

// BeltCBCEncr encrypts src in CBC mode. iv must be exactly 16 bytes.
func BeltCBCEncr(src, key, iv []byte) ([]byte, error) {
	if err := checkBeltKey(key); err != nil {
		return nil, err
	}
	if len(iv) != 16 {
		return nil, errors.New("bee2: belt-CBC iv must be 16 bytes")
	}
	dst := make([]byte, len(src))
	rc := C.beltCBCEncr(
		unsafe.Pointer(&dst[0]),
		unsafe.Pointer(&src[0]),
		C.size_t(len(src)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.octet)(unsafe.Pointer(&iv[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltCBCEncr failed")
	}
	return dst, nil
}

// BeltCBCDecr decrypts src in CBC mode.
func BeltCBCDecr(src, key, iv []byte) ([]byte, error) {
	if err := checkBeltKey(key); err != nil {
		return nil, err
	}
	if len(iv) != 16 {
		return nil, errors.New("bee2: belt-CBC iv must be 16 bytes")
	}
	dst := make([]byte, len(src))
	rc := C.beltCBCDecr(
		unsafe.Pointer(&dst[0]),
		unsafe.Pointer(&src[0]),
		C.size_t(len(src)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.octet)(unsafe.Pointer(&iv[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltCBCDecr failed")
	}
	return dst, nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-CFB (STB 34.101.31 §6.1.3)
// ────────────────────────────────────────────────────────────────────────────

// BeltCFBEncr encrypts src in CFB mode. iv must be exactly 16 bytes.
func BeltCFBEncr(src, key, iv []byte) ([]byte, error) {
	if err := checkBeltKey(key); err != nil {
		return nil, err
	}
	if len(iv) != 16 {
		return nil, errors.New("bee2: belt-CFB iv must be 16 bytes")
	}
	dst := make([]byte, len(src))
	rc := C.beltCFBEncr(
		unsafe.Pointer(&dst[0]),
		unsafe.Pointer(&src[0]),
		C.size_t(len(src)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.octet)(unsafe.Pointer(&iv[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltCFBEncr failed")
	}
	return dst, nil
}

// BeltCFBDecr decrypts src in CFB mode.
func BeltCFBDecr(src, key, iv []byte) ([]byte, error) {
	if err := checkBeltKey(key); err != nil {
		return nil, err
	}
	if len(iv) != 16 {
		return nil, errors.New("bee2: belt-CFB iv must be 16 bytes")
	}
	dst := make([]byte, len(src))
	rc := C.beltCFBDecr(
		unsafe.Pointer(&dst[0]),
		unsafe.Pointer(&src[0]),
		C.size_t(len(src)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.octet)(unsafe.Pointer(&iv[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltCFBDecr failed")
	}
	return dst, nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-CTR (STB 34.101.31 §6.1.4)
// ────────────────────────────────────────────────────────────────────────────

// BeltCTR encrypts or decrypts src in CTR mode (symmetric operation).
// iv must be exactly 16 bytes.
func BeltCTR(src, key, iv []byte) ([]byte, error) {
	if err := checkBeltKey(key); err != nil {
		return nil, err
	}
	if len(iv) != 16 {
		return nil, errors.New("bee2: belt-CTR iv must be 16 bytes")
	}
	dst := make([]byte, len(src))
	rc := C.beltCTR(
		unsafe.Pointer(&dst[0]),
		unsafe.Pointer(&src[0]),
		C.size_t(len(src)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.octet)(unsafe.Pointer(&iv[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltCTR failed")
	}
	return dst, nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-MAC (STB 34.101.31 §6.2)
// ────────────────────────────────────────────────────────────────────────────

// BeltMAC computes an 8-byte message authentication code over src under key.
func BeltMAC(src, key []byte) ([]byte, error) {
	if err := checkBeltKey(key); err != nil {
		return nil, err
	}
	mac := make([]byte, 8)
	rc := C.beltMAC(
		(*C.octet)(unsafe.Pointer(&mac[0])),
		unsafe.Pointer(&src[0]),
		C.size_t(len(src)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltMAC failed")
	}
	return mac, nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-DWP authenticated encryption (STB 34.101.31 §6.3.1)
// ────────────────────────────────────────────────────────────────────────────

// BeltDWPWrap encrypts plaintext and authenticates (plaintext, aad) together.
//
// Returns (ciphertext, mac[8]).
// iv must be 16 bytes.
func BeltDWPWrap(plaintext, aad, key, iv []byte) (ciphertext, mac []byte, err error) {
	if err = checkBeltKey(key); err != nil {
		return
	}
	if len(iv) != 16 {
		err = errors.New("bee2: belt-DWP iv must be 16 bytes")
		return
	}
	ciphertext = make([]byte, len(plaintext))
	mac = make([]byte, 8)

	var ptPtr, aadPtr unsafe.Pointer
	if len(plaintext) > 0 {
		ptPtr = unsafe.Pointer(&plaintext[0])
	}
	if len(aad) > 0 {
		aadPtr = unsafe.Pointer(&aad[0])
	}

	rc := C.beltDWPWrap(
		unsafe.Pointer(&ciphertext[0]),
		(*C.octet)(unsafe.Pointer(&mac[0])),
		ptPtr, C.size_t(len(plaintext)),
		aadPtr, C.size_t(len(aad)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.octet)(unsafe.Pointer(&iv[0])),
	)
	if rc != 0 {
		err = errors.New("bee2: beltDWPWrap failed")
		ciphertext, mac = nil, nil
	}
	return
}

// BeltDWPUnwrap decrypts and verifies a DWP-protected message.
// mac must be the 8-byte tag returned by BeltDWPWrap.
func BeltDWPUnwrap(ciphertext, aad, mac, key, iv []byte) ([]byte, error) {
	if err := checkBeltKey(key); err != nil {
		return nil, err
	}
	if len(iv) != 16 {
		return nil, errors.New("bee2: belt-DWP iv must be 16 bytes")
	}
	if len(mac) != 8 {
		return nil, errors.New("bee2: belt-DWP mac must be 8 bytes")
	}
	plaintext := make([]byte, len(ciphertext))

	var ctPtr, aadPtr unsafe.Pointer
	if len(ciphertext) > 0 {
		ctPtr = unsafe.Pointer(&ciphertext[0])
	}
	if len(aad) > 0 {
		aadPtr = unsafe.Pointer(&aad[0])
	}

	rc := C.beltDWPUnwrap(
		unsafe.Pointer(&plaintext[0]),
		ctPtr, C.size_t(len(ciphertext)),
		aadPtr, C.size_t(len(aad)),
		(*C.octet)(unsafe.Pointer(&mac[0])),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.octet)(unsafe.Pointer(&iv[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltDWPUnwrap: authentication failed")
	}
	return plaintext, nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-CHE authenticated encryption (STB 34.101.31 §6.3.2)
// ────────────────────────────────────────────────────────────────────────────

// BeltCHEWrap encrypts plaintext and authenticates (plaintext, aad).
// Returns (ciphertext, mac[8]).
// iv must be 16 bytes.
func BeltCHEWrap(plaintext, aad, key, iv []byte) (ciphertext, mac []byte, err error) {
	if err = checkBeltKey(key); err != nil {
		return
	}
	if len(iv) != 16 {
		err = errors.New("bee2: belt-CHE iv must be 16 bytes")
		return
	}
	ciphertext = make([]byte, len(plaintext))
	mac = make([]byte, 8)

	var ptPtr, aadPtr unsafe.Pointer
	if len(plaintext) > 0 {
		ptPtr = unsafe.Pointer(&plaintext[0])
	}
	if len(aad) > 0 {
		aadPtr = unsafe.Pointer(&aad[0])
	}

	rc := C.beltCHEWrap(
		unsafe.Pointer(&ciphertext[0]),
		(*C.octet)(unsafe.Pointer(&mac[0])),
		ptPtr, C.size_t(len(plaintext)),
		aadPtr, C.size_t(len(aad)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.octet)(unsafe.Pointer(&iv[0])),
	)
	if rc != 0 {
		err = errors.New("bee2: beltCHEWrap failed")
		ciphertext, mac = nil, nil
	}
	return
}

// BeltCHEUnwrap decrypts and verifies a CHE-protected message.
func BeltCHEUnwrap(ciphertext, aad, mac, key, iv []byte) ([]byte, error) {
	if err := checkBeltKey(key); err != nil {
		return nil, err
	}
	if len(iv) != 16 {
		return nil, errors.New("bee2: belt-CHE iv must be 16 bytes")
	}
	if len(mac) != 8 {
		return nil, errors.New("bee2: belt-CHE mac must be 8 bytes")
	}
	plaintext := make([]byte, len(ciphertext))

	var ctPtr, aadPtr unsafe.Pointer
	if len(ciphertext) > 0 {
		ctPtr = unsafe.Pointer(&ciphertext[0])
	}
	if len(aad) > 0 {
		aadPtr = unsafe.Pointer(&aad[0])
	}

	rc := C.beltCHEUnwrap(
		unsafe.Pointer(&plaintext[0]),
		ctPtr, C.size_t(len(ciphertext)),
		aadPtr, C.size_t(len(aad)),
		(*C.octet)(unsafe.Pointer(&mac[0])),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.octet)(unsafe.Pointer(&iv[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltCHEUnwrap: authentication failed")
	}
	return plaintext, nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-KWP key wrap (STB 34.101.31 §6.4)
// ────────────────────────────────────────────────────────────────────────────

// BeltKWPWrap wraps key under wrapKey, producing a token of len(key)+16 bytes.
// header is optional (16 bytes or nil).  key must be ≥ 16 bytes.
func BeltKWPWrap(key, header, wrapKey []byte) ([]byte, error) {
	if err := checkBeltKey(wrapKey); err != nil {
		return nil, err
	}
	if len(key) < 16 {
		return nil, errors.New("bee2: belt-KWP key must be ≥ 16 bytes")
	}
	token := make([]byte, len(key)+16)
	var hdrPtr *C.octet
	if len(header) >= 16 {
		hdrPtr = (*C.octet)(unsafe.Pointer(&header[0]))
	}
	rc := C.beltKWPWrap(
		(*C.octet)(unsafe.Pointer(&token[0])),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		hdrPtr,
		(*C.octet)(unsafe.Pointer(&wrapKey[0])),
		C.size_t(len(wrapKey)),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltKWPWrap failed")
	}
	return token, nil
}

// BeltKWPUnwrap recovers the original key from token.
// header must match what was given to BeltKWPWrap (nil means all-zero header).
func BeltKWPUnwrap(token, header, wrapKey []byte) ([]byte, error) {
	if err := checkBeltKey(wrapKey); err != nil {
		return nil, err
	}
	if len(token) < 32 {
		return nil, errors.New("bee2: belt-KWP token too short (must be ≥ 32 bytes)")
	}
	key := make([]byte, len(token)-16)
	var hdrPtr *C.octet
	if len(header) >= 16 {
		hdrPtr = (*C.octet)(unsafe.Pointer(&header[0]))
	}
	rc := C.beltKWPUnwrap(
		(*C.octet)(unsafe.Pointer(&key[0])),
		(*C.octet)(unsafe.Pointer(&token[0])),
		C.size_t(len(token)),
		hdrPtr,
		(*C.octet)(unsafe.Pointer(&wrapKey[0])),
		C.size_t(len(wrapKey)),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltKWPUnwrap failed")
	}
	return key, nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-HMAC (STB 34.101.47 §7)
// ────────────────────────────────────────────────────────────────────────────

// BeltHMAC computes a 32-byte HMAC-belt-hash over src under key.
func BeltHMAC(src, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("bee2: belt-HMAC key must not be empty")
	}
	mac := make([]byte, 32)
	rc := C.beltHMAC(
		(*C.octet)(unsafe.Pointer(&mac[0])),
		unsafe.Pointer(&src[0]),
		C.size_t(len(src)),
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltHMAC failed")
	}
	return mac, nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-PBKDF2 (STB 34.101.45 annex E)
// ────────────────────────────────────────────────────────────────────────────

// BeltPBKDF2 derives a 32-byte key from password using PBKDF2 with belt-HMAC.
// iter should be ≥ 10 000 in production; salt should be ≥ 8 bytes.
func BeltPBKDF2(password []byte, iter int, salt []byte) ([]byte, error) {
	if iter <= 0 {
		return nil, errors.New("bee2: belt-PBKDF2 iter must be > 0")
	}
	if len(password) == 0 {
		return nil, errors.New("bee2: belt-PBKDF2 password must not be empty")
	}
	key := make([]byte, 32)
	var saltPtr *C.octet
	if len(salt) > 0 {
		saltPtr = (*C.octet)(unsafe.Pointer(&salt[0]))
	}
	rc := C.beltPBKDF2(
		(*C.octet)(unsafe.Pointer(&key[0])),
		(*C.octet)(unsafe.Pointer(&password[0])),
		C.size_t(len(password)),
		C.size_t(iter),
		saltPtr,
		C.size_t(len(salt)),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltPBKDF2 failed")
	}
	return key, nil
}

// ────────────────────────────────────────────────────────────────────────────
// belt-KRP (STB 34.101.31 §7.3)
// ────────────────────────────────────────────────────────────────────────────

// BeltKRP transforms src key of length n into dest key of length m.
// level must be 12 bytes, header must be 16 bytes.
func BeltKRP(src []byte, level, header []byte, m int) ([]byte, error) {
	n := len(src)
	if n != 16 && n != 24 && n != 32 {
		return nil, errors.New("bee2: belt-KRP src key must be 16, 24, or 32 bytes")
	}
	if m != 16 && m != 24 && m != 32 {
		return nil, errors.New("bee2: belt-KRP dest key must be 16, 24, or 32 bytes")
	}
	if m > n {
		return nil, errors.New("bee2: belt-KRP m must be <= n")
	}
	if len(level) != 12 {
		return nil, errors.New("bee2: belt-KRP level must be 12 bytes")
	}
	if len(header) != 16 {
		return nil, errors.New("bee2: belt-KRP header must be 16 bytes")
	}
	dest := make([]byte, m)
	rc := C.beltKRP(
		(*C.octet)(unsafe.Pointer(&dest[0])),
		C.size_t(m),
		(*C.octet)(unsafe.Pointer(&src[0])),
		C.size_t(n),
		(*C.octet)(unsafe.Pointer(&level[0])),
		(*C.octet)(unsafe.Pointer(&header[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: beltKRP failed")
	}
	return dest, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

func checkBeltKey(key []byte) error {
	n := len(key)
	if n != 16 && n != 24 && n != 32 {
		return errors.New("bee2: belt key must be 16, 24, or 32 bytes")
	}
	return nil
}
