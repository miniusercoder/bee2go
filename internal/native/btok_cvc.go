package native

/*
#include "bridge.h"
#include <bee2/crypto/btok.h>
*/
import "C"
import (
	"strings"
	"unsafe"
)

type CVCCertificate struct {
	Authority, Holder string
	PublicKey         []byte
	From, Until       [6]byte
	EID               [5]byte
	ESign             [2]byte
	Signature         []byte
}

func cvcInput(v CVCCertificate) (C.btok_cvc_t, error) {
	var c C.btok_cvc_t
	if len(v.Authority) > 12 || len(v.Holder) > 12 || strings.ContainsRune(v.Authority, 0) || strings.ContainsRune(v.Holder, 0) || len(v.PublicKey) > 128 || len(v.Signature) > 96 {
		return c, invalid("btok CVC fields")
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.authority[0])), 13), v.Authority)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.holder[0])), 13), v.Holder)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.pubkey[0])), 128), v.PublicKey)
	c.pubkey_len = C.size_t(len(v.PublicKey))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.from[0])), 6), v.From[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.until[0])), 6), v.Until[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.hat_eid[0])), 5), v.EID[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.hat_esign[0])), 2), v.ESign[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.sig[0])), 96), v.Signature)
	c.sig_len = C.size_t(len(v.Signature))
	return c, nil
}
func cvcOutput(c *C.btok_cvc_t) (CVCCertificate, error) {
	var v CVCCertificate
	if c.pubkey_len > 128 || c.sig_len > 96 {
		return v, invalid("btok CVC size")
	}
	v.Authority = C.GoString(&c.authority[0])
	v.Holder = C.GoString(&c.holder[0])
	v.PublicKey = C.GoBytes(unsafe.Pointer(&c.pubkey[0]), C.int(c.pubkey_len))
	v.Signature = C.GoBytes(unsafe.Pointer(&c.sig[0]), C.int(c.sig_len))
	copy(v.From[:], unsafe.Slice((*byte)(unsafe.Pointer(&c.from[0])), 6))
	copy(v.Until[:], unsafe.Slice((*byte)(unsafe.Pointer(&c.until[0])), 6))
	copy(v.EID[:], unsafe.Slice((*byte)(unsafe.Pointer(&c.hat_eid[0])), 5))
	copy(v.ESign[:], unsafe.Slice((*byte)(unsafe.Pointer(&c.hat_esign[0])), 2))
	return v, nil
}
func BTOKCVCCheck(v CVCCertificate, issuer *CVCCertificate) error {
	c, e := cvcInput(v)
	if e != nil {
		return e
	}
	if issuer == nil {
		return codeErr("btok CVC check", C.btokCVCCheck(&c))
	}
	a, e := cvcInput(*issuer)
	if e != nil {
		return e
	}
	return codeErr("btok CVC check issuer", C.btokCVCCheck2(&c, &a))
}
func BTOKCVCWrap(v CVCCertificate, key, issuer []byte, issue bool) ([]byte, CVCCertificate, error) {
	var zero CVCCertificate
	c, e := cvcInput(v)
	if e != nil {
		return nil, zero, e
	}
	if len(key) != 24 && len(key) != 32 && len(key) != 48 && len(key) != 64 {
		return nil, zero, invalid("btok CVC key")
	}
	if issue && len(issuer) == 0 {
		return nil, zero, invalid("btok CVC issuer")
	}
	var n C.size_t
	call := func(out []byte) C.err_t {
		if issue {
			return C.btokCVCIss(octets(out), &n, &c, octets(issuer), C.size_t(len(issuer)), octets(key), C.size_t(len(key)))
		}
		return C.btokCVCWrap(octets(out), &n, &c, octets(key), C.size_t(len(key)))
	}
	if e = codeErr("btok CVC size", call(nil)); e != nil {
		return nil, zero, e
	}
	if n == 0 || n > 4096 {
		return nil, zero, invalid("btok CVC size")
	}
	out := make([]byte, int(n))
	capacity := n
	if e = codeErr("btok CVC wrap", call(out)); e != nil {
		return nil, zero, e
	}
	if n != capacity {
		return nil, zero, invalid("btok CVC size")
	}
	result, e := cvcOutput(&c)
	if e != nil {
		return nil, zero, e
	}
	return out, result, nil
}
func BTOKCVCUnwrap(cert, pub []byte) (CVCCertificate, error) {
	var zero CVCCertificate
	if len(cert) == 0 || (len(pub) != 0 && len(pub) != 48 && len(pub) != 64 && len(pub) != 96 && len(pub) != 128) {
		return zero, invalid("btok CVC input")
	}
	var c C.btok_cvc_t
	if e := codeErr("btok CVC unwrap", C.btokCVCUnwrap(&c, octets(cert), C.size_t(len(cert)), octets(pub), C.size_t(len(pub)))); e != nil {
		return zero, e
	}
	return cvcOutput(&c)
}
func BTOKCVCLength(der []byte) (int, error) {
	if len(der) == 0 {
		return 0, invalid("btok CVC length")
	}
	n := C.btokCVCLen(octets(der), C.size_t(len(der)))
	if n == ^C.size_t(0) || uint64(n) > uint64(len(der)) {
		return 0, invalid("btok CVC length")
	}
	return int(n), nil
}
func cvcDate(date *[6]byte) *C.octet {
	if date == nil {
		return nil
	}
	return octets(date[:])
}
func BTOKCVCValidate(cert, issuer []byte, date *[6]byte) error {
	if len(cert) == 0 || len(issuer) == 0 {
		return invalid("btok CVC validate")
	}
	return codeErr("btok CVC validate", C.btokCVCVal(octets(cert), C.size_t(len(cert)), octets(issuer), C.size_t(len(issuer)), cvcDate(date)))
}
func BTOKCVCValidate2(cert []byte, issuer CVCCertificate, date *[6]byte) (CVCCertificate, error) {
	var zero CVCCertificate
	if len(cert) == 0 {
		return zero, invalid("btok CVC validate")
	}
	a, e := cvcInput(issuer)
	if e != nil {
		return zero, e
	}
	var c C.btok_cvc_t
	if e = codeErr("btok CVC validate", C.btokCVCVal2(&c, octets(cert), C.size_t(len(cert)), &a, cvcDate(date))); e != nil {
		return zero, e
	}
	return cvcOutput(&c)
}
func BTOKCVCMatch(cert, key []byte) error {
	if len(cert) == 0 || (len(key) != 24 && len(key) != 32 && len(key) != 48 && len(key) != 64) {
		return invalid("btok CVC match")
	}
	return codeErr("btok CVC match", C.btokCVCMatch(octets(cert), C.size_t(len(cert)), octets(key), C.size_t(len(key))))
}
