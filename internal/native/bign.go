package native

/*
#include "bridge.h"
#include <bee2/crypto/bign.h>
*/
import "C"
import (
	"io"
	"strings"
	"unsafe"
)

type BignParams struct {
	s     *state
	level int
}

func newBignParams() (*BignParams, error) {
	s, e := newState(uintptr(C.sizeof_bign_params))
	if e != nil {
		return nil, e
	}
	return &BignParams{s: s}, nil
}
func (p *BignParams) c() *C.bign_params { return (*C.bign_params)(p.s.ptr) }
func (p *BignParams) check() error {
	if p == nil {
		return invalid("bign.params")
	}
	return p.s.check()
}
func (p *BignParams) Close() error {
	if p != nil {
		return p.s.Close()
	}
	return nil
}
func (p *BignParams) Level() int {
	if e := p.check(); e != nil {
		panic(e)
	}
	return p.level
}
func BignStandard(oid string) (*BignParams, error) {
	if strings.ContainsRune(oid, 0) {
		return nil, invalid("bign.params")
	}
	p, e := newBignParams()
	if e != nil {
		return nil, e
	}
	cs := C.CString(oid)
	defer C.free(unsafe.Pointer(cs))
	if e = codeErr("bign.params", C.bignParamsStd(p.c(), cs)); e != nil {
		p.Close()
		return nil, e
	}
	p.level = int(p.c().l)
	return p, nil
}
func BignFromDER(der []byte) (*BignParams, error) {
	p, e := newBignParams()
	if e != nil {
		return nil, e
	}
	e = codeErr("bign.params.decode", C.bignParamsDec(p.c(), octets(der), C.size_t(len(der))))
	if e == nil {
		e = codeErr("bign.params.validate", C.bignParamsVal(p.c()))
	}
	if e != nil {
		p.Close()
		return nil, e
	}
	p.level = int(p.c().l)
	return p, nil
}
func (p *BignParams) DER() ([]byte, error) {
	if e := p.check(); e != nil {
		return nil, e
	}
	var n C.size_t
	e := codeErr("bign.params.encode", C.bignParamsEnc(nil, &n, p.c()))
	if e != nil {
		return nil, e
	}
	if uint64(n) > uint64(^uint(0)>>1) {
		return nil, invalid("bign.der.size")
	}
	out := make([]byte, int(n))
	e = codeErr("bign.params.encode", C.bignParamsEnc(octets(out), &n, p.c()))
	if e != nil || int(n) > len(out) {
		return nil, e
	}
	return out[:int(n)], nil
}
func (p *BignParams) Validate() error {
	if e := p.check(); e != nil {
		return e
	}
	return codeErr("bign.params.validate", C.bignParamsVal(p.c()))
}
func BignOID(oid string) ([]byte, error) {
	if strings.ContainsRune(oid, 0) {
		return nil, invalid("bign.oid")
	}
	cs := C.CString(oid)
	defer C.free(unsafe.Pointer(cs))
	var n C.size_t
	if e := codeErr("bign.oid", C.bignOidToDER(nil, &n, cs)); e != nil {
		return nil, e
	}
	if uint64(n) > uint64(^uint(0)>>1) {
		return nil, invalid("bign.oid.size")
	}
	out := make([]byte, int(n))
	if e := codeErr("bign.oid", C.bignOidToDER(octets(out), &n, cs)); e != nil {
		return nil, e
	}
	return out[:int(n)], nil
}
func BignGenerateKey(p *BignParams, entropy io.Reader) ([]byte, []byte, error) {
	if e := p.check(); e != nil {
		return nil, nil, e
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, nil, e
	}
	defer r.Close()
	a, b := make([]byte, p.level/4), make([]byte, p.level/2)
	e = codeErr("bign.generateKey", C.bignKeypairGen(octets(a), octets(b), p.c(), (C.gen_i)(C.bee2go_random), r.CTR.s.ptr))
	if e != nil {
		Wipe(a)
		Wipe(b)
		return nil, nil, e
	}
	return a, b, nil
}
func BignValidatePair(p *BignParams, priv, pub []byte) error {
	if e := p.check(); e != nil {
		return e
	}
	if len(priv) != p.level/4 || len(pub) != p.level/2 {
		return invalid("bign.keyPair")
	}
	return codeErr("bign.keyPair", C.bignKeypairVal(p.c(), octets(priv), octets(pub)))
}
func BignValidatePublic(p *BignParams, pub []byte) error {
	if e := p.check(); e != nil {
		return e
	}
	if len(pub) != p.level/2 {
		return invalid("bign.publicKey")
	}
	return codeErr("bign.publicKey", C.bignPubkeyVal(p.c(), octets(pub)))
}
func BignPublic(p *BignParams, priv []byte) ([]byte, error) {
	if e := p.check(); e != nil {
		return nil, e
	}
	if len(priv) != p.level/4 {
		return nil, invalid("bign.publicKey")
	}
	out := make([]byte, p.level/2)
	if e := codeErr("bign.publicKey", C.bignPubkeyCalc(octets(out), p.c(), octets(priv))); e != nil {
		return nil, e
	}
	return out, nil
}
func BignDH(p *BignParams, priv, pub []byte, n int) ([]byte, error) {
	if e := p.check(); e != nil {
		return nil, e
	}
	if len(priv) != p.level/4 || len(pub) != p.level/2 || n < 0 || n > p.level/2 {
		return nil, invalid("bign.dh")
	}
	out := make([]byte, n)
	if e := codeErr("bign.dh", C.bignDH(octets(out), p.c(), octets(priv), octets(pub), C.size_t(n))); e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func bignSignCheck(p *BignParams, oid, digest, priv []byte) error {
	if e := p.check(); e != nil {
		return e
	}
	if len(oid) == 0 || len(digest) != p.level/4 || len(priv) != p.level/4 {
		return invalid("bign.sign")
	}
	return nil
}
func BignSign(p *BignParams, oid, digest, priv []byte, entropy io.Reader) ([]byte, error) {
	if e := bignSignCheck(p, oid, digest, priv); e != nil {
		return nil, e
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := make([]byte, 3*p.level/8)
	e = codeErr("bign.sign", C.bignSign(octets(out), p.c(), octets(oid), C.size_t(len(oid)), octets(digest), octets(priv), (C.gen_i)(C.bee2go_random), r.CTR.s.ptr))
	if e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BignSign2(p *BignParams, oid, digest, priv, t []byte) ([]byte, error) {
	if e := bignSignCheck(p, oid, digest, priv); e != nil {
		return nil, e
	}
	out := make([]byte, 3*p.level/8)
	e := codeErr("bign.sign2", C.bignSign2(octets(out), p.c(), octets(oid), C.size_t(len(oid)), octets(digest), octets(priv), pointer(t), C.size_t(len(t))))
	if e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BignVerify(p *BignParams, oid, digest, sig, pub []byte) error {
	if e := p.check(); e != nil {
		return e
	}
	if len(oid) == 0 || len(digest) != p.level/4 || len(sig) != 3*p.level/8 || len(pub) != p.level/2 {
		return invalid("bign.verify")
	}
	return codeErr("bign.verify", C.bignVerify(p.c(), octets(oid), C.size_t(len(oid)), octets(digest), octets(sig), octets(pub)))
}
func BignWrap(p *BignParams, key, header, pub []byte, entropy io.Reader) ([]byte, error) {
	if e := p.check(); e != nil {
		return nil, e
	}
	if len(key) < 16 || (len(header) != 0 && len(header) != 16) || len(pub) != p.level/2 || len(key) > int(^uint(0)>>1)-p.level/4-16 {
		return nil, invalid("bign.wrap")
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := make([]byte, len(key)+p.level/4+16)
	e = codeErr("bign.wrap", C.bignKeyWrap(octets(out), p.c(), octets(key), C.size_t(len(key)), octets(header), octets(pub), (C.gen_i)(C.bee2go_random), r.CTR.s.ptr))
	if e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BignUnwrap(p *BignParams, token, header, priv []byte) ([]byte, error) {
	if e := p.check(); e != nil {
		return nil, e
	}
	if len(token) < p.level/4+32 || (len(header) != 0 && len(header) != 16) || len(priv) != p.level/4 {
		return nil, invalid("bign.unwrap")
	}
	out := make([]byte, len(token)-p.level/4-16)
	e := codeErr("bign.unwrap", C.bignKeyUnwrap(octets(out), p.c(), octets(token), C.size_t(len(token)), octets(header), octets(priv)))
	if e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
