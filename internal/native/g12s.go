package native

/*
#include "bridge.h"
#include <bee2/crypto/g12s.h>
*/
import "C"
import (
	"io"
	"strings"
	"unsafe"
)

type G12S struct {
	s                *state
	keyLen, fieldLen int
}

func G12SStandard(name string) (*G12S, error) {
	if strings.ContainsRune(name, 0) {
		return nil, invalid("g12s.Standard")
	}
	s, e := newState(uintptr(C.sizeof_g12s_params))
	if e != nil {
		return nil, e
	}
	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))
	p := (*C.g12s_params)(s.ptr)
	if e = codeErr("g12s.Standard", C.g12sParamsStd(p, n)); e != nil {
		s.Close()
		return nil, e
	}
	if e = codeErr("g12s.Standard", C.g12sParamsVal(p)); e != nil {
		s.Close()
		return nil, e
	}
	m := int(p.l) / 8
	f := int(p.l) * 68 / 512
	for f > 0 && p.p[f-1] == 0 {
		f--
	}
	return &G12S{s, m, f}, nil
}
func (p *G12S) Close() error {
	if p != nil {
		return p.s.Close()
	}
	return nil
}
func (p *G12S) check() error {
	if p == nil {
		return invalid("g12s.Params")
	}
	return p.s.check()
}
func (p *G12S) Validate() error {
	if e := p.check(); e != nil {
		return e
	}
	return codeErr("g12s.Validate", C.g12sParamsVal((*C.g12s_params)(p.s.ptr)))
}
func (p *G12S) GenerateKey(entropy io.Reader) ([]byte, []byte, error) {
	if e := p.check(); e != nil {
		return nil, nil, e
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, nil, e
	}
	defer r.Close()
	a := make([]byte, p.keyLen)
	b := make([]byte, 2*p.fieldLen)
	e = codeErr("g12s.GenerateKey", C.g12sKeypairGen(octets(a), octets(b), (*C.g12s_params)(p.s.ptr), C.gen_i(C.bee2go_random), r.s.ptr))
	if e != nil {
		Wipe(a)
		return nil, nil, e
	}
	return a, b, nil
}
func (p *G12S) Sign(hash, priv []byte, entropy io.Reader) ([]byte, error) {
	if e := p.check(); e != nil {
		return nil, e
	}
	if len(hash) != p.keyLen || len(priv) != p.keyLen {
		return nil, invalid("g12s.Sign")
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	sig := make([]byte, 2*p.keyLen)
	e = codeErr("g12s.Sign", C.g12sSign(octets(sig), (*C.g12s_params)(p.s.ptr), octets(hash), octets(priv), C.gen_i(C.bee2go_random), r.s.ptr))
	if e != nil {
		return nil, e
	}
	return sig, nil
}
func (p *G12S) Verify(hash, sig, pub []byte) error {
	if e := p.check(); e != nil {
		return e
	}
	if len(hash) != p.keyLen || len(sig) != 2*p.keyLen || len(pub) != 2*p.fieldLen {
		return invalid("g12s.Verify")
	}
	return codeErr("g12s.Verify", C.g12sVerify((*C.g12s_params)(p.s.ptr), octets(hash), octets(sig), octets(pub)))
}
