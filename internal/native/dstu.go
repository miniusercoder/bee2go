package native

/*
#include "bridge.h"
#include <bee2/crypto/dstu.h>
*/
import "C"
import (
	"io"
	"strings"
	"unsafe"
)

type DSTU struct {
	s                *state
	fieldLen, keyLen int
}

func DSTUStandard(name string) (*DSTU, error) {
	if strings.ContainsRune(name, 0) {
		return nil, invalid("dstu.Standard")
	}
	s, e := newState(uintptr(C.sizeof_dstu_params))
	if e != nil {
		return nil, e
	}
	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))
	p := (*C.dstu_params)(s.ptr)
	if e = codeErr("dstu.Standard", C.dstuParamsStd(p, n)); e != nil {
		s.Close()
		return nil, e
	}
	f := (int(p.p[0]) + 7) / 8
	k := f
	for k > 0 && p.n[k-1] == 0 {
		k--
	}
	return &DSTU{s, f, k}, nil
}
func (p *DSTU) check() error {
	if p == nil {
		return invalid("dstu.Params")
	}
	return p.s.check()
}
func (p *DSTU) Close() error {
	if p != nil {
		return p.s.Close()
	}
	return nil
}
func (p *DSTU) Validate() error {
	if e := p.check(); e != nil {
		return e
	}
	return codeErr("dstu.Validate", C.dstuParamsVal((*C.dstu_params)(p.s.ptr)))
}
func (p *DSTU) GeneratePoint(entropy io.Reader) ([]byte, error) {
	if e := p.check(); e != nil {
		return nil, e
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	v := make([]byte, 2*p.fieldLen)
	e = codeErr("dstu.GeneratePoint", C.dstuPointGen(octets(v), (*C.dstu_params)(p.s.ptr), C.gen_i(C.bee2go_random), r.s.ptr))
	if e != nil {
		return nil, e
	}
	return v, nil
}
func (p *DSTU) ValidatePoint(v []byte) error {
	if e := p.check(); e != nil {
		return e
	}
	if len(v) != 2*p.fieldLen {
		return invalid("dstu.ValidatePoint")
	}
	return codeErr("dstu.ValidatePoint", C.dstuPointVal((*C.dstu_params)(p.s.ptr), octets(v)))
}
func (p *DSTU) SetBasePoint(v []byte) error {
	if e := p.ValidatePoint(v); e != nil {
		return e
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&(*C.dstu_params)(p.s.ptr).P[0])), len(v)), v)
	return nil
}
func (p *DSTU) Compress(v []byte) ([]byte, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	if len(v) != 2*p.fieldLen {
		return nil, invalid("dstu.Compress")
	}
	x := make([]byte, p.fieldLen)
	e := codeErr("dstu.Compress", C.dstuPointCompress(octets(x), (*C.dstu_params)(p.s.ptr), octets(v)))
	if e != nil {
		return nil, e
	}
	return x, nil
}
func (p *DSTU) Recover(x []byte) ([]byte, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	if len(x) != p.fieldLen {
		return nil, invalid("dstu.Recover")
	}
	v := make([]byte, 2*p.fieldLen)
	e := codeErr("dstu.Recover", C.dstuPointRecover(octets(v), (*C.dstu_params)(p.s.ptr), octets(x)))
	if e != nil {
		return nil, e
	}
	return v, nil
}
func (p *DSTU) GenerateKey(entropy io.Reader) ([]byte, []byte, error) {
	if e := p.Validate(); e != nil {
		return nil, nil, e
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, nil, e
	}
	defer r.Close()
	a := make([]byte, p.keyLen)
	b := make([]byte, 2*p.fieldLen)
	e = codeErr("dstu.GenerateKey", C.dstuKeypairGen(octets(a), octets(b), (*C.dstu_params)(p.s.ptr), C.gen_i(C.bee2go_random), r.s.ptr))
	if e != nil {
		Wipe(a)
		return nil, nil, e
	}
	return a, b, nil
}
func (p *DSTU) Sign(hash, priv []byte, ld int, entropy io.Reader) ([]byte, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	if len(priv) != p.keyLen || ld%16 != 0 || ld < 16*p.keyLen {
		return nil, invalid("dstu.Sign")
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	sig := make([]byte, ld/8)
	e = codeErr("dstu.Sign", C.dstuSign(octets(sig), (*C.dstu_params)(p.s.ptr), C.size_t(ld), octets(hash), C.size_t(len(hash)), octets(priv), C.gen_i(C.bee2go_random), r.s.ptr))
	if e != nil {
		return nil, e
	}
	return sig, nil
}
func (p *DSTU) Verify(hash, sig, pub []byte) error {
	if e := p.Validate(); e != nil {
		return e
	}
	if len(sig)%2 != 0 || len(sig) < 2*p.keyLen || len(pub) != 2*p.fieldLen {
		return invalid("dstu.Verify")
	}
	return codeErr("dstu.Verify", C.dstuVerify((*C.dstu_params)(p.s.ptr), C.size_t(len(sig)*8), octets(hash), C.size_t(len(hash)), octets(sig), octets(pub)))
}
