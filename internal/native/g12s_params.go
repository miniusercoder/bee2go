package native

/*
#include "bridge.h"
#include <bee2/crypto/g12s.h>
*/
import "C"
import "unsafe"

type G12SData struct {
	L        uint32
	P, A, B  [68]byte
	Q        [64]byte
	Cofactor uint32
	X, Y     [68]byte
}

func (p *G12S) Data() (G12SData, error) {
	if e := p.check(); e != nil {
		return G12SData{}, e
	}
	v := (*C.g12s_params)(p.s.ptr)
	var d G12SData
	d.L = uint32(v.l)
	d.Cofactor = uint32(v.n)
	copy(d.P[:], unsafe.Slice((*byte)(unsafe.Pointer(&v.p[0])), 68))
	copy(d.A[:], unsafe.Slice((*byte)(unsafe.Pointer(&v.a[0])), 68))
	copy(d.B[:], unsafe.Slice((*byte)(unsafe.Pointer(&v.b[0])), 68))
	copy(d.Q[:], unsafe.Slice((*byte)(unsafe.Pointer(&v.q[0])), 64))
	copy(d.X[:], unsafe.Slice((*byte)(unsafe.Pointer(&v.xP[0])), 68))
	copy(d.Y[:], unsafe.Slice((*byte)(unsafe.Pointer(&v.yP[0])), 68))
	return d, nil
}
func G12SFromData(d G12SData) (*G12S, error) {
	s, e := newState(uintptr(C.sizeof_g12s_params))
	if e != nil {
		return nil, e
	}
	v := (*C.g12s_params)(s.ptr)
	v.l = C.u32(d.L)
	v.n = C.u32(d.Cofactor)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v.p[0])), 68), d.P[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v.a[0])), 68), d.A[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v.b[0])), 68), d.B[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v.q[0])), 64), d.Q[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v.xP[0])), 68), d.X[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v.yP[0])), 68), d.Y[:])
	if e = codeErr("g12s.FromData", C.g12sParamsVal(v)); e != nil {
		s.Close()
		return nil, e
	}
	f := int(v.l) * 68 / 512
	for f > 0 && v.p[f-1] == 0 {
		f--
	}
	return &G12S{s, int(v.l) / 8, f}, nil
}
