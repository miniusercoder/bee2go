package native

/*
#include "bridge.h"
#include <bee2/crypto/dstu.h>
*/
import "C"
import "unsafe"

type DSTUData struct {
	Field    [4]uint16
	A        byte
	B, N     [64]byte
	Cofactor uint32
	Base     [128]byte
}

func (p *DSTU) Data() (DSTUData, error) {
	if e := p.check(); e != nil {
		return DSTUData{}, e
	}
	v := (*C.dstu_params)(p.s.ptr)
	var d DSTUData
	for i, x := range v.p {
		d.Field[i] = uint16(x)
	}
	d.A = byte(v.A)
	d.Cofactor = uint32(v.c)
	copy(d.B[:], unsafe.Slice((*byte)(unsafe.Pointer(&v.B[0])), 64))
	copy(d.N[:], unsafe.Slice((*byte)(unsafe.Pointer(&v.n[0])), 64))
	copy(d.Base[:], unsafe.Slice((*byte)(unsafe.Pointer(&v.P[0])), 128))
	return d, nil
}
func DSTUFromData(d DSTUData) (*DSTU, error) {
	s, e := newState(uintptr(C.sizeof_dstu_params))
	if e != nil {
		return nil, e
	}
	v := (*C.dstu_params)(s.ptr)
	for i, x := range d.Field {
		v.p[i] = C.u16(x)
	}
	v.A = C.octet(d.A)
	v.c = C.u32(d.Cofactor)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v.B[0])), 64), d.B[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v.n[0])), 64), d.N[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v.P[0])), 128), d.Base[:])
	if e = codeErr("dstu.FromData", C.dstuParamsVal(v)); e != nil {
		s.Close()
		return nil, e
	}
	f := (int(v.p[0]) + 7) / 8
	k := f
	for k > 0 && v.n[k-1] == 0 {
		k--
	}
	return &DSTU{s, f, k}, nil
}
