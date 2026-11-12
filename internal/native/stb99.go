package native

/*
#include "bridge.h"
#include <bee2/crypto/stb99.h>
*/
import "C"
import (
	"strings"
	"unsafe"
)

type STB99Seed struct {
	L  uint64
	ZI [31]uint16
	DI [18]uint64
	RI [10]uint64
}
type STB99Params struct {
	L, R uint64
	P    [308]byte
	Q    [33]byte
	A, D [308]byte
}

func stb99SeedC(s STB99Seed) (v C.stb99_seed) {
	v.l = C.size_t(s.L)
	for i, x := range s.ZI {
		v.zi[i] = C.u16(x)
	}
	for i, x := range s.DI {
		v.di[i] = C.size_t(x)
	}
	for i, x := range s.RI {
		v.ri[i] = C.size_t(x)
	}
	return
}
func stb99SeedGo(s C.stb99_seed) (v STB99Seed) {
	v.L = uint64(s.l)
	for i, x := range s.zi {
		v.ZI[i] = uint16(x)
	}
	for i, x := range s.di {
		v.DI[i] = uint64(x)
	}
	for i, x := range s.ri {
		v.RI[i] = uint64(x)
	}
	return
}
func stb99ParamsC(p STB99Params) (v C.stb99_params) {
	v.l = C.size_t(p.L)
	v.r = C.size_t(p.R)
	for i, x := range p.P {
		v.p[i] = C.octet(x)
	}
	for i, x := range p.Q {
		v.q[i] = C.octet(x)
	}
	for i, x := range p.A {
		v.a[i] = C.octet(x)
	}
	for i, x := range p.D {
		v.d[i] = C.octet(x)
	}
	return
}
func stb99ParamsGo(p C.stb99_params) (v STB99Params) {
	v.L = uint64(p.l)
	v.R = uint64(p.r)
	for i, x := range p.p {
		v.P[i] = byte(x)
	}
	for i, x := range p.q {
		v.Q[i] = byte(x)
	}
	for i, x := range p.a {
		v.A[i] = byte(x)
	}
	for i, x := range p.d {
		v.D[i] = byte(x)
	}
	return
}
func STB99SeedVal(s STB99Seed) error {
	v := stb99SeedC(s)
	return codeErr("stb99.Seed.Validate", C.stb99SeedVal(&v))
}
func STB99SeedAdj(s STB99Seed) (STB99Seed, error) {
	v := stb99SeedC(s)
	e := codeErr("stb99.Seed.Adjust", C.stb99SeedAdj(&v))
	return stb99SeedGo(v), e
}
func STB99Std(name string) (STB99Params, STB99Seed, error) {
	if strings.ContainsRune(name, 0) {
		return STB99Params{}, STB99Seed{}, invalid("stb99.Standard")
	}
	var p C.stb99_params
	var s C.stb99_seed
	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))
	e := codeErr("stb99.Standard", C.stb99ParamsStd(&p, &s, n))
	return stb99ParamsGo(p), stb99SeedGo(s), e
}
func STB99Gen(s STB99Seed) (STB99Params, error) {
	var p C.stb99_params
	v := stb99SeedC(s)
	e := codeErr("stb99.Generate", C.stb99ParamsGen(&p, &v))
	return stb99ParamsGo(p), e
}
func STB99Val(p STB99Params) error {
	v := stb99ParamsC(p)
	return codeErr("stb99.Params.Validate", C.stb99ParamsVal(&v))
}
