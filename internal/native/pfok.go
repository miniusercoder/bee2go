package native

/*
#include "bridge.h"
#include <bee2/crypto/pfok.h>
*/
import "C"
import (
	"io"
	"strings"
	"unsafe"
)

type PFOKSeed struct {
	L  uint64
	ZI [31]uint16
	LI [20]uint64
}
type PFOKParams struct {
	L, R, N uint64
	P, G    [368]byte
}

func pfokSeedC(s PFOKSeed) (v C.pfok_seed) {
	v.l = C.size_t(s.L)
	for i, x := range s.ZI {
		v.zi[i] = C.u16(x)
	}
	for i, x := range s.LI {
		v.li[i] = C.size_t(x)
	}
	return
}
func pfokSeedGo(s C.pfok_seed) (v PFOKSeed) {
	v.L = uint64(s.l)
	for i, x := range s.zi {
		v.ZI[i] = uint16(x)
	}
	for i, x := range s.li {
		v.LI[i] = uint64(x)
	}
	return
}
func pfokParamsC(p PFOKParams) (v C.pfok_params) {
	v.l = C.size_t(p.L)
	v.r = C.size_t(p.R)
	v.n = C.size_t(p.N)
	for i, x := range p.P {
		v.p[i] = C.octet(x)
	}
	for i, x := range p.G {
		v.g[i] = C.octet(x)
	}
	return
}
func pfokParamsGo(p C.pfok_params) (v PFOKParams) {
	v.L = uint64(p.l)
	v.R = uint64(p.r)
	v.N = uint64(p.n)
	for i, x := range p.p {
		v.P[i] = byte(x)
	}
	for i, x := range p.g {
		v.G[i] = byte(x)
	}
	return
}
func PFOKSeedVal(s PFOKSeed) error {
	v := pfokSeedC(s)
	return codeErr("pfok.Seed.Validate", C.pfokSeedVal(&v))
}
func PFOKSeedAdj(s PFOKSeed) (PFOKSeed, error) {
	v := pfokSeedC(s)
	e := codeErr("pfok.Seed.Adjust", C.pfokSeedAdj(&v))
	return pfokSeedGo(v), e
}
func PFOKStd(name string) (PFOKParams, PFOKSeed, error) {
	var p C.pfok_params
	var s C.pfok_seed
	if strings.ContainsRune(name, 0) {
		return PFOKParams{}, PFOKSeed{}, invalid("pfok.Standard")
	}
	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))
	e := codeErr("pfok.Standard", C.pfokParamsStd(&p, &s, n))
	return pfokParamsGo(p), pfokSeedGo(s), e
}
func PFOKGen(s PFOKSeed) (PFOKParams, error) {
	var p C.pfok_params
	v := pfokSeedC(s)
	e := codeErr("pfok.Generate", C.pfokParamsGen(&p, &v, nil))
	return pfokParamsGo(p), e
}
func PFOKVal(p PFOKParams) error {
	v := pfokParamsC(p)
	return codeErr("pfok.Params.Validate", C.pfokParamsVal(&v))
}
func PFOKKey(p PFOKParams, entropy io.Reader) ([]byte, []byte, error) {
	if e := PFOKVal(p); e != nil {
		return nil, nil, e
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, nil, e
	}
	defer r.Close()
	v := pfokParamsC(p)
	a := make([]byte, (p.R+7)/8)
	b := make([]byte, (p.L+7)/8)
	e = codeErr("pfok.GenerateKey", C.pfokKeypairGen(octets(a), octets(b), &v, C.gen_i(C.bee2go_random), r.s.ptr))
	if e != nil {
		Wipe(a)
		return nil, nil, e
	}
	return a, b, nil
}
func PFOKPublic(p PFOKParams, a []byte) ([]byte, error) {
	if e := PFOKVal(p); e != nil {
		return nil, e
	}
	if uint64(len(a)) != (p.R+7)/8 {
		return nil, invalid("pfok.PublicKey")
	}
	v := pfokParamsC(p)
	b := make([]byte, (p.L+7)/8)
	e := codeErr("pfok.PublicKey", C.pfokPubkeyCalc(octets(b), &v, octets(a)))
	if e != nil {
		return nil, e
	}
	return b, nil
}
func PFOKPublicVal(p PFOKParams, b []byte) error {
	if e := PFOKVal(p); e != nil {
		return e
	}
	if uint64(len(b)) != (p.L+7)/8 {
		return invalid("pfok.ValidatePublicKey")
	}
	v := pfokParamsC(p)
	return codeErr("pfok.ValidatePublicKey", C.pfokPubkeyVal(&v, octets(b)))
}
func PFOKShare(p PFOKParams, a, a1, b, b1 []byte, mti bool) ([]byte, error) {
	if e := PFOKVal(p); e != nil {
		return nil, e
	}
	if uint64(len(a)) != (p.R+7)/8 || uint64(len(b)) != (p.L+7)/8 || (mti && (len(a1) != len(a) || len(b1) != len(b))) {
		return nil, invalid("pfok.Share")
	}
	v := pfokParamsC(p)
	key := make([]byte, (p.N+7)/8)
	var e error
	if mti {
		e = codeErr("pfok.MTI", C.pfokMTI(octets(key), &v, octets(a), octets(a1), octets(b), octets(b1)))
	} else {
		e = codeErr("pfok.DH", C.pfokDH(octets(key), &v, octets(a), octets(b)))
	}
	if e != nil {
		Wipe(key)
		return nil, e
	}
	return key, nil
}
