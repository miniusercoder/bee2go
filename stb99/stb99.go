// Package stb99 implements STB 1176.2-99 parameter generation.
package stb99

import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/internal/native"
)

// Seed contains the generation seed and its chains.
type Seed struct {
	L  uint64
	ZI [31]uint16
	DI [18]uint64
	RI [10]uint64
}

// Params contains integers in upstream little-endian representation.
type Params struct {
	L, R uint64
	P    [308]byte
	Q    [33]byte
	A, D [308]byte
}

func (s Seed) Validate() error { return native.STB99SeedVal(native.STB99Seed(s)) }
func (s *Seed) Adjust() error {
	if s == nil {
		return bee2.ErrInvalidInput
	}
	v, e := native.STB99SeedAdj(native.STB99Seed(*s))
	if e == nil {
		*s = Seed(v)
	}
	return e
}
func (p Params) Validate() error { return native.STB99Val(native.STB99Params(p)) }
func Standard(name string) (Params, Seed, error) {
	p, s, e := native.STB99Std(name)
	return Params(p), Seed(s), e
}
func Generate(seed Seed) (Params, error) {
	p, e := native.STB99Gen(native.STB99Seed(seed))
	return Params(p), e
}
