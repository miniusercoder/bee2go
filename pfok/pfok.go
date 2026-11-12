// Package pfok implements the PFOK key agreement algorithms.
package pfok

import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"io"
)

// Seed contains generation input; numbers use upstream representation.
type Seed struct {
	L  uint64
	ZI [31]uint16
	LI [20]uint64
}

// Params holds little-endian parameter values.
type Params struct {
	L, R, N uint64
	P, G    [368]byte
}

func (s Seed) Validate() error { return native.PFOKSeedVal(native.PFOKSeed(s)) }
func (s *Seed) Adjust() error {
	if s == nil {
		return bee2.ErrInvalidInput
	}
	v, e := native.PFOKSeedAdj(native.PFOKSeed(*s))
	if e == nil {
		*s = Seed(v)
	}
	return e
}
func (p Params) Validate() error { return native.PFOKVal(native.PFOKParams(p)) }
func Standard(name string) (Params, Seed, error) {
	p, s, e := native.PFOKStd(name)
	return Params(p), Seed(s), e
}
func Generate(s Seed) (Params, error) {
	p, e := native.PFOKGen(native.PFOKSeed(s))
	return Params(p), e
}
func (p Params) GenerateKey(entropy io.Reader) ([]byte, []byte, error) {
	return native.PFOKKey(native.PFOKParams(p), entropy)
}
func (p Params) PublicKey(priv []byte) ([]byte, error) {
	return native.PFOKPublic(native.PFOKParams(p), priv)
}
func (p Params) ValidatePublicKey(pub []byte) error {
	return native.PFOKPublicVal(native.PFOKParams(p), pub)
}
func (p Params) DH(priv, pub []byte) ([]byte, error) {
	return native.PFOKShare(native.PFOKParams(p), priv, nil, pub, nil, false)
}
func (p Params) MTI(priv, ephemeralPriv, pub, ephemeralPub []byte) ([]byte, error) {
	return native.PFOKShare(native.PFOKParams(p), priv, ephemeralPriv, pub, ephemeralPub, true)
}

// GenerateWithProgress reports each candidate q as little-endian machine words.
// attempt is zero for the final candidate. The callback cannot cancel generation.
func GenerateWithProgress(s Seed, progress func(q []byte, attempt uint64)) (Params, error) {
	p, e := native.PFOKGenProgress(native.PFOKSeed(s), progress)
	return Params(p), e
}
