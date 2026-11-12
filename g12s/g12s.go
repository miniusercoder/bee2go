// Package g12s implements GOST R 34.10-2012 signatures.
package g12s

import (
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"io"
)

// Params owns a validated standard parameter set. Close it after use.
type Params struct{ p *native.G12S }

func Standard(name string) (*Params, error) {
	p, e := native.G12SStandard(name)
	if e != nil {
		return nil, e
	}
	return &Params{p}, nil
}
func (p *Params) Close() error {
	if p == nil {
		return nil
	}
	return p.owner().Close()
}
func (p *Params) Validate() error { return p.owner().Validate() }
func (p *Params) GenerateKey(entropy io.Reader) ([]byte, []byte, error) {
	return p.owner().GenerateKey(entropy)
}

// Sign accepts a big-endian digest and a little-endian private key.
func (p *Params) Sign(digest, priv []byte, entropy io.Reader) ([]byte, error) {
	return p.owner().Sign(digest, priv, entropy)
}

// Verify accepts a big-endian digest and signature, and a little-endian public key.
func (p *Params) Verify(digest, sig, pub []byte) error { return p.owner().Verify(digest, sig, pub) }

func (p *Params) owner() *native.G12S {
	if p == nil {
		return nil
	}
	return p.p
}

// Data holds curve parameters in the upstream little-endian encoding.
type Data struct {
	L        uint32
	P, A, B  [68]byte
	Q        [64]byte
	Cofactor uint32
	X, Y     [68]byte
}

// Data returns a copy of the curve parameters.
func (p *Params) Data() (Data, error) { d, e := p.owner().Data(); return Data(d), e }

// FromData validates and imports user-supplied curve parameters.
func FromData(d Data) (*Params, error) {
	p, e := native.G12SFromData(native.G12SData(d))
	if e != nil {
		return nil, e
	}
	return &Params{p}, nil
}
