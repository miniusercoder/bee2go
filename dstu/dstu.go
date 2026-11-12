// Package dstu implements DSTU 4145-2002 signatures.
package dstu

import (
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"io"
)

// Params owns a standard curve and its base point. Close after use.
type Params struct{ p *native.DSTU }

func Standard(name string) (*Params, error) {
	p, e := native.DSTUStandard(name)
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
func (p *Params) GeneratePoint(entropy io.Reader) ([]byte, error) {
	return p.owner().GeneratePoint(entropy)
}
func (p *Params) ValidatePoint(point []byte) error      { return p.owner().ValidatePoint(point) }
func (p *Params) SetBasePoint(point []byte) error       { return p.owner().SetBasePoint(point) }
func (p *Params) Compress(point []byte) ([]byte, error) { return p.owner().Compress(point) }
func (p *Params) Recover(point []byte) ([]byte, error)  { return p.owner().Recover(point) }
func (p *Params) GenerateKey(entropy io.Reader) ([]byte, []byte, error) {
	return p.owner().GenerateKey(entropy)
}

// Sign uses little-endian digest and key encodings, and a signature size in bits.
func (p *Params) Sign(digest, priv []byte, bits int, entropy io.Reader) ([]byte, error) {
	return p.owner().Sign(digest, priv, bits, entropy)
}
func (p *Params) Verify(digest, sig, pub []byte) error { return p.owner().Verify(digest, sig, pub) }

func (p *Params) owner() *native.DSTU {
	if p == nil {
		return nil
	}
	return p.p
}

// Data holds curve parameters in the upstream little-endian encoding.
type Data struct {
	Field    [4]uint16
	A        byte
	B, N     [64]byte
	Cofactor uint32
	Base     [128]byte
}

// Data returns a copy of the curve parameters.
func (p *Params) Data() (Data, error) { d, e := p.owner().Data(); return Data(d), e }

// FromData validates and imports user-supplied curve parameters.
func FromData(d Data) (*Params, error) {
	p, e := native.DSTUFromData(native.DSTUData(d))
	if e != nil {
		return nil, e
	}
	return &Params{p}, nil
}
