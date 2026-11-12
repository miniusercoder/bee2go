// Package bign wraps the bee2 BIGN signatures, key transport and agreement.
// Numeric byte strings use the upstream little-endian representation.
// SignDigest consumes a digest; it never hashes a message implicitly.
package bign

import (
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"io"
)

const (
	Curve256v1  = "1.2.112.0.2.0.34.101.45.3.1"
	Curve384v1  = "1.2.112.0.2.0.34.101.45.3.2"
	Curve512v1  = "1.2.112.0.2.0.34.101.45.3.3"
	OIDBeltHash = "1.2.112.0.2.0.34.101.31.81"
)

var ErrNoResult = errors.New("bign: no order for this candidate")

type Params struct{ n *native.BignParams }

func StandardParams(oid string) (*Params, error) {
	n, e := native.BignStandard(oid)
	if e != nil {
		return nil, e
	}
	return &Params{n}, nil
}
func ParamsFromDER(der []byte) (*Params, error) {
	n, e := native.BignFromDER(der)
	if e != nil {
		return nil, e
	}
	return &Params{n}, nil
}
func (p *Params) DER() ([]byte, error) { return p.n.DER() }
func (p *Params) Validate() error      { return p.n.Validate() }
func (p *Params) Level() int           { return p.n.Level() }
func (p *Params) Close() error {
	if p != nil {
		return p.n.Close()
	}
	return nil
}
func params(p *Params) *native.BignParams {
	if p == nil {
		return nil
	}
	return p.n
}
func OIDToDER(oid string) ([]byte, error) { return native.BignOID(oid) }
func GenerateKey(p *Params, r io.Reader) ([]byte, []byte, error) {
	return native.BignGenerateKey(params(p), r)
}
func ValidateKeyPair(p *Params, priv, pub []byte) error {
	return native.BignValidatePair(params(p), priv, pub)
}
func ValidatePublicKey(p *Params, pub []byte) error    { return native.BignValidatePublic(params(p), pub) }
func PublicKey(p *Params, priv []byte) ([]byte, error) { return native.BignPublic(params(p), priv) }
func DH(p *Params, priv, pub []byte, n int) ([]byte, error) {
	return native.BignDH(params(p), priv, pub, n)
}
func SignDigest(p *Params, oid, digest, priv []byte, r io.Reader) ([]byte, error) {
	return native.BignSign(params(p), oid, digest, priv, r)
}
func SignDigestDeterministic(p *Params, oid, digest, priv, t []byte) ([]byte, error) {
	return native.BignSign2(params(p), oid, digest, priv, t)
}
func VerifyDigest(p *Params, oid, digest, sig, pub []byte) error {
	return native.BignVerify(params(p), oid, digest, sig, pub)
}
func WrapKey(p *Params, key, header, pub []byte, r io.Reader) ([]byte, error) {
	return native.BignWrap(params(p), key, header, pub, r)
}
func UnwrapKey(p *Params, token, header, priv []byte) ([]byte, error) {
	return native.BignUnwrap(params(p), token, header, priv)
}

type CurveCandidate struct {
	Level   int
	P, A, B []byte
	Seed    [8]byte
}
type ParamsSeed struct {
	Level int
	P, A  []byte
	Seed  [8]byte
}
type OrderCalculator func(CurveCandidate) ([]byte, error)
type SeedObserver func(CurveCandidate) error

// GenerateParams requires an external curve-order calculator. ErrNoResult asks
// bee2 to try the next seed; any other error aborts. Callbacks are synchronous.
func GenerateParams(seed ParamsSeed, calc OrderCalculator, onSeed SeedObserver) (*Params, error) {
	if calc == nil {
		return nil, bee2.ErrInvalidInput
	}
	convert := func(c native.BignCandidate) CurveCandidate {
		return CurveCandidate{Level: c.Level, P: c.P, A: c.A, B: c.B, Seed: c.Seed}
	}
	compute := func(c native.BignCandidate) ([]byte, error) {
		q, e := calc(convert(c))
		if errors.Is(e, ErrNoResult) {
			e = native.ErrNoOrder
		}
		return q, e
	}
	var observe func(native.BignCandidate) error
	if onSeed != nil {
		observe = func(c native.BignCandidate) error { return onSeed(convert(c)) }
	}
	n, e := native.BignGenerateParams(native.BignSeed{Level: seed.Level, P: seed.P, A: seed.A, Seed: seed.Seed}, compute, observe)
	if e != nil {
		return nil, e
	}
	return &Params{n}, nil
}
