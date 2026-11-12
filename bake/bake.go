// Package bake implements BMQV, BSTS and BPACE message protocols. Sessions own
// their parameters, entropy state and certificate data. Close every session.
package bake

import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/bign"
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"io"
)

type Role int

const (
	RoleA Role = 1
	RoleB Role = 2
)

type Settings struct {
	ConfirmA, ConfirmB bool
	HelloA, HelloB     []byte
	Entropy            io.Reader
}
type CertValidator func(paramsDER, cert []byte) (publicKey []byte, err error)
type Certificate struct {
	Data     []byte
	Validate CertValidator
}
type session struct {
	n                  *native.BakeSession
	role               Role
	confirmA, confirmB bool
}

func (s *session) Close() error {
	if s == nil {
		return nil
	}
	return s.n.Close()
}
func (s *session) Key() ([]byte, error) { return s.n.Key() }
func newSession(kind int, p *bign.Params, role Role, settings Settings, secret []byte, cert Certificate) (*session, error) {
	if p == nil {
		return nil, bee2.ErrInvalidInput
	}
	der, e := p.DER()
	if e != nil {
		return nil, e
	}
	n, e := native.NewBakeSession(kind, int(role), der, native.BakeSettings{ConfirmA: settings.ConfirmA, ConfirmB: settings.ConfirmB, HelloA: settings.HelloA, HelloB: settings.HelloB, Entropy: settings.Entropy}, secret, cert.Data, native.CertificateValidator(cert.Validate))
	if e != nil {
		return nil, e
	}
	return &session{n, role, settings.ConfirmA, settings.ConfirmB}, nil
}

type BSTS struct{ *session }

func NewBSTS(p *bign.Params, role Role, settings Settings, private []byte, cert Certificate) (*BSTS, error) {
	s, e := newSession(2, p, role, settings, private, cert)
	if e != nil {
		return nil, e
	}
	return &BSTS{s}, nil
}
func (s *BSTS) Step2() ([]byte, error)          { return s.n.Step(2, nil, nil, nil) }
func (s *BSTS) Step3(in []byte) ([]byte, error) { return s.n.Step(3, in, nil, nil) }
func (s *BSTS) Step4(in []byte, v CertValidator) ([]byte, error) {
	return s.n.Step(4, in, nil, native.CertificateValidator(v))
}
func (s *BSTS) Step5(in []byte, v CertValidator) error {
	_, e := s.n.Step(5, in, nil, native.CertificateValidator(v))
	return e
}

type BMQV struct{ *session }

func NewBMQV(p *bign.Params, role Role, settings Settings, private []byte, cert Certificate) (*BMQV, error) {
	s, e := newSession(1, p, role, settings, private, cert)
	if e != nil {
		return nil, e
	}
	return &BMQV{s}, nil
}
func (s *BMQV) Step2() ([]byte, error) { return s.n.Step(2, nil, nil, nil) }
func (s *BMQV) Step3(in []byte, peer Certificate) ([]byte, error) {
	return s.n.Step(3, in, peer.Data, native.CertificateValidator(peer.Validate))
}
func (s *BMQV) Step4(in []byte, peer Certificate) ([]byte, error) {
	return s.n.Step(4, in, peer.Data, native.CertificateValidator(peer.Validate))
}
func (s *BMQV) Step5(in []byte) error { _, e := s.n.Step(5, in, nil, nil); return e }

type BPACE struct{ *session }

func NewBPACE(p *bign.Params, role Role, settings Settings, password []byte) (*BPACE, error) {
	s, e := newSession(3, p, role, settings, password, Certificate{})
	if e != nil {
		return nil, e
	}
	return &BPACE{s}, nil
}
func (s *BPACE) Step2() ([]byte, error)              { return s.n.Step(2, nil, nil, nil) }
func (s *BPACE) Step3(in []byte) ([]byte, error)     { return s.n.Step(3, in, nil, nil) }
func (s *BPACE) Step4(in []byte) ([]byte, error)     { return s.n.Step(4, in, nil, nil) }
func (s *BPACE) Step5(in []byte) ([]byte, error)     { return s.n.Step(5, in, nil, nil) }
func (s *BPACE) Step6(in []byte) error               { _, e := s.n.Step(6, in, nil, nil); return e }
func KDF(secret, iv []byte, num int) ([]byte, error) { return native.BakeKDF(secret, iv, num) }
func SWU(p *bign.Params, msg []byte) ([]byte, error) {
	if p == nil {
		return nil, bee2.ErrInvalidInput
	}
	der, e := p.DER()
	if e != nil {
		return nil, e
	}
	return native.BakeSWU(der, msg)
}
func DH(p *bign.Params, private, public []byte, n int) ([]byte, error) {
	return bign.DH(p, private, public, n)
}
