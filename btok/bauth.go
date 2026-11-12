package btok

import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/bake"
	"github.com/miniusercoder/bee2go/v3/bign"
	"github.com/miniusercoder/bee2go/v3/internal/native"
)

type BAuthTerminal struct{ n *native.BakeSession }
type BAuthToken struct{ n *native.BakeSession }

func newBAuth(kind, role int, p *bign.Params, s bake.Settings, private []byte, c bake.Certificate) (*native.BakeSession, error) {
	if p == nil {
		return nil, bee2.ErrInvalidInput
	}
	der, e := p.DER()
	if e != nil {
		return nil, e
	}
	return native.NewBakeSession(kind, role, der, native.BakeSettings{ConfirmA: s.ConfirmA, ConfirmB: s.ConfirmB, HelloA: s.HelloA, HelloB: s.HelloB, Entropy: s.Entropy}, private, c.Data, native.CertificateValidator(c.Validate))
}
func NewBAuthTerminal(p *bign.Params, s bake.Settings, private []byte, c bake.Certificate) (*BAuthTerminal, error) {
	n, e := newBAuth(5, 1, p, s, private, c)
	if e != nil {
		return nil, e
	}
	return &BAuthTerminal{n}, nil
}
func NewBAuthToken(p *bign.Params, s bake.Settings, private []byte, c bake.Certificate) (*BAuthToken, error) {
	n, e := newBAuth(4, 2, p, s, private, c)
	if e != nil {
		return nil, e
	}
	return &BAuthToken{n}, nil
}
func (s *BAuthTerminal) Step3(in []byte) ([]byte, error) { return s.n.Step(3, in, nil, nil) }
func (s *BAuthTerminal) Step5(in []byte, v bake.CertValidator) error {
	_, e := s.n.Step(5, in, nil, native.CertificateValidator(v))
	return e
}
func (s *BAuthTerminal) Key() ([]byte, error) { return s.n.Key() }
func (s *BAuthTerminal) Close() error {
	if s != nil {
		return s.n.Close()
	}
	return nil
}
func (s *BAuthToken) Step2(c bake.Certificate) ([]byte, error) {
	return s.n.Step(2, nil, c.Data, native.CertificateValidator(c.Validate))
}
func (s *BAuthToken) Step4(in []byte) ([]byte, error) { return s.n.Step(4, in, nil, nil) }
func (s *BAuthToken) Key() ([]byte, error)            { return s.n.Key() }
func (s *BAuthToken) Close() error {
	if s != nil {
		return s.n.Close()
	}
	return nil
}
