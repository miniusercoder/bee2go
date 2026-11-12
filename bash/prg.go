package bash

import "github.com/miniusercoder/bee2go/v3/internal/native"

// PRG is a programmable BASH sponge. It is not safe for concurrent use.
type PRG struct{ n *native.BashPRG }

func NewPRG(level, capacity int, ann, key []byte) (*PRG, error) {
	p, e := native.NewBashPRG(level, capacity, ann, key)
	if e != nil {
		return nil, e
	}
	return &PRG{p}, nil
}
func (p *PRG) Restart(ann, key []byte) error { return p.n.Restart(ann, key) }
func (p *PRG) Ratchet() error                { return p.n.Ratchet() }
func (p *PRG) Close() error {
	if p == nil {
		return nil
	}
	return p.n.Close()
}
func (p *PRG) AbsorbStart() error        { return p.n.Start(1) }
func (p *PRG) AbsorbStep(b []byte) error { return p.n.Step(1, b) }
func (p *PRG) Absorb(b []byte) error {
	if e := p.AbsorbStart(); e != nil {
		return e
	}
	return p.AbsorbStep(b)
}
func (p *PRG) SqueezeStart() error        { return p.n.Start(2) }
func (p *PRG) SqueezeStep(b []byte) error { return p.n.Step(2, b) }
func (p *PRG) Squeeze(b []byte) error {
	if e := p.SqueezeStart(); e != nil {
		return e
	}
	return p.SqueezeStep(b)
}
func (p *PRG) EncryptStart() error        { return p.n.Start(3) }
func (p *PRG) EncryptStep(b []byte) error { return p.n.Step(3, b) }
func (p *PRG) Encrypt(b []byte) error {
	if e := p.EncryptStart(); e != nil {
		return e
	}
	return p.EncryptStep(b)
}
func (p *PRG) DecryptStart() error        { return p.n.Start(4) }
func (p *PRG) DecryptStep(b []byte) error { return p.n.Step(4, b) }
func (p *PRG) Decrypt(b []byte) error {
	if e := p.DecryptStart(); e != nil {
		return e
	}
	return p.DecryptStep(b)
}
