package belt

import "github.com/miniusercoder/bee2go/v3/internal/native"

type SDEState struct{ n *native.BeltSDE }

func NewSDE(key []byte) (*SDEState, error) {
	s, e := native.NewBeltSDE(key)
	if e != nil {
		return nil, e
	}
	return &SDEState{s}, nil
}
func (s *SDEState) Encrypt(b, iv []byte) error { return s.n.Crypt(b, iv, false) }
func (s *SDEState) Decrypt(b, iv []byte) error { return s.n.Crypt(b, iv, true) }
func (s *SDEState) Close() error {
	if s == nil {
		return nil
	}
	return s.n.Close()
}

type FMTState struct{ n *native.BeltFMTState }

func NewFMT(mod uint32, count int, key []byte) (*FMTState, error) {
	s, e := native.NewBeltFMT(mod, count, key)
	if e != nil {
		return nil, e
	}
	return &FMTState{s}, nil
}
func (s *FMTState) Encrypt(b []uint16, iv []byte) error { return s.n.Crypt(b, iv, false) }
func (s *FMTState) Decrypt(b []uint16, iv []byte) error { return s.n.Crypt(b, iv, true) }
func (s *FMTState) Close() error {
	if s == nil {
		return nil
	}
	return s.n.Close()
}

type KRPState struct{ n *native.BeltKRPState }

func NewKRP(key, level []byte) (*KRPState, error) {
	s, e := native.NewBeltKRP(key, level)
	if e != nil {
		return nil, e
	}
	return &KRPState{s}, nil
}
func (s *KRPState) Derive(n int, header []byte) ([]byte, error) { return s.n.Derive(n, header) }
func (s *KRPState) Close() error {
	if s == nil {
		return nil
	}
	return s.n.Close()
}
