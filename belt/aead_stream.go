package belt

import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/internal/native"
)

// AuthenticatedStream buffers input until Seal or Open. limit bounds the total
// buffered payload and associated data. Refresh must use a fresh IV.
type AuthenticatedStream struct {
	key, iv, data, aad      []byte
	limit                   int
	che, open, done, closed bool
}

func NewAuthenticatedStream(che, open bool, key, iv []byte, limit int) (*AuthenticatedStream, error) {
	if (len(key) != 16 && len(key) != 24 && len(key) != 32) || len(iv) != 16 || limit < 0 {
		return nil, bee2.ErrInvalidInput
	}
	return &AuthenticatedStream{key: append([]byte(nil), key...), iv: append([]byte(nil), iv...), limit: limit, che: che, open: open}, nil
}
func (s *AuthenticatedStream) add(dst *[]byte, b []byte) error {
	if s.closed {
		return bee2.ErrClosed
	}
	if s.done {
		return bee2.ErrState
	}
	if len(b) > s.limit-len(s.data)-len(s.aad) {
		return bee2.ErrInvalidInput
	}
	// ponytail: exact-size copies make many tiny fragments quadratic; add bounded growth if throughput matters.
	p := make([]byte, len(*dst)+len(b))
	copy(p, *dst)
	copy(p[len(*dst):], b)
	native.Wipe(*dst)
	*dst = p
	return nil
}
func (s *AuthenticatedStream) AddAAD(b []byte) error { return s.add(&s.aad, b) }
func (s *AuthenticatedStream) Update(b []byte) error { return s.add(&s.data, b) }
func (s *AuthenticatedStream) Seal() ([]byte, []byte, error) {
	if s.closed {
		return nil, nil, bee2.ErrClosed
	}
	if s.done || s.open {
		return nil, nil, bee2.ErrState
	}
	s.done = true
	return native.BeltAEAD(s.che, false, s.data, s.aad, nil, s.key, s.iv)
}
func (s *AuthenticatedStream) Open(tag []byte) ([]byte, error) {
	if s.closed {
		return nil, bee2.ErrClosed
	}
	if s.done || !s.open {
		return nil, bee2.ErrState
	}
	s.done = true
	out, _, e := native.BeltAEAD(s.che, true, s.data, s.aad, tag, s.key, s.iv)
	return out, e
}
func (s *AuthenticatedStream) Refresh(iv []byte) error {
	if s.closed {
		return bee2.ErrClosed
	}
	if len(iv) != 16 {
		return bee2.ErrInvalidInput
	}
	copy(s.iv, iv)
	native.Wipe(s.data)
	native.Wipe(s.aad)
	s.data = nil
	s.aad = nil
	s.done = false
	return nil
}
func (s *AuthenticatedStream) Close() error {
	if s == nil || s.closed {
		return nil
	}
	native.Wipe(s.key)
	native.Wipe(s.iv)
	native.Wipe(s.data)
	native.Wipe(s.aad)
	s.key = nil
	s.iv = nil
	s.data = nil
	s.aad = nil
	s.closed = true
	return nil
}
