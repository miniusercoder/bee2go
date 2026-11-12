// Package belt implements the BELT cryptographic algorithms.
package belt

import "github.com/miniusercoder/bee2go/v3/internal/native"

// HashState is a BELT hash. Close releases its native state.
type HashState struct{ n *native.BeltHash }

func NewHash() (*HashState, error) {
	h, e := native.NewBeltHash()
	if e != nil {
		return nil, e
	}
	return &HashState{h}, nil
}
func (h *HashState) Write(p []byte) (int, error) { return h.n.Write(p) }
func (h *HashState) Sum(b []byte) []byte         { return h.n.Sum(b) }
func (h *HashState) Reset()                      { h.n.Reset() }
func (h *HashState) Size() int                   { return h.n.Size() }
func (h *HashState) BlockSize() int              { return h.n.BlockSize() }
func (h *HashState) Close() error {
	if h == nil {
		return nil
	}
	return h.n.Close()
}
func Hash(src []byte) ([]byte, error) {
	h, e := NewHash()
	if e != nil {
		return nil, e
	}
	defer h.Close()
	h.Write(src)
	return h.Sum(nil), nil
}
