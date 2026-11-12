// Package bash implements the BASH hash and programmable sponge.
package bash

import "github.com/miniusercoder/bee2go/v3/internal/native"

// HashState is a BASH hash. Close releases its native state.
type HashState struct{ n *native.BashHash }

func NewHash(level int) (*HashState, error) {
	h, e := native.NewBashHash(level)
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
func Hash(level int, src []byte) ([]byte, error) {
	h, e := NewHash(level)
	if e != nil {
		return nil, e
	}
	defer h.Close()
	h.Write(src)
	return h.Sum(nil), nil
}
