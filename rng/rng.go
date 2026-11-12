// Package rng provides owned access to bee2's global generator and entropy
// diagnostics. Diagnostics are not a certification of generated data.
package rng

import (
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"io"
)

type Generator struct{ n *native.RNG }

func New() (*Generator, error) {
	n, e := native.NewRNG()
	if e != nil {
		return nil, e
	}
	return &Generator{n}, nil
}
func (g *Generator) Read(b []byte) (int, error)              { return g.n.Read(b) }
func (g *Generator) ReadWithoutReseed(b []byte) (int, error) { return g.n.ReadWithoutReseed(b) }
func (g *Generator) Rekey() error                            { return g.n.Rekey() }
func (g *Generator) Close() error {
	if g != nil {
		return g.n.Close()
	}
	return nil
}
func ReadEntropy(b []byte, source string) (int, error) { return native.RNGReadEntropy(b, source) }
func TestSource(source string) error                   { return native.RNGTestSource(source) }
func Health() error                                    { return native.RNGHealth(false) }
func Health2() error                                   { return native.RNGHealth(true) }
func TestFIPS1(b []byte) bool                          { return native.RNGFIPS(1, b) }
func TestFIPS2(b []byte) bool                          { return native.RNGFIPS(2, b) }
func TestFIPS3(b []byte) bool                          { return native.RNGFIPS(3, b) }
func TestFIPS4(b []byte) bool                          { return native.RNGFIPS(4, b) }

// NewWithSource adds a caller-supplied 32-byte entropy contribution to bee2's
// standard sources. A short read fails before changing the global generator.
// A nil source behaves like New.
func NewWithSource(source io.Reader) (*Generator, error) {
	n, e := native.NewRNGWithSource(source)
	if e != nil {
		return nil, e
	}
	return &Generator{n}, nil
}

// IsCreated reports whether any owned reference keeps bee2's generator alive.
func IsCreated() bool { return native.RNGIsCreated() }
