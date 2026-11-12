package native

import (
	"crypto/rand"
	"fmt"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"io"
)

// Random is an operation-owned, seeded native generator. Reader input is seed
// material, not a promise to reproduce that reader's byte stream in C.
type Random struct{ *CTR }

func NewRandom(entropy io.Reader) (*Random, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	var seed [64]byte
	defer Wipe(seed[:])
	if _, e := io.ReadFull(entropy, seed[:]); e != nil {
		return nil, fmt.Errorf("%w: %w", bee2.ErrRandom, e)
	}
	ctr, e := NewCTR(seed[:32], seed[32:])
	if e != nil {
		return nil, e
	}
	return &Random{ctr}, nil
}
