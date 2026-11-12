package native

/*
#include "bign_generate.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"runtime/cgo"
	"unsafe"
)

type BignCandidate struct {
	Level   int
	P, A, B []byte
	Seed    [8]byte
}
type BignSeed struct {
	Level int
	P, A  []byte
	Seed  [8]byte
}

var ErrNoOrder = errors.New("bign: no order")

type bignGeneration struct {
	calc    func(BignCandidate) ([]byte, error)
	observe func(BignCandidate) error
	err     error
}

func bignCandidate(p *C.bign_params) BignCandidate {
	n := int(p.l) / 4
	c := BignCandidate{Level: int(p.l), P: C.GoBytes(unsafe.Pointer(&p.p[0]), C.int(n)), A: C.GoBytes(unsafe.Pointer(&p.a[0]), C.int(n)), B: C.GoBytes(unsafe.Pointer(&p.b[0]), C.int(n))}
	for i := range c.Seed {
		c.Seed[i] = byte(p.seed[i])
	}
	return c
}

//export bee2go_bign_order
func bee2go_bign_order(p *C.bign_params, h C.uintptr_t) (rc C.err_t) {
	g := cgo.Handle(h).Value().(*bignGeneration)
	defer func() {
		if recover() != nil {
			g.err = fmt.Errorf("bign: order calculator panicked")
			rc = 109
		}
	}()
	q, e := g.calc(bignCandidate(p))
	if errors.Is(e, ErrNoOrder) {
		return 118
	}
	if e != nil {
		g.err = e
		return 109
	}
	if len(q) != int(p.l)/4 {
		g.err = invalid("bign.order.length")
		return 109
	}
	for i := range q {
		p.q[i] = C.octet(q[i])
	}
	return 0
}

//export bee2go_bign_seed
func bee2go_bign_seed(p *C.bign_params, h C.uintptr_t) (rc C.err_t) {
	g := cgo.Handle(h).Value().(*bignGeneration)
	defer func() {
		if recover() != nil {
			g.err = fmt.Errorf("bign: seed observer panicked")
			rc = 109
		}
	}()
	if g.observe != nil {
		if e := g.observe(bignCandidate(p)); e != nil {
			g.err = e
			return 109
		}
	}
	return 0
}
func BignGenerateParams(seed BignSeed, calc func(BignCandidate) ([]byte, error), observe func(BignCandidate) error) (*BignParams, error) {
	if calc == nil || (seed.Level != 128 && seed.Level != 192 && seed.Level != 256) || len(seed.P) != seed.Level/4 || len(seed.A) != seed.Level/4 {
		return nil, invalid("bign.generateParams")
	}
	p, e := newBignParams()
	if e != nil {
		return nil, e
	}
	p.level = seed.Level
	p.c().l = C.size_t(seed.Level)
	for i := range seed.P {
		p.c().p[i] = C.octet(seed.P[i])
		p.c().a[i] = C.octet(seed.A[i])
	}
	for i := range seed.Seed {
		p.c().seed[i] = C.octet(seed.Seed[i])
	}
	g := &bignGeneration{calc: calc, observe: observe}
	h := cgo.NewHandle(g)
	defer h.Delete()
	rc := C.bee2go_bign_generate(p.c(), C.uintptr_t(h))
	if g.err != nil {
		p.Close()
		return nil, g.err
	}
	if e = codeErr("bign.generateParams", rc); e != nil {
		p.Close()
		return nil, e
	}
	return p, nil
}
