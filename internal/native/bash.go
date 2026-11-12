package native

/*
#include "bridge.h"
#include <bee2/crypto/bash.h>
*/
import "C"
import bee2 "github.com/miniusercoder/bee2go/v3"

type BashHash struct {
	s     *state
	level int
}

func NewBashHash(level int) (*BashHash, error) {
	if level <= 0 || level > 256 || level%16 != 0 {
		return nil, invalid("bash.NewHash")
	}
	s, e := newState(uintptr(C.bashHash_keep()))
	if e != nil {
		return nil, e
	}
	C.bashHashStart(s.ptr, C.size_t(level))
	return &BashHash{s, level}, nil
}
func (h *BashHash) Write(p []byte) (int, error) {
	if e := h.s.check(); e != nil {
		return 0, e
	}
	if len(p) > 0 {
		C.bashHashStepH(pointer(p), C.size_t(len(p)), h.s.ptr)
	}
	return len(p), nil
}
func (h *BashHash) Sum(b []byte) []byte {
	if e := h.s.check(); e != nil {
		panic(e)
	}
	out := make([]byte, h.level/4)
	C.bashHashStepG(octets(out), C.size_t(len(out)), h.s.ptr)
	return append(b, out...)
}
func (h *BashHash) Reset() {
	if e := h.s.check(); e != nil {
		panic(e)
	}
	C.memWipe(h.s.ptr, C.size_t(h.s.size))
	C.bashHashStart(h.s.ptr, C.size_t(h.level))
}
func (h *BashHash) Size() int {
	if e := h.s.check(); e != nil {
		panic(e)
	}
	return h.level / 4
}
func (h *BashHash) BlockSize() int {
	if e := h.s.check(); e != nil {
		panic(e)
	}
	return 192 - h.level/2
}
func (h *BashHash) Close() error {
	if h == nil {
		return nil
	}
	return h.s.Close()
}

type BashPRG struct {
	s            *state
	level, phase int
	keyed        bool
}

func bashParams(level int, ann, key []byte) bool {
	return len(ann) <= 60 && len(ann)%4 == 0 && len(key) <= 60 && len(key)%4 == 0 && (len(key) == 0 || len(key) >= level/8)
}
func NewBashPRG(level, capacity int, ann, key []byte) (*BashPRG, error) {
	if (level != 128 && level != 192 && level != 256) || (capacity != 1 && capacity != 2) || !bashParams(level, ann, key) {
		return nil, invalid("bash.NewPRG")
	}
	s, e := newState(uintptr(C.bashPrg_keep()))
	if e != nil {
		return nil, e
	}
	C.bashPrgStart(s.ptr, C.size_t(level), C.size_t(capacity), octets(ann), C.size_t(len(ann)), octets(key), C.size_t(len(key)))
	return &BashPRG{s: s, level: level, keyed: len(key) > 0}, nil
}
func (p *BashPRG) Restart(ann, key []byte) error {
	if e := p.s.check(); e != nil {
		return e
	}
	if !bashParams(p.level, ann, key) {
		return invalid("bash.PRG.Restart")
	}
	C.bashPrgRestart(octets(ann), C.size_t(len(ann)), octets(key), C.size_t(len(key)), p.s.ptr)
	p.keyed = p.keyed || len(key) > 0
	p.phase = 0
	return nil
}
func (p *BashPRG) Start(phase int) error {
	if e := p.s.check(); e != nil {
		return e
	}
	if (phase == 3 || phase == 4) && !p.keyed {
		return bee2.ErrState
	}
	switch phase {
	case 1:
		C.bashPrgAbsorbStart(p.s.ptr)
	case 2:
		C.bashPrgSqueezeStart(p.s.ptr)
	case 3:
		C.bashPrgEncrStart(p.s.ptr)
	case 4:
		C.bashPrgDecrStart(p.s.ptr)
	default:
		return invalid("bash.PRG.Start")
	}
	p.phase = phase
	return nil
}
func (p *BashPRG) Step(phase int, b []byte) error {
	if e := p.s.check(); e != nil {
		return e
	}
	if p.phase != phase {
		return bee2.ErrState
	}
	switch phase {
	case 1:
		C.bashPrgAbsorbStep(pointer(b), C.size_t(len(b)), p.s.ptr)
	case 2:
		C.bashPrgSqueezeStep(pointer(b), C.size_t(len(b)), p.s.ptr)
	case 3:
		C.bashPrgEncrStep(pointer(b), C.size_t(len(b)), p.s.ptr)
	case 4:
		C.bashPrgDecrStep(pointer(b), C.size_t(len(b)), p.s.ptr)
	}
	return nil
}
func (p *BashPRG) Ratchet() error {
	if e := p.s.check(); e != nil {
		return e
	}
	C.bashPrgRatchet(p.s.ptr)
	p.phase = 0
	return nil
}
func (p *BashPRG) Close() error {
	if p == nil {
		return nil
	}
	return p.s.Close()
}
