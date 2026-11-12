package native

/*
#include "bake_bridge.h"
*/
import "C"
import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"io"
	"unsafe"
)

type BakeSettings struct {
	ConfirmA, ConfirmB bool
	HelloA, HelloB     []byte
	Entropy            io.Reader
}
type BakeSession struct {
	s, settings, helloA, helloB       *state
	random                            *Random
	params                            *BignParams
	cert                              *nativeCertificate
	peers                             []*nativeCertificate
	kind, role, level, next           int
	confirmA, confirmB, ready, failed bool
	busy                              bool
	certLen                           int
}

func (s *BakeSession) Close() error {
	if s != nil && s.busy {
		return bee2.ErrState
	}
	if s == nil {
		return nil
	}
	s.s.Close()
	s.settings.Close()
	s.helloA.Close()
	s.helloB.Close()
	if s.random != nil {
		s.random.Close()
	}
	s.params.Close()
	s.cert.Close()
	for _, c := range s.peers {
		c.Close()
	}
	s.peers = nil
	return nil
}
func copyState(b []byte) (*state, error) {
	if len(b) == 0 {
		return nil, nil
	}
	s, e := newState(uintptr(len(b)))
	if e != nil {
		return nil, e
	}
	C.memcpy(s.ptr, pointer(b), C.size_t(len(b)))
	return s, nil
}
func statePointer(s *state) unsafe.Pointer {
	if s == nil {
		return nil
	}
	return s.ptr
}
func NewBakeSession(kind, role int, der []byte, settings BakeSettings, secret, cert []byte, validator CertificateValidator) (s *BakeSession, err error) {
	if kind < 1 || kind > 5 || (role != 1 && role != 2) || (kind == 2 && (!settings.ConfirmA || !settings.ConfirmB)) || (kind >= 4 && !settings.ConfirmA) || (kind != 3 && validator == nil) {
		return nil, invalid("bake.settings")
	}
	p, e := BignFromDER(der)
	if e != nil {
		return nil, e
	}
	s = &BakeSession{params: p, kind: kind, role: role, level: p.level, confirmA: settings.ConfirmA, confirmB: settings.ConfirmB, certLen: len(cert)}
	defer func() {
		if err != nil {
			s.Close()
			s = nil
		}
	}()
	if kind != 3 && len(secret) != p.level/4 {
		return s, invalid("bake.privateKey")
	}
	s.random, err = NewRandom(settings.Entropy)
	if err != nil {
		return s, err
	}
	s.settings, err = newState(uintptr(C.sizeof_bake_settings))
	if err != nil {
		return s, err
	}
	st := (*C.bake_settings)(s.settings.ptr)
	if settings.ConfirmA {
		st.kca = 1
	}
	if settings.ConfirmB {
		st.kcb = 1
	}
	st.rng = (C.gen_i)(C.bee2go_random)
	st.rng_state = s.random.CTR.s.ptr
	s.helloA, err = copyState(settings.HelloA)
	if err != nil {
		return s, err
	}
	s.helloB, err = copyState(settings.HelloB)
	if err != nil {
		return s, err
	}
	st.helloa = statePointer(s.helloA)
	st.helloa_len = C.size_t(len(settings.HelloA))
	st.hellob = statePointer(s.helloB)
	st.hellob_len = C.size_t(len(settings.HelloB))
	var n C.size_t
	switch kind {
	case 1:
		n = C.bakeBMQV_keep(C.size_t(p.level))
	case 2:
		n = C.bakeBSTS_keep(C.size_t(p.level))
	case 3:
		n = C.bakeBPACE_keep(C.size_t(p.level))
	case 4:
		n = C.btokBAuthCT_keep(C.size_t(p.level))
	case 5:
		n = C.btokBAuthT_keep(C.size_t(p.level))
	}
	s.s, err = newState(uintptr(n))
	if err != nil {
		return s, err
	}
	if kind != 3 {
		s.cert, err = newCertificate(cert)
		if err != nil {
			return s, err
		}
	}
	err = certificateCall(validator, func(h C.uintptr_t) C.err_t {
		return C.bee2go_bake_start(C.int(kind), s.s.ptr, p.c(), st, octets(secret), C.size_t(len(secret)), s.cert.c(), h)
	})
	if err != nil {
		return s, err
	}
	if role == 2 {
		s.next = 2
	} else {
		s.next = 3
	}
	return s, nil
}
func (s *BakeSession) Step(step int, in, peerCert []byte, v CertificateValidator) ([]byte, error) {
	if s == nil {
		return nil, bee2.ErrClosed
	}
	if e := s.s.check(); e != nil {
		return nil, e
	}
	if s.busy {
		return nil, bee2.ErrState
	}
	if s.failed || s.next != step {
		s.failed = true
		return nil, bee2.ErrState
	}
	input, output := -1, 0
	next := 0
	l := s.level
	switch s.kind {
	case 1:
		switch step {
		case 2:
			input = 0
			output = l / 2
			next = 4
		case 3:
			input = l / 2
			output = l / 2
			if s.confirmA {
				output += 8
			}
			if s.confirmB {
				next = 5
			}
		case 4:
			input = l / 2
			if s.confirmA {
				input += 8
			}
			if s.confirmB {
				output = 8
			}
		case 5:
			input = 8
		}
	case 2:
		switch step {
		case 2:
			input = 0
			output = l / 2
			next = 4
		case 3:
			input = l / 2
			output = 3*l/4 + s.certLen + 8
			next = 5
		case 4:
			if len(in) >= 3*l/4+8 {
				input = len(in)
			}
			output = l/4 + s.certLen + 8
		case 5:
			if len(in) >= l/4+8 {
				input = len(in)
			}
		}
	case 3:
		switch step {
		case 2:
			input = 0
			output = l / 8
			next = 4
		case 3:
			input = l / 8
			output = 5 * l / 8
			next = 5
		case 4:
			input = 5 * l / 8
			output = l / 2
			if s.confirmB {
				output += 8
			}
			if s.confirmA {
				next = 6
			}
		case 5:
			input = l / 2
			if s.confirmB {
				input += 8
			}
			if s.confirmA {
				output = 8
			}
		case 6:
			input = 8
		}
	case 4:
		switch step {
		case 2:
			input = 0
			output = 5*l/8 + 16
			next = 4
		case 4:
			input = 8
			if s.confirmB {
				input += 16
				output = l/4 + s.certLen + 8
			}
		}
	case 5:
		switch step {
		case 3:
			input = 5*l/8 + 16
			output = 8
			if s.confirmB {
				output += 16
				next = 5
			}
		case 5:
			if len(in) >= l/4+8 {
				input = len(in)
			}
		}
	}
	if input < 0 || len(in) != input {
		s.failed = true
		return nil, invalid("bake.message")
	}
	var peer *nativeCertificate
	var err error
	if (s.kind == 1 && (step == 3 || step == 4)) || (s.kind == 4 && step == 2) {
		if v == nil {
			s.failed = true
			return nil, invalid("bake.validator")
		}
		peer, err = newCertificate(peerCert)
		if err != nil {
			s.failed = true
			return nil, err
		}
		s.peers = append(s.peers, peer)
	}
	if ((s.kind == 2 && (step == 4 || step == 5)) || (s.kind == 5 && step == 5)) && v == nil {
		s.failed = true
		return nil, invalid("bake.validator")
	}

	out := make([]byte, output)
	s.busy = true
	defer func() { s.busy = false }()
	err = certificateCall(v, func(h C.uintptr_t) C.err_t {
		return C.bee2go_bake_step(C.int(s.kind), C.int(step), octets(out), octets(in), C.size_t(len(in)), peer.c(), s.s.ptr, h)
	})
	if err != nil {
		s.failed = true
		Wipe(out)
		return nil, err
	}
	s.next = next
	s.ready = next == 0
	return out, nil
}
func (s *BakeSession) Key() ([]byte, error) {
	if s == nil {
		return nil, bee2.ErrClosed
	}
	if e := s.s.check(); e != nil {
		return nil, e
	}
	if s.busy || s.failed || !s.ready {
		return nil, bee2.ErrState
	}
	out := make([]byte, 32)
	e := codeErr("bake.key", C.bee2go_bake_step(C.int(s.kind), 7, octets(out), nil, 0, nil, s.s.ptr, 0))
	if e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BakeKDF(secret, iv []byte, num int) ([]byte, error) {
	if num < 0 {
		return nil, invalid("bake.kdf")
	}
	out := make([]byte, 32)
	if e := codeErr("bake.kdf", C.bakeKDF(octets(out), octets(secret), C.size_t(len(secret)), octets(iv), C.size_t(len(iv)), C.size_t(num))); e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BakeSWU(der, msg []byte) ([]byte, error) {
	p, e := BignFromDER(der)
	if e != nil {
		return nil, e
	}
	defer p.Close()
	if len(msg) != p.level/4 {
		return nil, invalid("bake.swu")
	}
	out := make([]byte, p.level/2)
	if e = codeErr("bake.swu", C.bakeSWU(octets(out), p.c(), octets(msg))); e != nil {
		return nil, e
	}
	return out, nil
}
