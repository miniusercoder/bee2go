package native

/*
#include "bridge.h"
*/
import "C"

type CTR struct{ s *state }

func NewCTR(key, iv []byte) (*CTR, error) {
	if len(key) != 32 || (len(iv) != 0 && len(iv) != 32) {
		return nil, invalid("brng.CTR")
	}
	s, e := newState(uintptr(C.brngCTR_keep()))
	if e != nil {
		return nil, e
	}
	C.brngCTRStart(s.ptr, octets(key), octets(iv))
	return &CTR{s}, nil
}
func (r *CTR) Read(b []byte) (int, error) {
	if r == nil {
		return 0, invalid("brng.CTR")
	}
	if e := r.s.check(); e != nil {
		return 0, e
	}
	clear(b)
	C.brngCTRStepR(pointer(b), C.size_t(len(b)), r.s.ptr)
	return len(b), nil
}

// Transform uses the original bytes as additional material, as upstream does.
func (r *CTR) Transform(b []byte) error {
	if r == nil {
		return invalid("brng.CTR")
	}
	if e := r.s.check(); e != nil {
		return e
	}
	C.brngCTRStepR(pointer(b), C.size_t(len(b)), r.s.ptr)
	return nil
}
func (r *CTR) IV() ([]byte, error) {
	if e := r.s.check(); e != nil {
		return nil, e
	}
	v := make([]byte, 32)
	C.brngCTRStepG(octets(v), r.s.ptr)
	return v, nil
}
func (r *CTR) Close() error {
	if r != nil {
		return r.s.Close()
	}
	return nil
}

type HMAC struct{ s, iv *state }

func NewHMAC(key, iv []byte) (*HMAC, error) {
	s, e := newState(uintptr(C.brngHMAC_keep()))
	if e != nil {
		return nil, e
	}
	var owned *state
	if len(iv) > 0 {
		owned, e = newState(uintptr(len(iv)))
		if e != nil {
			s.Close()
			return nil, e
		}
		C.memcpy(owned.ptr, pointer(iv), C.size_t(len(iv)))
	}
	var ivp *C.octet
	if owned != nil {
		ivp = (*C.octet)(owned.ptr)
	}
	C.brngHMACStart(s.ptr, octets(key), C.size_t(len(key)), ivp, C.size_t(len(iv)))
	return &HMAC{s, owned}, nil
}
func (r *HMAC) Read(b []byte) (int, error) {
	if e := r.s.check(); e != nil {
		return 0, e
	}
	C.brngHMACStepR(pointer(b), C.size_t(len(b)), r.s.ptr)
	return len(b), nil
}
func (r *HMAC) Close() error {
	if r != nil {
		r.s.Close()
		r.iv.Close()
	}
	return nil
}
