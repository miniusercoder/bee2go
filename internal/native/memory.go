package native

/*
#include "bridge.h"
*/
import "C"
import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"runtime"
	"unsafe"
)

type state struct {
	ptr  unsafe.Pointer
	size uintptr
}

func newState(size uintptr) (*state, error) {
	p := C.calloc(1, C.size_t(size))
	if p == nil {
		return nil, &bee2.Error{Op: "allocate", Code: 110}
	}
	return &state{p, size}, nil
}
func (s *state) check() error {
	if s == nil || s.ptr == nil {
		return bee2.ErrClosed
	}
	return nil
}
func (s *state) Close() error {
	if s != nil && s.ptr != nil {
		C.memWipe(s.ptr, C.size_t(s.size))
		C.free(s.ptr)
		s.ptr = nil
	}
	return nil
}
func pointer(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(&b[0])
}
func octets(b []byte) *C.octet { return (*C.octet)(pointer(b)) }
func codeErr(op string, code C.err_t) error {
	if code == 0 {
		return nil
	}
	return &bee2.Error{Op: op, Code: uint32(code)}
}
func invalid(op string) error { return &bee2.Error{Op: op, Code: 109} }

// Wipe overwrites only the current length. It cannot erase other copies.
func Wipe(b []byte) {
	if len(b) > 0 {
		C.memWipe(pointer(b), C.size_t(len(b)))
		runtime.KeepAlive(b)
	}
}
