package native

/*
#include "bridge.h"
#include <bee2/core/rng.h>
static err_t bee2go_rng_source(size_t* read,void* out,size_t n,void* seed) {
 if(n>32)return ERR_BAD_LENGTH;
 memcpy(out,seed,n);*read=n;return ERR_OK;
}
static err_t bee2go_rng_create_seed(const octet seed[32]) {
 octet copy[32];err_t rc;memcpy(copy,seed,32);
 rc=rngCreate(bee2go_rng_source,copy);memWipe(copy,32);return rc;
}
*/
import "C"
import (
	"fmt"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"io"
	"strings"
	"sync"
	"unsafe"
)

var rngMu sync.Mutex

type RNG struct{ closed bool }

func NewRNG() (*RNG, error) {
	rngMu.Lock()
	defer rngMu.Unlock()
	if e := codeErr("rng.create", C.rngCreate(nil, nil)); e != nil {
		return nil, e
	}
	return &RNG{}, nil
}
func (r *RNG) Read(b []byte) (int, error)              { return r.read(b, true) }
func (r *RNG) ReadWithoutReseed(b []byte) (int, error) { return r.read(b, false) }
func (r *RNG) read(b []byte, fresh bool) (int, error) {
	rngMu.Lock()
	defer rngMu.Unlock()
	if r == nil || r.closed {
		return 0, bee2.ErrClosed
	}
	if fresh {
		C.rngStepR(pointer(b), C.size_t(len(b)), nil)
	} else {
		C.rngStepR2(pointer(b), C.size_t(len(b)), nil)
	}
	return len(b), nil
}
func (r *RNG) Rekey() error {
	rngMu.Lock()
	defer rngMu.Unlock()
	if r == nil || r.closed {
		return bee2.ErrClosed
	}
	C.rngRekey()
	return nil
}
func (r *RNG) Close() error {
	rngMu.Lock()
	defer rngMu.Unlock()
	if r != nil && !r.closed {
		C.rngClose()
		r.closed = true
	}
	return nil
}
func RNGReadEntropy(b []byte, source string) (int, error) {
	if strings.ContainsRune(source, 0) {
		return 0, invalid("rng.source")
	}
	cs := C.CString(source)
	defer C.free(unsafe.Pointer(cs))
	var n C.size_t
	e := codeErr("rng.entropy", C.rngESRead(&n, pointer(b), C.size_t(len(b)), cs))
	if e != nil {
		Wipe(b)
		return 0, e
	}
	return int(n), nil
}
func RNGTestSource(source string) error {
	if strings.ContainsRune(source, 0) {
		return invalid("rng.source")
	}
	cs := C.CString(source)
	defer C.free(unsafe.Pointer(cs))
	return codeErr("rng.testSource", C.rngESTest(cs))
}
func RNGHealth(strong bool) error {
	if strong {
		return codeErr("rng.health2", C.rngESHealth2())
	}
	return codeErr("rng.health", C.rngESHealth())
}
func RNGFIPS(n int, b []byte) bool {
	if len(b) < 2500 {
		return false
	}
	switch n {
	case 1:
		return C.rngTestFIPS1(octets(b)) != 0
	case 2:
		return C.rngTestFIPS2(octets(b)) != 0
	case 3:
		return C.rngTestFIPS3(octets(b)) != 0
	case 4:
		return C.rngTestFIPS4(octets(b)) != 0
	}
	return false
}

// NewRNGWithSource reads an additional 32-byte entropy contribution before C.
// The supplied reader is never retained by the native singleton.
func NewRNGWithSource(source io.Reader) (*RNG, error) {
	if source == nil {
		return NewRNG()
	}
	var seed [32]byte
	defer Wipe(seed[:])
	if _, e := io.ReadFull(source, seed[:]); e != nil {
		return nil, fmt.Errorf("%w: %w", bee2.ErrRandom, e)
	}
	rngMu.Lock()
	defer rngMu.Unlock()
	if e := codeErr("rng.createSource", C.bee2go_rng_create_seed(octets(seed[:]))); e != nil {
		return nil, e
	}
	return &RNG{}, nil
}
func RNGIsCreated() bool { rngMu.Lock(); defer rngMu.Unlock(); return C.rngIsValid() != 0 }
